use crate::Args;
use anyhow::{ensure, Result};
use ghostlink_contracts::Stream;

#[cfg(windows)]
pub struct Listener {
    pipe: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    endpoint: String,
    owner: String,
}

#[cfg(windows)]
fn create(
    endpoint: &str,
    owner: &str,
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
    };
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{owner})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut()
            ) != 0,
            "Invalid pipe ACL"
        );
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(64)
            .create_with_security_attributes_raw(
                endpoint,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            );
        LocalFree(descriptor);
        Ok(result?)
    }
}

#[cfg(windows)]
impl Listener {
    pub async fn bind(args: &Args) -> Result<Self> {
        ensure!(
            args.endpoint.starts_with(r"\\.\pipe\") && !args.endpoint[9..].contains(['\\', '/']),
            "Only local pipe endpoints are permitted"
        );
        let current = ghostlink_engine::storage::current_sid()?;
        let owner = args.owner_sid.clone().unwrap_or_else(|| current.clone());
        ensure!(
            owner.starts_with("S-1-")
                && owner.len() < 190
                && owner
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-')),
            "Invalid owner SID"
        );
        ensure!(
            current == owner || current == "S-1-5-18",
            "Only SYSTEM may configure access for a different user"
        );
        let pipe = create(&args.endpoint, &owner, true)?;
        Ok(Self {
            pipe: Some(pipe),
            endpoint: args.endpoint.clone(),
            owner,
        })
    }
    pub async fn accept(&mut self) -> Result<Stream> {
        let connected = self.pipe.as_mut().unwrap().connect().await;
        if let Err(error) = connected {
            // A failed connect can leave this instance unusable. Replace it; the new one exists
            // before the old one closes, so the pipe name is never free.
            if let Ok(fresh) = create(&self.endpoint, &self.owner, false) {
                self.pipe = Some(fresh);
            }
            return Err(error.into());
        }
        // Always retain a server instance so the pipe name cannot be captured between clients.
        let next = create(&self.endpoint, &self.owner, false)?;
        let connected = self.pipe.replace(next).unwrap();
        Ok(Box::new(connected))
    }
}

#[cfg(unix)]
pub struct Listener {
    listener: tokio::net::UnixListener,
    owner: u32,
    path: std::path::PathBuf,
}
#[cfg(unix)]
impl Listener {
    pub async fn bind(args: &Args) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        let path = std::path::PathBuf::from(&args.endpoint);
        ensure!(path.is_absolute(), "Socket path must be absolute");
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid socket directory"))?;
        std::fs::create_dir_all(parent)?;
        let meta = std::fs::symlink_metadata(parent)?;
        ensure!(
            !meta.file_type().is_symlink()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o022 == 0,
            "Socket directory must be owned by the daemon and not writable by other users"
        );
        let owner = args.owner_uid.unwrap_or_else(|| unsafe { libc::geteuid() });
        ensure!(
            unsafe { libc::geteuid() } == 0 || owner == unsafe { libc::geteuid() },
            "Only root may authorize another UID"
        );
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            ensure!(
                meta.file_type().is_socket(),
                "Refusing to remove a non-socket endpoint"
            );
            ensure!(
                tokio::net::UnixStream::connect(&path).await.is_err(),
                "Another service owns the socket"
            );
            std::fs::remove_file(&path)?;
        }
        let listener = tokio::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(c_path.as_ptr(), owner, u32::MAX) } == 0,
            "Cannot assign socket owner"
        );
        Ok(Self {
            listener,
            owner,
            path,
        })
    }
    pub async fn accept(&mut self) -> Result<Stream> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let uid = stream.peer_cred()?.uid();
            if uid == self.owner || uid == 0 {
                return Ok(Box::new(stream));
            }
        }
    }
}
#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
