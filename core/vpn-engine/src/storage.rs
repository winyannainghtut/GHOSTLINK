use anyhow::{ensure, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

/// Remove temporary plaintext configuration on startup errors, cancellation and normal exit.
pub struct PrivateConfig(std::path::PathBuf);
impl PrivateConfig {
    pub fn write(path: &Path, bytes: &[u8]) -> Result<Self> {
        atomic_write(path, bytes)?;
        Ok(Self(path.into()))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for PrivateConfig {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// This process's effective user ID.
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions, cannot fail and reads no memory of ours.
    unsafe { libc::geteuid() }
}

/// Service-private state; never call this on an arbitrary user-supplied file.
///
/// # Errors
/// Fails if the directory cannot be created, if it exists but belongs to another, untrusted
/// identity (another user on Unix; anyone but this user, SYSTEM or Administrators on Windows),
/// or if its permissions (mode 0700) or private ACL cannot be set.
pub fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            !fs::symlink_metadata(path)?.file_type().is_symlink(),
            "State directory must not be a symlink"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                fs::symlink_metadata(path)?.file_attributes() & 0x400 == 0,
                "State directory must not be a reparse point"
            );
            check_owner(path)?;
        }
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            fs::metadata(path)?.uid() == effective_uid(),
            "State directory has a different owner"
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    restrict_acl(path)?;
    Ok(())
}

#[cfg(windows)]
fn check_owner(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::*, OWNER_SECURITY_INFORMATION},
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let current = current_sid()?;
    // SAFETY: `name` is a NUL-terminated UTF-16 path that outlives the call. On success
    // GetNamedSecurityInfoW sets `descriptor` to a LocalAlloc'd security descriptor and `owner`
    // to a SID inside it; both are read only before `descriptor` is freed, once, below. The
    // string ConvertSidToStringSidW returns is NUL-terminated (the loop stops at the NUL), read
    // only while allocated, and freed once. Every early return happens before an allocation.
    unsafe {
        let mut owner = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        ensure!(
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor
            ) == 0,
            "Cannot inspect state directory owner"
        );
        let mut sid = std::ptr::null_mut();
        let converted = ConvertSidToStringSidW(owner, &mut sid);
        let allowed = if converted != 0 {
            let mut len = 0;
            while *sid.add(len) != 0 {
                len += 1;
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid, len));
            LocalFree(sid.cast());
            value == current || matches!(value.as_str(), "S-1-5-18" | "S-1-5-32-544")
        } else {
            false
        };
        LocalFree(descriptor);
        ensure!(
            allowed,
            "State directory belongs to another untrusted identity; refusing privileged access"
        );
    }
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("pending");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // A stale temporary file never causes following a link or overwriting another file.
    let mut file = options.open(&temporary).context(
        "Cannot create private transaction file; inspect stale .pending files after a crash",
    )?;
    let result = (|| {
        #[cfg(windows)]
        restrict_acl(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            };
            let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            ensure!(
                // SAFETY: both paths are NUL-terminated UTF-16 buffers that outlive the call,
                // which only reads them.
                unsafe {
                    MoveFileExW(
                        from.as_ptr(),
                        to.as_ptr(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                    )
                } != 0,
                "Atomic state replacement failed"
            );
        }
        #[cfg(unix)]
        {
            fs::rename(&temporary, path)?;
            if let Some(parent) = path.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
pub fn current_sid() -> Result<String> {
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::ConvertSidToStringSidW, *},
        System::Threading::*,
    };
    // SAFETY: the token handle is closed once, right after its last use. The first
    // GetTokenInformation call only reports the size needed; the buffer for the second holds at
    // least that many bytes and is made of usize words, so it is aligned for TOKEN_USER (which
    // holds pointers; a Vec<u8> need not be). TOKEN_USER is read only after that call succeeded,
    // and its SID points into `data`, which lives until the end of the block. The string
    // ConvertSidToStringSidW returns is NUL-terminated, read only while allocated, and freed once.
    unsafe {
        let mut token = std::ptr::null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
            "Cannot inspect user token"
        );
        let mut size = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
        let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let ok = GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size);
        CloseHandle(token);
        ensure!(ok != 0, "Cannot inspect user SID");
        let mut sid = std::ptr::null_mut();
        ensure!(
            ConvertSidToStringSidW((*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid, &mut sid) != 0,
            "Cannot format user SID"
        );
        let mut len = 0;
        while *sid.add(len) != 0 {
            len += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(sid, len));
        LocalFree(sid.cast());
        Ok(result)
    }
}

#[cfg(windows)]
pub fn restrict_acl(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::*, *},
    };
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{})", current_sid()?);
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` and `name` are NUL-terminated UTF-16 buffers that outlive the calls. On
    // success `sd` is a LocalAlloc'd security descriptor, passed to SetFileSecurityW while it
    // is allocated and freed once afterwards; the failed conversion returns before allocating.
    unsafe {
        let mut sd = std::ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut()
            ) != 0,
            "Cannot create private ACL"
        );
        let ok = SetFileSecurityW(
            name.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        );
        LocalFree(sd);
        ensure!(ok != 0, "Cannot protect state ACL");
    }
    Ok(())
}

#[cfg(windows)]
pub fn seal(bytes: &[u8]) -> Result<Vec<u8>> {
    dpapi(bytes, true)
}
#[cfg(windows)]
pub fn unseal(bytes: &[u8]) -> Result<Vec<u8>> {
    dpapi(bytes, false)
}
#[cfg(unix)]
pub fn seal(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}
#[cfg(unix)]
pub fn unseal(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(windows)]
fn dpapi(bytes: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len().try_into()?,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: `input` points at `bytes`, which outlives the call; DPAPI only reads it (the
    // `*mut` is the C struct's type). On success DPAPI sets `output` to a LocalAlloc'd buffer of
    // `cbData` bytes, which is copied out while allocated and then freed once; on failure it
    // allocates nothing and the function returns before reading it.
    unsafe {
        let ok = if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        ensure!(
            ok != 0,
            "Windows DPAPI failed; state must be read by the identity that created it"
        );
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData.cast());
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_storage_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        private_dir(dir.path()).unwrap();
        let path = dir.path().join("state");
        let sealed = seal(b"private material").unwrap();
        atomic_write(&path, &sealed).unwrap();
        assert_eq!(
            unseal(&fs::read(&path).unwrap()).unwrap(),
            b"private material"
        );
        atomic_write(&path, b"replacement").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }
}
