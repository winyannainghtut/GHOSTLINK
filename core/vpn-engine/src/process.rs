use anyhow::{ensure, Result};

/// Check OS ownership before sending credentials to an engine's loopback listeners.
pub fn verify_listeners(pid: u32, ports: &[u16]) -> Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::NetworkManagement::IpHelper::*;
        // SAFETY: the first call only reports the size needed. The buffer for the second is u32
        // words (MIB_TCPTABLE_OWNER_PID's alignment) with slack, and `size` tells the API its
        // length in bytes. The table is read only after that call succeeded, and the row count
        // it states is checked against the buffer before the rows are sliced, so the slice
        // stays inside `data`, which outlives it.
        unsafe {
            let mut size = 0;
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            let mut data = vec![0u32; size as usize / 4 + 64];
            size = (data.len() * 4) as u32;
            ensure!(
                GetExtendedTcpTable(
                    data.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    2,
                    TCP_TABLE_OWNER_PID_ALL,
                    0
                ) == 0,
                "Cannot inspect local engine sockets"
            );
            let table = data.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
            let count = (*table).dwNumEntries as usize;
            ensure!(
                count
                    <= (data.len() * 4).saturating_sub(4)
                        / std::mem::size_of::<MIB_TCPROW_OWNER_PID>(),
                "Invalid TCP ownership table"
            );
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), count);
            for port in ports {
                ensure!(
                    rows.iter().any(|row| row.dwOwningPid == pid
                        && row.dwState == 2
                        && row.dwLocalAddr == u32::from_ne_bytes([127, 0, 0, 1])
                        && u16::from_be(row.dwLocalPort as u16) == *port),
                    "Engine does not own its local listener"
                );
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::{collections::HashSet, fs};
        let descriptors = fs::read_dir(format!("/proc/{pid}/fd"))?;
        let inodes: HashSet<String> = descriptors
            .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
            .filter_map(|link| {
                let value = link.to_string_lossy();
                Some(value.strip_prefix("socket:[")?.strip_suffix(']')?.into())
            })
            .collect();
        let table = fs::read_to_string(format!("/proc/{pid}/net/tcp"))?;
        for port in ports {
            let address = format!("0100007F:{port:04X}");
            ensure!(
                table.lines().skip(1).any(|line| {
                    let columns: Vec<_> = line.split_ascii_whitespace().collect();
                    columns.len() > 9
                        && columns[1] == address
                        && columns[3] == "0A"
                        && inodes.contains(columns[9])
                }),
                "Engine does not own its local listener"
            );
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    anyhow::bail!("Engine socket ownership is unsupported on this platform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_requires_the_actual_process_owner() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(verify_listeners(std::process::id(), &[port]).is_ok());
        // Another PID; on Linux, not one of this test's own threads (they share its sockets).
        let other = (1..)
            .map(|n| std::process::id().wrapping_add(n))
            .find(|pid| {
                !cfg!(target_os = "linux")
                    || !std::path::Path::new(&format!("/proc/self/task/{pid}")).exists()
            })
            .unwrap();
        assert!(verify_listeners(other, &[port]).is_err());
    }
}
