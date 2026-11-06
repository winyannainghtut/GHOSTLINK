# Windows development and installation

Run development builds in a user-owned directory. `scripts/cargo.ps1` discovers Visual Studio C++ Build Tools and either the system SDK or pinned SDK files under `.tools`. Use a complete MSVC installation or run `scripts/bootstrap-windows.ps1 -IncludeSdk`. No global PATH or registry changes are made by that bootstrap.

## User-owned development session

Start the daemon in one terminal:

```powershell
./target/debug/myvpnd.exe --data-dir 'D:\custom vpn\.state-dev' --outline-engine 'D:\custom vpn\target\debug\myvpn-tunnel.exe' --openvpn 'D:\custom vpn\.tools\openvpn-bin\openvpn.exe'
```

In another terminal run `./target/debug/myvpn.exe status --json` and `./apps/desktop/src-tauri/target/debug/myvpn-desktop.exe`. Use the actual checkout path on another machine. An unelevated daemon supports key/profile/agent management, but cannot create a privileged TUN adapter. There is no automatic UAC bypass.

The optional OpenVPN executable path is only needed for that backend. The Outline-compatible path now requires the **managed MyVPN worker**, not the unmodified standalone sing-box CLI; the managed worker supports graceful Windows shutdown and parent-death cleanup. `--sing-box` remains an argument alias for older development commands, but the binary must implement the managed worker interface.

## Installer behavior

`scripts/build-windows.ps1` builds optimized CLI/service/MCP, Tauri GUI and Go worker, then compiles and validates a WiX MSI. It also creates a portable directory archive. Rust binaries link the MSVC runtime statically for this build. The GUI requires the separately installed Microsoft WebView2 Runtime.

The MSI installs into 64-bit Program Files, adds the CLI directory to the machine PATH, creates a Start menu shortcut and installs an automatic LocalSystem service named `MyVPN`. The service pipe grants access to SYSTEM and the selected user's SID. The MSI uses Windows Installer's UserSID for an interactive install and retains a previous installation's owner. For unattended installation, supply the intended user's SID explicitly:

```powershell
$vpnOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
msiexec.exe /i .\MyVPN-0.1.0-windows-x64.msi "MYVPN_OWNER_SID=$vpnOwnerSid"
```

Administrator consent is a human installation step. The owner SID must belong to the normal user who will run the GUI/CLI; do not substitute Everyone or another broad group. Use the installer repair/upgrade process with administrator access to change installation policy.

The service creates its private state directory and encrypts secrets with SYSTEM's DPAPI identity. User-mode development state cannot simply be copied into the SYSTEM service directory: DPAPI is identity-bound. Import keys through the installed service instead. State is retained when uninstalling, to preserve encrypted profiles; remove it only through an intentional administrator cleanup after disconnecting.

The embedded Wintun 0.14.1 DLL in the pinned Go dependency was compared byte-for-byte with the official archive and its Authenticode signature was valid (WireGuard LLC). This verifies the binary provenance; driver installation and routed networking have not yet been verified through the MSI in this environment.

## Required installation verification

On an authorized Windows test machine: install, check the service starts, confirm the intended standard user can call `status`, check another OS user is denied, import a locally held key, establish a real tunnel, inspect egress/routes/DNS/IPv6, disconnect and compare network state. Exercise service stop/restart and uninstall only after checking recovery. Do not label a package install-tested merely because WiX compilation passed.

The current unsigned package is a development build. Windows code signing and a verified public update/rollback channel are not configured. Keep old installers and corresponding source bundles together when preparing rollback tests.
