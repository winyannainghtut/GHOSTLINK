// Why a connection failed, in words. The service reports a short code (the status's last_error),
// set by the tunnel engines in core/vpn-engine (worker_session.rs for Shadowsocks, VLESS,
// WireGuard and AmneziaWG; management.rs for OpenVPN) and by the service. The managed engine's
// codes start with "outline_" for every protocol, so the words here name none. No imports, so the
// tests run it directly.
const REASONS: Record<string, string> = {
  outline_server_unreachable_or_key_rejected: 'The server did not answer in time, or it did not accept the key. Check the key and that the server is online.',
  outline_engine_exited_check_service_permissions: 'The tunnel engine stopped unexpectedly. Check that the Ghostlink service is installed and running, then run the diagnostics in Settings.',
  outline_engine_start_failed_check_permissions_or_driver: 'The tunnel could not start. The diagnostics in Settings show whether the service has the rights and network driver it needs.',
  outline_tunnel_interface_not_observed: 'The VPN network adapter did not come up. The diagnostics in Settings show whether the network driver is installed.',
  outline_engine_protocol_error: 'The tunnel engine sent an answer Ghostlink did not expect. Try again, then run the diagnostics in Settings.',
  outline_engine_socket_owner_mismatch: 'Another program took the tunnel engine’s local ports. Try again; if it happens again, run the diagnostics in Settings.',
  outline_health_check_failed: 'The connection stopped passing traffic.',
  network_cleanup_unverified: 'The connection closed, but Ghostlink could not confirm that its network changes were undone. Check routing and DNS (the diagnostics in Settings) before connecting again.',
  forced_stop_network_cleanup_unverified: 'The tunnel engine had to be stopped by force, so Ghostlink could not confirm that its network changes were undone. Check routing and DNS (the diagnostics in Settings) before connecting again.',
  connection_timeout: 'The server did not answer in time. Check that it is online and that this network allows the connection.',
  authentication_failed: 'The server did not accept the user name or password.',
  credentials_required: 'This profile needs a user name and password.',
  engine_fatal_error: 'OpenVPN stopped with an error. Check the profile, then the diagnostics in Settings.',
  engine_exited: 'OpenVPN stopped unexpectedly. Run the diagnostics in Settings.',
  engine_exited_before_management: 'OpenVPN stopped before it was ready. Check the profile, then the diagnostics in Settings.',
  management_connection_failed: 'Ghostlink could not take control of OpenVPN. Run the diagnostics in Settings.',
  management_connection_lost: 'Ghostlink lost control of OpenVPN. Run the diagnostics in Settings.',
  autoconnect_failed: 'The automatic connection when the service started did not work. Connect again, or check the default server.',
};

export function failureText(code: string | null | undefined): string {
  return (code && Object.hasOwn(REASONS, code) && REASONS[code]) || 'Check your key, then the diagnostics in Settings.';
}
