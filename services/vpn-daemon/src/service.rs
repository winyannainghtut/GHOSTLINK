use anyhow::Result;
use clap::Parser;
use std::{ffi::OsString, time::Duration};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

define_windows_service!(ffi_main, service_main);
pub fn dispatch() -> Result<()> {
    service_dispatcher::start("MyVPN", ffi_main)?;
    Ok(())
}
fn status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(20),
        process_id: None,
    }
}
fn service_main(_arguments: Vec<OsString>) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut sender = Some(sender);
    let handle = match service_control_handler::register("MyVPN", move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(sender) = sender.take() {
                let _ = sender.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    let _ = handle.set_service_status(status(ServiceState::StartPending));
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => return,
    };
    // Report Running only after private state, locking and the IPC listener are ready.
    let args = crate::Args::parse();
    let result = runtime.block_on(crate::run(
        args,
        async {
            let _ = receiver.await;
            let _ = handle.set_service_status(status(ServiceState::StopPending));
        },
        || {
            handle.set_service_status(status(ServiceState::Running))?;
            Ok(())
        },
    ));
    let mut stopped = status(ServiceState::Stopped);
    if result.is_err() {
        stopped.exit_code = ServiceExitCode::Win32(1);
    }
    let _ = handle.set_service_status(stopped);
}
