//! Windows and macOS: the tray icon needs a native event loop on the main thread (tao).
use super::{Builder, Poster};
use crate::app::{App, Control, Msg};
use std::sync::{Arc, Mutex};
use tao::{
    event::{Event, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder},
};

pub fn run(build: Builder) -> Result<(), String> {
    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::<Msg>::with_user_event().build();
    #[cfg(target_os = "macos")]
    {
        // Menu-bar only: no Dock icon, no application menu.
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }
    let proxy = Mutex::new(event_loop.create_proxy());
    let poster: Poster = Arc::new(move |message| {
        if let Ok(proxy) = proxy.lock() {
            let _ = proxy.send_event(message);
        }
    });
    let mut build = Some(build);
    let mut app: Option<App> = None;
    // Windows: an invisible top-level window titled "BaradWatchU Tray" gives the tray a polite
    // way to be asked to quit: a WM_CLOSE posted to it (install.ps1 does this) is handled like
    // "Close tray". `taskkill` without /F does not reach invisible windows.
    #[cfg(target_os = "windows")]
    let mut _close_target: Option<tao::window::Window> = None;
    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        #[cfg(not(target_os = "windows"))]
        let _ = target;
        match event {
            // macOS requires the status item to be created once the loop is running.
            Event::NewEvents(StartCause::Init) => {
                #[cfg(target_os = "windows")]
                {
                    _close_target = tao::window::WindowBuilder::new()
                        .with_title("BaradWatchU Tray")
                        .with_visible(false)
                        .build(target)
                        .ok();
                }
                if let Some(build) = build.take() {
                    match build(poster.clone()) {
                        Ok(created) => app = Some(created),
                        Err(error) => {
                            eprintln!("Errore: {error}");
                            *control_flow = ControlFlow::ExitWithCode(1);
                        }
                    }
                }
            }
            Event::UserEvent(message) => {
                if let Some(current) = app.as_mut() {
                    if current.handle(message) == Control::Exit {
                        app = None;
                        *control_flow = ControlFlow::Exit;
                    }
                }
            }
            #[cfg(target_os = "windows")]
            Event::WindowEvent {
                event: tao::event::WindowEvent::CloseRequested,
                ..
            } => {
                // Dropping the app removes the icon and releases the single-instance lock.
                app = None;
                _close_target = None;
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    })
}
