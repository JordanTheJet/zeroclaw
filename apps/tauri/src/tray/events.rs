//! Tray menu event handling.

use tauri::{AppHandle, Manager, Runtime, menu::MenuEvent};

pub fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    match event.id().as_ref() {
        "show" => show_main_window(app, None),
        "chat" => show_main_window(app, Some("/agents")),
        "quit" => {
            app.exit(0);
        }
        _ => {}
    }
}

fn show_main_window<R: Runtime>(app: &AppHandle<R>, navigate_to: Option<&str>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        if let Some(path) = navigate_to {
            // The dashboard is a History-API SPA (react-router BrowserRouter),
            // so assigning `location.hash` does not navigate it. Push the path
            // and fire `popstate`, which react-router listens for.
            let escaped = path.replace('\\', "\\\\").replace('\'', "\\'");
            let script = format!(
                "window.history.pushState({{}}, '', '{escaped}'); \
                 window.dispatchEvent(new PopStateEvent('popstate'));"
            );
            let _ = window.eval(&script);
        }
    }
}
