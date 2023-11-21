#[macro_export]
macro_rules! console_debug {
    ($($t:tt)*) => {
        web_sys::console::debug_1(&format_args!($($t)*).to_string().into())
    }
}

/// When debugging your Worker via `wrangler dev`, `wrangler tail`, or from the Workers Dashboard,
/// anything passed to this macro will be printed to the terminal or written to the console.
#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => {
        web_sys::console::log_1(&format_args!($($t)*).to_string().into())
    }
}

/// When debugging your Worker via `wrangler dev`, `wrangler tail`, or from the Workers Dashboard,
/// anything passed to this macro will be printed to the terminal or written to the console.
#[macro_export]
macro_rules! console_warn {
    ($($t:tt)*) => {
        web_sys::console::warn_1(&format_args!($($t)*).to_string().into())
    }
}

/// When debugging your Worker via `wrangler dev`, `wrangler tail`, or from the Workers Dashboard,
/// anything passed to this macro will be printed to the terminal or written to the console.
#[macro_export]
macro_rules! console_error {
    ($($t:tt)*) => {
        web_sys::console::error_1(&format_args!($($t)*).to_string().into())
    }
}
