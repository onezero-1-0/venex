use once_cell::sync::Lazy;
use std::sync::Mutex;
use crate::http_listener::HttpListener;

// Global reusable HTTP listener
pub static GLOBAL_HTTP_LISTENER: Lazy<Mutex<HttpListener>> = Lazy::new(|| {
    Mutex::new(HttpListener::new())
});
