//! C FFI bindings for the Rust SRT implementation.
//!
//! This crate provides `#[no_mangle] extern "C"` functions matching the
//! [original SRT C API](https://github.com/Haivision/srt/blob/master/srtcore/srt.h).
//! It can be compiled as a shared library (`.so`/`.dylib`/`.dll`) or static
//! library (`.a`) and used as a drop-in replacement for the C++ SRT library.
//!
//! # Exported Functions
//!
//! - **Lifecycle**: `srt_startup`, `srt_cleanup`, `srt_getversion`
//! - **Socket**: `srt_create_socket`, `srt_close`, `srt_getsockstate`
//! - **Connection**: `srt_bind`, `srt_listen`, `srt_accept`, `srt_connect`
//! - **Data**: `srt_send`, `srt_recv`, `srt_sendmsg`, `srt_recvmsg`
//! - **Options**: `srt_setsockopt`, `srt_getsockopt`, `srt_setsockflag`, `srt_getsockflag`
//! - **Epoll**: `srt_epoll_create`, `srt_epoll_add_usock`, `srt_epoll_wait`, `srt_epoll_release`
//! - **Error**: `srt_getlasterror`, `srt_clearlasterror`, `srt_strerror`
//! - **Logging**: `srt_setloglevel`

use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

/// SRT socket handle type (matches C++ SRTSOCKET = int32_t).
pub type SRTSOCKET = c_int;

/// Invalid socket constant.
pub const SRT_INVALID_SOCK: SRTSOCKET = -1;
/// Error return value.
pub const SRT_ERROR: c_int = -1;

/// Global initialized flag.
static INITIALIZED: OnceLock<bool> = OnceLock::new();

// ── Lifecycle ──

/// Initialize the SRT library. Must be called before any other SRT function.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn srt_startup() -> c_int {
    match INITIALIZED.set(true) {
        Ok(_) => 0,
        Err(_) => 0, // Already initialized is OK
    }
}

/// Clean up the SRT library. Should be called when done using SRT.
///
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn srt_cleanup() -> c_int {
    0
}

/// Get the SRT library version as an integer (major * 0x10000 + minor * 0x100 + patch).
#[no_mangle]
pub extern "C" fn srt_getversion() -> c_int {
    srt_protocol::config::SRT_VERSION as c_int
}

// ── Socket creation ──

/// Create a new SRT socket.
///
/// Returns a valid SRTSOCKET on success, or SRT_INVALID_SOCK on error.
#[no_mangle]
pub extern "C" fn srt_create_socket() -> SRTSOCKET {
    // TODO: integrate with the async runtime manager
    // For now return a placeholder
    SRT_INVALID_SOCK
}

/// Close an SRT socket.
///
/// Returns 0 on success, SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_close(_u: SRTSOCKET) -> c_int {
    // TODO: implement
    0
}

// ── Connection ──

/// Bind an SRT socket to a local address.
///
/// Returns 0 on success, SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_bind(_u: SRTSOCKET, _name: *const c_void, _namelen: c_int) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Set the socket to listening mode.
///
/// Returns 0 on success, SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_listen(_u: SRTSOCKET, _backlog: c_int) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Accept an incoming connection on a listening socket.
///
/// Returns the accepted socket on success, or SRT_INVALID_SOCK on error.
#[no_mangle]
pub extern "C" fn srt_accept(
    _u: SRTSOCKET,
    _addr: *mut c_void,
    _addrlen: *mut c_int,
) -> SRTSOCKET {
    // TODO: implement
    SRT_INVALID_SOCK
}

/// Connect to a remote SRT peer.
///
/// Returns 0 on success, SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_connect(
    _u: SRTSOCKET,
    _name: *const c_void,
    _namelen: c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

// ── Data transfer ──

/// Send data over an SRT socket.
///
/// Returns the number of bytes sent on success, or SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_send(
    _u: SRTSOCKET,
    _buf: *const c_char,
    _len: c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Send a message over an SRT socket with TTL and in-order options.
///
/// Returns the number of bytes sent on success, or SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_sendmsg(
    _u: SRTSOCKET,
    _buf: *const c_char,
    _len: c_int,
    _ttl: c_int,
    _inorder: c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Receive data from an SRT socket.
///
/// Returns the number of bytes received on success, or SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_recv(
    _u: SRTSOCKET,
    _buf: *mut c_char,
    _len: c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Receive a message from an SRT socket.
///
/// Returns the number of bytes received on success, or SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_recvmsg(
    _u: SRTSOCKET,
    _buf: *mut c_char,
    _len: c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

// ── Socket options ──

/// Set a socket option.
///
/// Returns 0 on success, SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_setsockopt(
    _u: SRTSOCKET,
    _level: c_int,
    _optname: c_int,
    _optval: *const c_void,
    _optlen: c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Get a socket option.
///
/// Returns 0 on success, SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_getsockopt(
    _u: SRTSOCKET,
    _level: c_int,
    _optname: c_int,
    _optval: *mut c_void,
    _optlen: *mut c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Set a socket option (SRT-specific shorthand, same as srt_setsockopt with level=0).
#[no_mangle]
pub extern "C" fn srt_setsockflag(
    u: SRTSOCKET,
    opt: c_int,
    optval: *const c_void,
    optlen: c_int,
) -> c_int {
    srt_setsockopt(u, 0, opt, optval, optlen)
}

/// Get a socket option (SRT-specific shorthand).
#[no_mangle]
pub extern "C" fn srt_getsockflag(
    u: SRTSOCKET,
    opt: c_int,
    optval: *mut c_void,
    optlen: *mut c_int,
) -> c_int {
    srt_getsockopt(u, 0, opt, optval, optlen)
}

// ── Epoll ──

/// Create a new epoll container.
///
/// Returns epoll ID on success, or SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_epoll_create() -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Add a socket to an epoll container.
///
/// Returns 0 on success, SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_epoll_add_usock(
    _eid: c_int,
    _u: SRTSOCKET,
    _events: *const c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Remove a socket from an epoll container.
#[no_mangle]
pub extern "C" fn srt_epoll_remove_usock(_eid: c_int, _u: SRTSOCKET) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Wait for events on an epoll container.
///
/// Returns number of ready sockets on success, or SRT_ERROR on error.
#[no_mangle]
pub extern "C" fn srt_epoll_wait(
    _eid: c_int,
    _readfds: *mut SRTSOCKET,
    _rnum: *mut c_int,
    _writefds: *mut SRTSOCKET,
    _wnum: *mut c_int,
    _ms_time_out: i64,
    _lrfds: *mut c_int,
    _lrnum: *mut c_int,
    _lwfds: *mut c_int,
    _lwnum: *mut c_int,
) -> c_int {
    // TODO: implement
    SRT_ERROR
}

/// Release (destroy) an epoll container.
#[no_mangle]
pub extern "C" fn srt_epoll_release(_eid: c_int) -> c_int {
    // TODO: implement
    SRT_ERROR
}

// ── Error handling ──

/// Get the last error code.
#[no_mangle]
pub extern "C" fn srt_getlasterror(_errno_loc: *mut c_int) -> c_int {
    // TODO: thread-local error tracking
    0
}

/// Clear the last error.
#[no_mangle]
pub extern "C" fn srt_clearlasterror() {
    // TODO: implement
}

/// Get a human-readable error string for an error code.
#[no_mangle]
pub extern "C" fn srt_strerror(_code: c_int, _errbuflen: c_int) -> *const c_char {
    // Return a static string for now
    b"SRT error\0".as_ptr() as *const c_char
}

// ── Status ──

/// Get the current socket status.
///
/// Returns the socket status as an integer matching SRTS_* constants.
#[no_mangle]
pub extern "C" fn srt_getsockstate(_u: SRTSOCKET) -> c_int {
    // TODO: implement
    1 // SRTS_INIT
}

// ── Logging ──

/// Set the log level for SRT logging.
#[no_mangle]
pub extern "C" fn srt_setloglevel(_ll: c_int) {
    // TODO: map to Rust log levels
}
