# srt-ffi

C FFI compatibility layer for the Rust SRT implementation.

This crate provides C-compatible function exports that match the [original SRT C API](https://github.com/Haivision/srt/blob/master/srtcore/srt.h). It can be compiled as a shared library (`.so`/`.dylib`/`.dll`) or static library (`.a`/`.lib`) and used as a drop-in replacement for the C++ SRT library.

## Building

### Shared library (default)

```bash
cargo build --release -p srt-ffi

# Output locations:
# macOS:   target/release/libsrt_ffi.dylib
# Linux:   target/release/libsrt_ffi.so
# Windows: target/release/srt_ffi.dll
```

### Static library

Add to `srt-ffi/Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib", "staticlib"]
```

Then build:

```bash
cargo build --release -p srt-ffi
# Output: target/release/libsrt_ffi.a (or srt_ffi.lib on Windows)
```

### Verify no system dependencies

```bash
# macOS
otool -L target/release/libsrt_ffi.dylib
# Should only show libSystem.B.dylib and libiconv - NO libssl or libcrypto

# Linux
ldd target/release/libsrt_ffi.so
# Should only show libc, libm, libpthread, libdl - NO libssl or libcrypto
```

## C API Reference

### Lifecycle

```c
int srt_startup(void);     // Initialize the library (call once)
int srt_cleanup(void);     // Clean up (call when done)
int srt_getversion(void);  // Get version as packed integer
```

### Socket Management

```c
SRTSOCKET srt_create_socket(void);      // Create a new SRT socket
int       srt_close(SRTSOCKET u);       // Close a socket
int       srt_getsockstate(SRTSOCKET u); // Get socket status
```

### Connection

```c
int       srt_bind(SRTSOCKET u, const struct sockaddr* name, int namelen);
int       srt_listen(SRTSOCKET u, int backlog);
SRTSOCKET srt_accept(SRTSOCKET u, struct sockaddr* addr, int* addrlen);
int       srt_connect(SRTSOCKET u, const struct sockaddr* name, int namelen);
```

### Data Transfer

```c
int srt_send(SRTSOCKET u, const char* buf, int len);
int srt_recv(SRTSOCKET u, char* buf, int len);
int srt_sendmsg(SRTSOCKET u, const char* buf, int len, int ttl, int inorder);
int srt_recvmsg(SRTSOCKET u, char* buf, int len);
```

### Socket Options

```c
int srt_setsockopt(SRTSOCKET u, int level, int optname, const void* optval, int optlen);
int srt_getsockopt(SRTSOCKET u, int level, int optname, void* optval, int* optlen);
int srt_setsockflag(SRTSOCKET u, int opt, const void* optval, int optlen);
int srt_getsockflag(SRTSOCKET u, int opt, void* optval, int* optlen);
```

### Epoll

```c
int srt_epoll_create(void);
int srt_epoll_add_usock(int eid, SRTSOCKET u, const int* events);
int srt_epoll_remove_usock(int eid, SRTSOCKET u);
int srt_epoll_wait(int eid, SRTSOCKET* readfds, int* rnum,
                   SRTSOCKET* writefds, int* wnum, int64_t timeout,
                   int* lrfds, int* lrnum, int* lwfds, int* lwnum);
int srt_epoll_release(int eid);
```

### Error Handling

```c
int         srt_getlasterror(int* errno_loc);
void        srt_clearlasterror(void);
const char* srt_strerror(int code, int errbuflen);
```

### Logging

```c
void srt_setloglevel(int ll);
```

## Usage from C

```c
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// SRT function declarations
typedef int SRTSOCKET;
extern int srt_startup(void);
extern int srt_cleanup(void);
extern SRTSOCKET srt_create_socket(void);
extern int srt_connect(SRTSOCKET u, const void* name, int namelen);
extern int srt_send(SRTSOCKET u, const char* buf, int len);
extern int srt_close(SRTSOCKET u);
extern int srt_getversion(void);

int main() {
    srt_startup();
    printf("SRT version: 0x%x\n", srt_getversion());

    SRTSOCKET sock = srt_create_socket();
    // ... connect and send data ...
    srt_close(sock);
    srt_cleanup();
    return 0;
}
```

Compile and link:

```bash
# macOS
gcc -o my_app my_app.c -L target/release -lsrt_ffi

# Linux
gcc -o my_app my_app.c -L target/release -lsrt_ffi -Wl,-rpath,target/release
```

## Usage from Python (ctypes)

```python
import ctypes

lib = ctypes.CDLL("target/release/libsrt_ffi.dylib")  # or .so on Linux

lib.srt_startup()
version = lib.srt_getversion()
print(f"SRT version: {version:#x}")
lib.srt_cleanup()
```

## Implementation Status

| Function | Status |
|----------|--------|
| `srt_startup` / `srt_cleanup` | Implemented |
| `srt_getversion` | Implemented |
| `srt_create_socket` / `srt_close` | Stub (returns placeholder) |
| `srt_bind` / `srt_listen` / `srt_accept` | Stub |
| `srt_connect` | Stub |
| `srt_send` / `srt_recv` | Stub |
| `srt_setsockopt` / `srt_getsockopt` | Stub |
| `srt_epoll_*` | Stub |
| `srt_getlasterror` / `srt_strerror` | Stub |

Functions marked "Stub" have the correct C signature and are exported, but return `SRT_ERROR` until the transport layer integration is completed.

## License

[Mozilla Public License 2.0](../LICENSE)
