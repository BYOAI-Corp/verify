//! Plain C ABI (feature `cabi`): raw WebAssembly exports for a Svelte/Vite app or WebView
//! (feature `wasm`), and the same three symbols in a native static library (iOS, Swift).
//! JS side: write the UTF-8 request into memory from bc_alloc, call bc_call, read the
//! response at (ret >> 32) for (ret & 0xffffffff) bytes, then bc_free both buffers.
use alloc::vec::Vec;

#[no_mangle]
pub extern "C" fn bc_alloc(len: usize) -> *mut u8 {
    let mut v: Vec<u8> = Vec::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}

/// # Safety
/// `ptr`/`len` must come from `bc_alloc(len)` or a `bc_call` response.
#[no_mangle]
pub unsafe extern "C" fn bc_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
}

/// # Safety
/// `ptr` must point to `len` bytes written by the caller into a `bc_alloc` buffer.
#[no_mangle]
pub unsafe extern "C" fn bc_call(ptr: *const u8, len: usize) -> u64 {
    let req = core::slice::from_raw_parts(ptr, len);
    let resp = match core::str::from_utf8(req) {
        Ok(s) => crate::api::call_json(s),
        Err(_) => alloc::string::String::from("{\"error\":\"request is not UTF-8\",\"ok\":false}"),
    };
    let mut bytes = resp.into_bytes();
    bytes.shrink_to_fit();
    let (p, n) = (bytes.as_mut_ptr(), bytes.len());
    core::mem::forget(bytes);
    ((p as u64) << 32) | (n as u64)
}
