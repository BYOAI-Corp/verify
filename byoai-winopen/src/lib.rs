//! Windows only: open `<root>\<part>\...\<part>` for reading the way byoai-chain opens a source
//! on Linux with openat(O_NOFOLLOW): every part is opened relative to the handle of the folder
//! before it (NtCreateFile with RootDirectory), never by a full path, so no part of the path is
//! looked up twice and nothing on the way can be swapped for a link between a check and an open.
//!
//! - OBJ_DONT_REPARSE: the open fails if any reparse point (symbolic link, junction, mount point,
//!   cloud placeholder) is met; FILE_OPEN_REPARSE_POINT and an attribute check refuse one as the
//!   last part too.
//! - Exact names: Windows matches names regardless of case and also by 8.3 short names; Linux
//!   matches exactly. After each open, the parent folder is asked (by its handle) for the entry of
//!   that name, and the name it stores must equal the part exactly, so `REPORT.PDF` or `LONGNA~1.TXT`
//!   do not reach `report.pdf` or `longname.txt`. Parts with wildcard or reserved characters
//!   (`* ? < > " | :` and `\`) are refused before anything is opened.
//! - The last part must be a plain file on a disk (not a folder, device or pipe).
//!
//! The root folder itself is opened by its path, so it may be reached through links, as on Linux.
//! Returns None for anything that cannot be opened this way; the caller reports it UNCHECKED.
#![cfg(windows)]

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileNamesInformation, NtCreateFile, NtQueryDirectoryFile, FILE_DIRECTORY_FILE, FILE_NAMES_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_TYPE_DISK, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// A part is one plain name: not empty, not "." or "..", none of the characters Windows reserves
/// or treats as a wildcard in a directory query, no control characters.
fn plain_part(p: &str) -> bool {
    !p.is_empty() && p != "." && p != ".." && p.len() <= 255 && !p.chars().any(|c| (c as u32) < 0x20 || "\\/:*?\"<>|".contains(c))
}

fn info(h: HANDLE) -> Option<BY_HANDLE_FILE_INFORMATION> {
    let mut i: BY_HANDLE_FILE_INFORMATION = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: h is an open handle owned by the caller; i is a valid out-pointer.
    (unsafe { GetFileInformationByHandle(h, &mut i) } != 0).then_some(i)
}

/// Open one part relative to the folder `dir`, refusing reparse points on the way and at the end.
fn open_at(dir: &OwnedHandle, name: &[u16], folder: bool) -> Option<OwnedHandle> {
    let bytes = u16::try_from(name.len() * 2).ok()?;
    let us = UNICODE_STRING { Length: bytes, MaximumLength: bytes, Buffer: name.as_ptr() as *mut u16 };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir.as_raw_handle() as HANDLE,
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut iosb: IO_STATUS_BLOCK = IO_STATUS_BLOCK::default();
    let mut h: HANDLE = std::ptr::null_mut();
    let access = SYNCHRONIZE | FILE_READ_ATTRIBUTES | if folder { FILE_LIST_DIRECTORY | FILE_TRAVERSE } else { FILE_READ_DATA };
    let kind = if folder { FILE_DIRECTORY_FILE } else { FILE_NON_DIRECTORY_FILE };
    // SAFETY: every pointer points at a live local (us, oa, iosb, h) for the duration of the call;
    // name outlives the call; on success the kernel returns a new handle that we take ownership of.
    let st = unsafe {
        NtCreateFile(
            &mut h,
            access,
            &oa,
            &mut iosb,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            kind | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if st < 0 || h.is_null() {
        return None;
    }
    // SAFETY: h was just returned to us by NtCreateFile and is owned by nobody else.
    let owned = unsafe { OwnedHandle::from_raw_handle(h as _) };
    let i = info(owned.as_raw_handle() as HANDLE)?;
    let is_dir = i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || is_dir != folder {
        return None;
    }
    Some(owned)
}

/// The name the folder `dir` stores for the entry that `name` reaches, asked by the folder's
/// handle. Equal to `name` only when `name` is the exact stored name (not another case, not an
/// 8.3 short name). The handle is queried once only: Windows honours the name mask only on the
/// first directory query of a handle, so a second query here would not filter.
fn stored_name_is(dir: &OwnedHandle, name: &[u16]) -> bool {
    let Ok(bytes) = u16::try_from(name.len() * 2) else { return false };
    let us = UNICODE_STRING { Length: bytes, MaximumLength: bytes, Buffer: name.as_ptr() as *mut u16 };
    let mut buf = vec![0u64; 160]; // 1280 bytes, 8-byte aligned: one entry of up to 255 UTF-16 units
    let mut iosb: IO_STATUS_BLOCK = IO_STATUS_BLOCK::default();
    // SAFETY: buf, us and iosb are live locals; the length given is buf's size in bytes; the
    // handle is a folder opened for listing and synchronous I/O.
    let st = unsafe {
        NtQueryDirectoryFile(
            dir.as_raw_handle() as HANDLE,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            &mut iosb,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            (buf.len() * 8) as u32,
            FileNamesInformation,
            true,
            &us,
            true,
        )
    };
    if st < 0 {
        return false;
    }
    let base = buf.as_ptr() as *const u8;
    // SAFETY: on success the kernel wrote one FILE_NAMES_INFORMATION at the start of buf.
    let n = unsafe { (*(base as *const FILE_NAMES_INFORMATION)).FileNameLength } as usize;
    let off = std::mem::offset_of!(FILE_NAMES_INFORMATION, FileName);
    if !n.is_multiple_of(2) || off + n > buf.len() * 8 {
        return false;
    }
    // SAFETY: the n bytes after FileName lie inside buf (checked above) and hold UTF-16 units.
    let stored = unsafe { std::slice::from_raw_parts(base.add(off) as *const u16, n / 2) };
    stored == name
}

/// Open `<root>\<parts...>` for reading as described at the top of this file.
pub fn open_inside(root: &std::path::Path, parts: &[&str]) -> Option<File> {
    if parts.is_empty() || !parts.iter().all(|p| plain_part(p)) {
        return None;
    }
    let mut cur: OwnedHandle = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000; // needed to open a folder
        let f = std::fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(root).ok()?;
        if !f.metadata().ok()?.is_dir() {
            return None;
        }
        OwnedHandle::from(f)
    };
    let (last, dirs) = parts.split_last()?;
    for d in dirs {
        let w: Vec<u16> = d.encode_utf16().collect();
        let next = open_at(&cur, &w, true)?;
        if !stored_name_is(&cur, &w) {
            return None;
        }
        cur = next;
    }
    let w: Vec<u16> = last.encode_utf16().collect();
    let f = open_at(&cur, &w, false)?;
    if !stored_name_is(&cur, &w) {
        return None;
    }
    // SAFETY: f is an open handle we own.
    if unsafe { GetFileType(f.as_raw_handle() as HANDLE) } != FILE_TYPE_DISK {
        return None;
    }
    Some(File::from(f))
}
