use crate::pkcs11::{CK_BYTE_PTR, CK_ULONG};
use std::{ptr, slice};

pub(crate) fn ptr_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: All PKCS#11 entry points call this only after validating the
        // pointer is non-null. The caller is responsible for passing a pointer
        // to writable storage of type T for the duration of the call.
        Some(unsafe { &mut *ptr })
    }
}

pub(crate) fn zero_ref<T>(out: &mut T) {
    // SAFETY: `out` is an exclusive mutable reference, so zeroing exactly one T
    // at that address does not alias. This is used only for C layout structs
    // returned through PKCS#11.
    unsafe {
        ptr::write_bytes(out, 0, 1);
    }
}

pub(crate) fn bytes_from_raw<'a>(ptr: CK_BYTE_PTR, len: CK_ULONG) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() || len > usize::MAX as CK_ULONG {
        None
    } else {
        // SAFETY: The PKCS#11 caller promises `ptr..ptr+len` is readable for
        // this call. We reject null and lengths that cannot fit in usize.
        Some(unsafe { slice::from_raw_parts(ptr, len as usize) })
    }
}

pub(crate) fn mut_slice_from_raw<'a, T>(ptr: *mut T, len: CK_ULONG) -> Option<&'a mut [T]> {
    if len == 0 {
        Some(&mut [])
    } else if ptr.is_null() || len > usize::MAX as CK_ULONG {
        None
    } else {
        // SAFETY: The PKCS#11 caller promises `ptr..ptr+len` is writable and
        // properly aligned for T for this call. We reject null and oversized
        // lengths before constructing the slice.
        Some(unsafe { slice::from_raw_parts_mut(ptr, len as usize) })
    }
}

pub(crate) fn slice_from_raw<'a, T>(ptr: *const T, len: CK_ULONG) -> Option<&'a [T]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() || len > usize::MAX as CK_ULONG {
        None
    } else {
        // SAFETY: The PKCS#11 caller promises `ptr..ptr+len` is readable and
        // properly aligned for T for this call. We reject null and oversized
        // lengths before constructing the slice.
        Some(unsafe { slice::from_raw_parts(ptr, len as usize) })
    }
}

pub(crate) fn copy_to_raw(dst: *mut u8, src: &[u8]) {
    if src.is_empty() {
        return;
    }
    // SAFETY: Callers use this only after validating `dst` is non-null and
    // points to a writable buffer at least `src.len()` bytes long.
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    }
}
