use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_GenerateKey(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _template: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GenerateKeyPair(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _public_template: CK_ATTRIBUTE_PTR,
    _public_count: CK_ULONG,
    _private_template: CK_ATTRIBUTE_PTR,
    _private_count: CK_ULONG,
    _public_key: CK_OBJECT_HANDLE_PTR,
    _private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_WrapKey(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _wrapping_key: CK_OBJECT_HANDLE,
    _key: CK_OBJECT_HANDLE,
    _wrapped_key: CK_BYTE_PTR,
    _wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_UnwrapKey(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _unwrapping_key: CK_OBJECT_HANDLE,
    _wrapped_key: CK_BYTE_PTR,
    _wrapped_key_len: CK_ULONG,
    _template: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DeriveKey(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _base_key: CK_OBJECT_HANDLE,
    _template: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    super::not_supported()
}
