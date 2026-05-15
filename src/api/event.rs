use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _slot: CK_SLOT_ID_PTR,
    _reserved: CK_VOID_PTR,
) -> CK_RV {
    super::not_supported()
}
