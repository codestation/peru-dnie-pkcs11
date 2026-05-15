use crate::{
    ffi::{mut_slice_from_raw, ptr_mut},
    pkcs11::*,
};

#[unsafe(no_mangle)]
pub extern "C" fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if slot_id != 1 {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(count) = ptr_mut(count) else {
        return CKR_ARGUMENTS_BAD;
    };
    let mechanisms = [CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS];
    if list.is_null() {
        *count = mechanisms.len() as CK_ULONG;
        return CKR_OK;
    }
    if *count < mechanisms.len() as CK_ULONG {
        *count = mechanisms.len() as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    let Some(list) = mut_slice_from_raw(list, mechanisms.len() as CK_ULONG) else {
        return CKR_ARGUMENTS_BAD;
    };
    list.copy_from_slice(&mechanisms);
    *count = mechanisms.len() as CK_ULONG;
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    if slot_id != 1 {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(info) = ptr_mut(info) else {
        return CKR_ARGUMENTS_BAD;
    };
    if mechanism != CKM_RSA_PKCS && mechanism != CKM_SHA256_RSA_PKCS {
        return CKR_MECHANISM_INVALID;
    }
    info.ulMinKeySize = 1024;
    info.ulMaxKeySize = 4096;
    info.flags = CKF_SIGN | CKF_HW;
    CKR_OK
}
