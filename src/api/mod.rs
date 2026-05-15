use crate::{
    card::DnieCard,
    ffi::ptr_mut,
    pkcs11::{
        CK_INFO_PTR, CK_RV, CK_VERSION, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_ALREADY_INITIALIZED,
        CKR_CRYPTOKI_NOT_INITIALIZED, CKR_OK, STATE, fill_blank, function_list_ptr, zeroed_mut,
    },
};

pub mod auth;
pub mod decrypt;
pub mod digest;
pub mod encrypt;
pub mod event;
pub mod key;
pub mod mechanism;
pub mod object;
pub mod operation;
pub mod random;
pub mod session;
pub mod sign;
pub mod slot;
pub mod token_pin;
pub mod verify;

pub(crate) fn not_supported() -> CK_RV {
    crate::pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Initialize(_args: crate::pkcs11::CK_VOID_PTR) -> CK_RV {
    crate::build_info::log_startup_metadata();
    crate::log_info!("C_Initialize begin");
    let mut st = STATE.lock().unwrap();
    if st.initialized {
        crate::log_warn!("C_Initialize called while already initialized");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    match DnieCard::open() {
        Ok(card) => {
            crate::log_info!(
                "DNIe open completed: present={}, profile={}, certificate_deferred=true, chain_deferred=true",
                card.present,
                card.profile_name()
            );
            st.card = Some(card);
        }
        Err(_) => {
            crate::log_warn!("DNIe open failed; publishing empty removable slot");
            st.card = Some(DnieCard::default());
        }
    }
    st.sessions.clear();
    st.next_session = 1;
    st.initialized = true;
    crate::log_info!("C_Initialize end");
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Finalize(reserved: crate::pkcs11::CK_VOID_PTR) -> CK_RV {
    crate::log_info!("C_Finalize begin");
    if !reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut st = STATE.lock().unwrap();
    if !st.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if let Some(card) = st.card.as_mut() {
        card.close();
    }
    st.card = None;
    st.sessions.clear();
    st.initialized = false;
    crate::log_info!("C_Finalize end");
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetInfo(info: CK_INFO_PTR) -> CK_RV {
    let Some(info) = zeroed_mut(info) else {
        return CKR_ARGUMENTS_BAD;
    };
    info.cryptokiVersion = CK_VERSION {
        major: 2,
        minor: 40,
    };
    fill_blank(&mut info.manufacturerID, b"Peru DNIe community");
    fill_blank(&mut info.libraryDescription, b"Peru DNIe PKCS11 Rust");
    info.libraryVersion = CK_VERSION { major: 0, minor: 1 };
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionList(out: crate::pkcs11::CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    let Some(out_ref) = ptr_mut(out) else {
        return CKR_ARGUMENTS_BAD;
    };
    *out_ref = function_list_ptr();
    CKR_OK
}
