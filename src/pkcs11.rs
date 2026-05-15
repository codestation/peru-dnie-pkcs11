use crate::{api, card::DnieCard};
use std::sync::{LazyLock, Mutex};

pub use cryptoki_sys::*;

#[derive(Default)]
pub(crate) struct Session {
    pub(crate) handle: CK_SESSION_HANDLE,
    pub(crate) open: bool,
    pub(crate) find_active: bool,
    pub(crate) find_results: Vec<CK_OBJECT_HANDLE>,
    pub(crate) find_pos: usize,
    pub(crate) sign_key: CK_OBJECT_HANDLE,
    pub(crate) sign_mech: CK_MECHANISM_TYPE,
    pub(crate) sign_data: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) initialized: bool,
    pub(crate) card: Option<DnieCard>,
    pub(crate) sessions: Vec<Session>,
    pub(crate) next_session: CK_SESSION_HANDLE,
}

pub(crate) static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| {
    Mutex::new(State {
        next_session: 1,
        ..State::default()
    })
});

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(api::C_Initialize),
    C_Finalize: Some(api::C_Finalize),
    C_GetInfo: Some(api::C_GetInfo),
    C_GetFunctionList: Some(api::C_GetFunctionList),
    C_GetSlotList: Some(api::slot::C_GetSlotList),
    C_GetSlotInfo: Some(api::slot::C_GetSlotInfo),
    C_GetTokenInfo: Some(api::slot::C_GetTokenInfo),
    C_GetMechanismList: Some(api::mechanism::C_GetMechanismList),
    C_GetMechanismInfo: Some(api::mechanism::C_GetMechanismInfo),
    C_InitToken: Some(api::token_pin::C_InitToken),
    C_InitPIN: Some(api::token_pin::C_InitPIN),
    C_SetPIN: Some(api::token_pin::C_SetPIN),
    C_OpenSession: Some(api::session::C_OpenSession),
    C_CloseSession: Some(api::session::C_CloseSession),
    C_CloseAllSessions: Some(api::session::C_CloseAllSessions),
    C_GetSessionInfo: Some(api::session::C_GetSessionInfo),
    C_GetOperationState: Some(api::operation::C_GetOperationState),
    C_SetOperationState: Some(api::operation::C_SetOperationState),
    C_Login: Some(api::auth::C_Login),
    C_Logout: Some(api::auth::C_Logout),
    C_CreateObject: Some(api::object::C_CreateObject),
    C_CopyObject: Some(api::object::C_CopyObject),
    C_DestroyObject: Some(api::object::C_DestroyObject),
    C_GetObjectSize: Some(api::object::C_GetObjectSize),
    C_GetAttributeValue: Some(api::object::C_GetAttributeValue),
    C_SetAttributeValue: Some(api::object::C_SetAttributeValue),
    C_FindObjectsInit: Some(api::object::C_FindObjectsInit),
    C_FindObjects: Some(api::object::C_FindObjects),
    C_FindObjectsFinal: Some(api::object::C_FindObjectsFinal),
    C_EncryptInit: Some(api::encrypt::C_EncryptInit),
    C_Encrypt: Some(api::encrypt::C_Encrypt),
    C_EncryptUpdate: Some(api::encrypt::C_EncryptUpdate),
    C_EncryptFinal: Some(api::encrypt::C_EncryptFinal),
    C_DecryptInit: Some(api::decrypt::C_DecryptInit),
    C_Decrypt: Some(api::decrypt::C_Decrypt),
    C_DecryptUpdate: Some(api::decrypt::C_DecryptUpdate),
    C_DecryptFinal: Some(api::decrypt::C_DecryptFinal),
    C_DigestInit: Some(api::digest::C_DigestInit),
    C_Digest: Some(api::digest::C_Digest),
    C_DigestUpdate: Some(api::digest::C_DigestUpdate),
    C_DigestKey: Some(api::digest::C_DigestKey),
    C_DigestFinal: Some(api::digest::C_DigestFinal),
    C_SignInit: Some(api::sign::C_SignInit),
    C_Sign: Some(api::sign::C_Sign),
    C_SignUpdate: Some(api::sign::C_SignUpdate),
    C_SignFinal: Some(api::sign::C_SignFinal),
    C_SignRecoverInit: Some(api::sign::C_SignRecoverInit),
    C_SignRecover: Some(api::sign::C_SignRecover),
    C_VerifyInit: Some(api::verify::C_VerifyInit),
    C_Verify: Some(api::verify::C_Verify),
    C_VerifyUpdate: Some(api::verify::C_VerifyUpdate),
    C_VerifyFinal: Some(api::verify::C_VerifyFinal),
    C_VerifyRecoverInit: Some(api::verify::C_VerifyRecoverInit),
    C_VerifyRecover: Some(api::verify::C_VerifyRecover),
    C_DigestEncryptUpdate: Some(api::digest::C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(api::decrypt::C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(api::sign::C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(api::decrypt::C_DecryptVerifyUpdate),
    C_GenerateKey: Some(api::key::C_GenerateKey),
    C_GenerateKeyPair: Some(api::key::C_GenerateKeyPair),
    C_WrapKey: Some(api::key::C_WrapKey),
    C_UnwrapKey: Some(api::key::C_UnwrapKey),
    C_DeriveKey: Some(api::key::C_DeriveKey),
    C_SeedRandom: Some(api::random::C_SeedRandom),
    C_GenerateRandom: Some(api::random::C_GenerateRandom),
    C_GetFunctionStatus: Some(api::operation::C_GetFunctionStatus),
    C_CancelFunction: Some(api::operation::C_CancelFunction),
    C_WaitForSlotEvent: Some(api::event::C_WaitForSlotEvent),
};

pub(crate) fn function_list_ptr() -> CK_FUNCTION_LIST_PTR {
    &FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR
}

pub(crate) fn zeroed_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    let out = crate::ffi::ptr_mut(ptr)?;
    crate::ffi::zero_ref(out);
    Some(out)
}

pub(crate) fn session_index(st: &State, handle: CK_SESSION_HANDLE) -> Option<usize> {
    st.sessions
        .iter()
        .position(|s| s.open && s.handle == handle)
}

pub(crate) fn token_present(st: &State) -> bool {
    st.card.as_ref().is_some_and(|c| c.present)
}

pub(crate) fn has_session(st: &State, handle: CK_SESSION_HANDLE) -> bool {
    session_index(st, handle).is_some()
}

pub(crate) fn fill_blank(dst: &mut [u8], src: &[u8]) {
    dst.fill(b' ');
    let n = dst.len().min(src.len());
    dst[..n].copy_from_slice(&src[..n]);
}
