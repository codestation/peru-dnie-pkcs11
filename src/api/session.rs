use crate::{ffi::ptr_mut, pkcs11::*};

#[unsafe(no_mangle)]
pub extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _app: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session_out: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if slot_id != 1 {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(session_out) = ptr_mut(session_out) else {
        return CKR_ARGUMENTS_BAD;
    };
    if flags & CKF_SERIAL_SESSION == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    let mut st = STATE.lock().unwrap();
    if !crate::pkcs11::token_present(&st) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if st.sessions.iter().filter(|s| s.open).count() >= 8 {
        return CKR_SESSION_COUNT;
    }
    let handle = st.next_session;
    st.next_session += 1;
    st.sessions.push(Session {
        handle,
        open: true,
        ..Session::default()
    });
    *session_out = handle;
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_CloseSession(handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    let Some(pos) = st
        .sessions
        .iter()
        .position(|s| s.open && s.handle == handle)
    else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    st.sessions.remove(pos);
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_CloseAllSessions(slot_id: CK_SLOT_ID) -> CK_RV {
    if slot_id != 1 {
        return CKR_SLOT_ID_INVALID;
    }
    let mut st = STATE.lock().unwrap();
    st.sessions.clear();
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetSessionInfo(handle: CK_SESSION_HANDLE, info: CK_SESSION_INFO_PTR) -> CK_RV {
    let Some(info) = ptr_mut(info) else {
        return CKR_ARGUMENTS_BAD;
    };
    let st = STATE.lock().unwrap();
    if !has_session(&st, handle) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    info.slotID = 1;
    info.state = if st.card.as_ref().is_some_and(|c| c.pin_verified) {
        CKS_RO_USER_FUNCTIONS
    } else {
        CKS_RO_PUBLIC_SESSION
    };
    info.flags = CKF_SERIAL_SESSION;
    info.ulDeviceError = 0;
    CKR_OK
}
