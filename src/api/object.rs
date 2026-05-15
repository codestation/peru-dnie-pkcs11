use crate::{
    ffi::{mut_slice_from_raw, ptr_mut},
    objects,
    pkcs11::*,
};

#[unsafe(no_mangle)]
pub extern "C" fn C_CreateObject(
    _session: CK_SESSION_HANDLE,
    _template: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_CopyObject(
    _session: CK_SESSION_HANDLE,
    _object: CK_OBJECT_HANDLE,
    _template: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
    _new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DestroyObject(_session: CK_SESSION_HANDLE, _object: CK_OBJECT_HANDLE) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetObjectSize(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> CK_RV {
    let Some(size) = ptr_mut(size) else {
        return CKR_ARGUMENTS_BAD;
    };
    let mut st = STATE.lock().unwrap();
    if !has_session(&st, session) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let Some(card) = st.card.as_mut() else {
        return CKR_TOKEN_NOT_PRESENT;
    };
    if objects::ensure_object_loaded(card, object).is_err() {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    let Some(n) = objects::object_size(card, object) else {
        return CKR_OBJECT_HANDLE_INVALID;
    };
    *size = n;
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetAttributeValue(
    handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    if !has_session(&st, handle) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if template.is_null() && count > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(card) = st.card.as_mut() else {
        return CKR_TOKEN_NOT_PRESENT;
    };
    if objects::ensure_object_loaded(card, object).is_err() {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    let Some(template) = mut_slice_from_raw(template, count) else {
        return CKR_ARGUMENTS_BAD;
    };
    let mut rv = CKR_OK;
    for attr in template {
        let ar = objects::get_attribute(card, object, attr);
        crate::log_debug!(
            "C_GetAttributeValue: object={}, attr=0x{:X}, rv=0x{:X}, len={}",
            object,
            attr.type_,
            ar,
            attr.ulValueLen
        );
        if ar != CKR_OK {
            rv = ar;
        }
    }
    crate::log_debug!(
        "C_GetAttributeValue complete: object={}, attr_count={}, rv=0x{:X}",
        object,
        count,
        rv
    );
    rv
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SetAttributeValue(
    _session: CK_SESSION_HANDLE,
    _object: CK_OBJECT_HANDLE,
    _template: CK_ATTRIBUTE_PTR,
    _count: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_FindObjectsInit(
    handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    let Some(idx) = session_index(&st, handle) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let Some(card) = st.card.as_mut() else {
        return CKR_TOKEN_NOT_PRESENT;
    };
    if objects::ensure_object_loaded(card, objects::OBJECT_CERT).is_err() {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if objects::may_request_certificate_objects(template, count) {
        let _ = card.ensure_chain_certs();
    }
    let mut results = Vec::new();
    if !card.certificate.der.is_empty()
        && objects::object_matches(card, objects::OBJECT_CERT, template, count)
    {
        results.push(objects::OBJECT_CERT);
    }
    for i in 0..card.chain.len() {
        let object = objects::OBJECT_CHAIN_CERT_BASE + i as CK_OBJECT_HANDLE;
        if objects::object_matches(card, object, template, count) {
            results.push(object);
        }
    }
    if card.pin_verified && objects::object_matches(card, objects::OBJECT_PRIVKEY, template, count)
    {
        results.push(objects::OBJECT_PRIVKEY);
    }
    st.sessions[idx].find_active = true;
    st.sessions[idx].find_results = results;
    st.sessions[idx].find_pos = 0;
    crate::log_debug!(
        "C_FindObjectsInit: session={}, template_count={}, result_count={}",
        handle,
        count,
        st.sessions[idx].find_results.len()
    );
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_FindObjects(
    handle: CK_SESSION_HANDLE,
    objects_out: CK_OBJECT_HANDLE_PTR,
    max_count: CK_ULONG,
    count_out: CK_ULONG_PTR,
) -> CK_RV {
    let Some(count_out) = ptr_mut(count_out) else {
        return CKR_ARGUMENTS_BAD;
    };
    if objects_out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(objects_out) = mut_slice_from_raw(objects_out, max_count) else {
        return CKR_ARGUMENTS_BAD;
    };
    let mut st = STATE.lock().unwrap();
    let Some(idx) = session_index(&st, handle) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let s = &mut st.sessions[idx];
    if !s.find_active {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let mut n = 0usize;
    while n < max_count as usize && s.find_pos < s.find_results.len() {
        objects_out[n] = s.find_results[s.find_pos];
        s.find_pos += 1;
        n += 1;
    }
    *count_out = n as CK_ULONG;
    crate::log_debug!(
        "C_FindObjects: session={}, max_count={}, returned_count={}, next_pos={}",
        handle,
        max_count,
        n,
        s.find_pos
    );
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_FindObjectsFinal(handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    let Some(idx) = session_index(&st, handle) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    st.sessions[idx].find_active = false;
    CKR_OK
}
