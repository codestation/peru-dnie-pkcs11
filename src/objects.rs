use crate::card::{CertObject, DnieCard};
use crate::ffi::{copy_to_raw, slice_from_raw};
use crate::pkcs11::*;
use std::mem;

pub const OBJECT_CERT: CK_OBJECT_HANDLE = 1;
pub const OBJECT_PRIVKEY: CK_OBJECT_HANDLE = 2;
pub const OBJECT_CHAIN_CERT_BASE: CK_OBJECT_HANDLE = 100;

static OBJECT_ID: [u8; 1] = [0x01];

// Certificate and key objects share lazy loading rules, so callers can ask
// this helper to populate only the material needed for the object they are
// about to inspect.
pub fn ensure_object_loaded(card: &mut DnieCard, object: CK_OBJECT_HANDLE) -> Result<(), i32> {
    if object == OBJECT_CERT || object == OBJECT_PRIVKEY {
        return card.ensure_signing_certificate();
    }
    Ok(())
}

pub fn get_attribute(card: &DnieCard, object: CK_OBJECT_HANDLE, attr: &mut CK_ATTRIBUTE) -> CK_RV {
    if object == OBJECT_CERT {
        return cert_attribute(
            &card.certificate,
            &OBJECT_ID,
            b"Peru DNIe signing certificate",
            attr,
        );
    }
    if let Some(idx) = chain_index(card, object) {
        let id = object_id_for_chain(idx);
        let label = format!("Peru DNIe chain certificate {}", idx + 1);
        return cert_attribute(&card.chain[idx], &id, label.as_bytes(), attr);
    }
    if object != OBJECT_PRIVKEY {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    match attr.type_ {
        CKA_CLASS => copy_ulong(attr, CKO_PRIVATE_KEY),
        CKA_TOKEN => copy_bool(attr, CK_TRUE),
        CKA_PRIVATE => copy_bool(attr, CK_TRUE),
        CKA_LABEL => copy_bytes(attr, b"Peru DNIe signing certificate"),
        CKA_ID => copy_bytes(attr, &OBJECT_ID),
        CKA_KEY_TYPE => copy_ulong(attr, CKK_RSA),
        CKA_SIGN => copy_bool(attr, CK_TRUE),
        CKA_DECRYPT | CKA_SIGN_RECOVER | CKA_UNWRAP | CKA_DERIVE => copy_bool(attr, CK_FALSE),
        CKA_EXTRACTABLE => copy_bool(attr, CK_FALSE),
        CKA_SENSITIVE | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE | CKA_LOCAL => {
            copy_bool(attr, CK_TRUE)
        }
        CKA_ALWAYS_AUTHENTICATE => copy_bool(attr, CK_FALSE),
        CKA_MODULUS if !card.public_modulus.is_empty() => copy_bytes(attr, &card.public_modulus),
        CKA_PUBLIC_EXPONENT if !card.public_exponent.is_empty() => {
            copy_bytes(attr, &card.public_exponent)
        }
        CKA_MODULUS_BITS if card.public_modulus_bits > 0 => {
            let bits = card.public_modulus_bits as CK_ULONG;
            copy_ulong(attr, bits)
        }
        _ => {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            CKR_ATTRIBUTE_TYPE_INVALID
        }
    }
}

pub fn object_size(card: &DnieCard, object: CK_OBJECT_HANDLE) -> Option<CK_ULONG> {
    if object == OBJECT_CERT {
        return Some(card.certificate.der.len() as CK_ULONG);
    }
    if let Some(idx) = chain_index(card, object) {
        return Some(card.chain[idx].der.len() as CK_ULONG);
    }
    if object == OBJECT_PRIVKEY {
        return Some(card.public_modulus.len().max(256) as CK_ULONG);
    }
    None
}

pub fn object_matches(
    card: &DnieCard,
    object: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> bool {
    if count == 0 {
        return true;
    }
    if template.is_null() {
        return false;
    }
    let Some(attrs) = attr_slice(template, count) else {
        return false;
    };
    for attr in attrs {
        if attr.pValue.is_null() {
            continue;
        }
        match attr.type_ {
            CKA_CLASS if attr.ulValueLen as usize == mem::size_of::<CK_OBJECT_CLASS>() => {
                let class = read_object_class(attr);
                let is_cert = object == OBJECT_CERT || object >= OBJECT_CHAIN_CERT_BASE;
                if is_cert && class != CKO_CERTIFICATE {
                    return false;
                }
                if object == OBJECT_PRIVKEY && class != CKO_PRIVATE_KEY {
                    return false;
                }
            }
            CKA_ID if bytes(attr) != object_id_for(object) => {
                return false;
            }
            CKA_LABEL => {
                let label = label_for(object);
                if bytes(attr) != label.as_bytes() {
                    return false;
                }
            }
            CKA_ISSUER | CKA_SERIAL_NUMBER | CKA_SUBJECT | CKA_VALUE => {
                let Some(cert) = cert_for(card, object) else {
                    return false;
                };
                let field = match attr.type_ {
                    CKA_ISSUER => cert.issuer.as_slice(),
                    CKA_SERIAL_NUMBER => cert.serial.as_slice(),
                    CKA_SUBJECT => cert.subject.as_slice(),
                    _ => cert.der.as_slice(),
                };
                if bytes(attr) != field {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

pub fn may_request_certificate_objects(template: CK_ATTRIBUTE_PTR, count: CK_ULONG) -> bool {
    if count == 0 {
        return true;
    }
    if template.is_null() {
        return false;
    }
    let Some(attrs) = attr_slice(template, count) else {
        return false;
    };
    for attr in attrs {
        if attr.type_ != CKA_CLASS || attr.pValue.is_null() {
            continue;
        }
        if attr.ulValueLen as usize != mem::size_of::<CK_OBJECT_CLASS>() {
            return false;
        }
        let class = read_object_class(attr);
        return class == CKO_CERTIFICATE;
    }
    true
}

fn cert_attribute(cert: &CertObject, id: &[u8], label: &[u8], attr: &mut CK_ATTRIBUTE) -> CK_RV {
    match attr.type_ {
        CKA_CLASS => copy_ulong(attr, CKO_CERTIFICATE),
        CKA_TOKEN => copy_bool(attr, CK_TRUE),
        CKA_PRIVATE => copy_bool(attr, CK_FALSE),
        CKA_LABEL => copy_bytes(attr, label),
        CKA_CERTIFICATE_TYPE => copy_ulong(attr, CKC_X_509),
        CKA_TRUSTED => copy_bool(attr, CK_FALSE),
        CKA_ID => copy_bytes(attr, id),
        CKA_ENCRYPT | CKA_DECRYPT | CKA_WRAP | CKA_UNWRAP | CKA_SIGN | CKA_SIGN_RECOVER
        | CKA_VERIFY | CKA_VERIFY_RECOVER | CKA_DERIVE => copy_bool(attr, CK_FALSE),
        CKA_SUBJECT if !cert.subject.is_empty() => copy_bytes(attr, &cert.subject),
        CKA_ISSUER if !cert.issuer.is_empty() => copy_bytes(attr, &cert.issuer),
        CKA_SERIAL_NUMBER if !cert.serial.is_empty() => copy_bytes(attr, &cert.serial),
        CKA_VALUE if !cert.der.is_empty() => copy_bytes(attr, &cert.der),
        _ => {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            CKR_ATTRIBUTE_TYPE_INVALID
        }
    }
}

fn copy_bool(attr: &mut CK_ATTRIBUTE, value: CK_BBOOL) -> CK_RV {
    copy_bytes(attr, &[value])
}

fn copy_ulong(attr: &mut CK_ATTRIBUTE, value: CK_ULONG) -> CK_RV {
    copy_bytes(attr, &value.to_ne_bytes())
}

fn copy_bytes(attr: &mut CK_ATTRIBUTE, value: &[u8]) -> CK_RV {
    if attr.pValue.is_null() {
        attr.ulValueLen = value.len() as CK_ULONG;
        return CKR_OK;
    }
    if attr.ulValueLen < value.len() as CK_ULONG {
        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    copy_to_raw(attr.pValue as CK_BYTE_PTR, value);
    attr.ulValueLen = value.len() as CK_ULONG;
    CKR_OK
}

fn bytes(attr: &CK_ATTRIBUTE) -> &[u8] {
    slice_from_raw(attr.pValue as *const u8, attr.ulValueLen).unwrap_or(&[])
}

fn attr_slice<'a>(ptr: CK_ATTRIBUTE_PTR, count: CK_ULONG) -> Option<&'a [CK_ATTRIBUTE]> {
    slice_from_raw(ptr, count)
}

fn read_object_class(attr: &CK_ATTRIBUTE) -> CK_OBJECT_CLASS {
    let mut raw = [0u8; mem::size_of::<CK_OBJECT_CLASS>()];
    raw.copy_from_slice(bytes(attr));
    CK_OBJECT_CLASS::from_ne_bytes(raw)
}

fn chain_index(card: &DnieCard, object: CK_OBJECT_HANDLE) -> Option<usize> {
    if object < OBJECT_CHAIN_CERT_BASE {
        return None;
    }
    let idx = (object - OBJECT_CHAIN_CERT_BASE) as usize;
    (idx < card.chain.len()).then_some(idx)
}

fn cert_for(card: &DnieCard, object: CK_OBJECT_HANDLE) -> Option<&CertObject> {
    if object == OBJECT_CERT {
        Some(&card.certificate)
    } else {
        chain_index(card, object).map(|idx| &card.chain[idx])
    }
}

fn label_for(object: CK_OBJECT_HANDLE) -> String {
    if object == OBJECT_CERT || object == OBJECT_PRIVKEY {
        "Peru DNIe signing certificate".to_owned()
    } else if object >= OBJECT_CHAIN_CERT_BASE {
        format!(
            "Peru DNIe chain certificate {}",
            object - OBJECT_CHAIN_CERT_BASE + 1
        )
    } else {
        String::new()
    }
}

fn object_id_for(object: CK_OBJECT_HANDLE) -> &'static [u8] {
    if object >= OBJECT_CHAIN_CERT_BASE {
        const CHAIN_IDS: [u8; 4] = [0x02, 0x03, 0x04, 0x05];
        let idx = (object - OBJECT_CHAIN_CERT_BASE) as usize;
        CHAIN_IDS
            .get(idx)
            .map_or(&[], |id| core::slice::from_ref(id))
    } else {
        &OBJECT_ID
    }
}

fn object_id_for_chain(idx: usize) -> [u8; 1] {
    [(0x02 + idx) as u8]
}
