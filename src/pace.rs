use crate::{apdu, tlv};
use aes::{
    Aes256,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, array::Array},
};
use bp256::{
    FieldBytes, Scalar,
    elliptic_curve::{
        PrimeField,
        sec1::{FromSec1Point, ToSec1Point},
    },
    r1::{AffinePoint, ProjectivePoint, Sec1Point},
};
use cmac::{Cmac, Mac};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use pcsc::Card;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const PACE_ECDH_IM_AES_CBC_CMAC_256_OID: &[u8] =
    &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04];
const PASSWORD_REF_CAN: u8 = 0x02;

const BP256_P: &[u8] =
    &hex_bytes("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377");
const BP256_A: &[u8] =
    &hex_bytes("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9");
const BP256_B: &[u8] =
    &hex_bytes("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6");
const BP256_G: &[u8] = &sec1(
    &hex_bytes("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"),
    &hex_bytes("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"),
);
const BP256_ORDER: &[u8] =
    &hex_bytes("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7");
const BP256_COFACTOR: &[u8] = &[0x01];

#[derive(Clone)]
pub struct SecureMessaging {
    k_enc: [u8; 32],
    k_mac: [u8; 32],
    ssc: u64,
}

impl Drop for SecureMessaging {
    fn drop(&mut self) {
        self.k_enc.zeroize();
        self.k_mac.zeroize();
    }
}

impl SecureMessaging {
    fn new(k_enc: [u8; 32], k_mac: [u8; 32]) -> Self {
        Self {
            k_enc,
            k_mac,
            ssc: 0,
        }
    }

    pub fn wrap_apdu(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Option<u32>,
    ) -> Result<Vec<u8>, ()> {
        if data.len() > 65535 || le.is_some_and(|v| v > 65536) {
            return Err(());
        }

        let sm_cla = cla | 0x0C;
        let mut body = Vec::new();
        if !data.is_empty() {
            let mut padded = Vec::new();
            append_iso_pad(&mut padded, data);
            self.ssc = self.ssc.checked_add(1).ok_or(())?;
            let iv = self.derive_iv(self.ssc);
            let cryptogram = aes256_cbc_encrypt(&self.k_enc, &iv, &padded)?;
            let mut do87 = Vec::with_capacity(cryptogram.len() + 1);
            do87.push(0x01);
            do87.extend_from_slice(&cryptogram);
            append_tlv(&mut body, 0x87, &do87)?;
        } else {
            self.ssc = self.ssc.checked_add(1).ok_or(())?;
        }

        if let Some(le) = le {
            let encoded = if le <= 256 {
                vec![if le == 256 { 0 } else { le as u8 }]
            } else {
                vec![(le >> 8) as u8, le as u8]
            };
            append_tlv(&mut body, 0x97, &encoded)?;
        }

        let mut padded_header = Vec::new();
        append_iso_pad(&mut padded_header, &[sm_cla, ins, p1, p2]);
        let mut mac_input = Vec::new();
        append_ssc(&mut mac_input, self.ssc);
        mac_input.extend_from_slice(&padded_header);
        mac_input.extend_from_slice(&body);
        let mac = aes_cmac_trunc8(&self.k_mac, &iso_padded(&mac_input))?;
        append_tlv(&mut body, 0x8E, &mac)?;

        let mut wrapped = vec![sm_cla, ins, p1, p2];
        if body.len() <= 255 && le.is_none_or(|v| v <= 256) {
            wrapped.push(body.len() as u8);
            wrapped.extend_from_slice(&body);
            wrapped.push(0);
        } else {
            wrapped.push(0);
            wrapped.push((body.len() >> 8) as u8);
            wrapped.push(body.len() as u8);
            wrapped.extend_from_slice(&body);
            wrapped.extend_from_slice(&[0, 0]);
        }
        Ok(wrapped)
    }

    pub fn unwrap_response(&mut self, rsp: &[u8]) -> Result<(Vec<u8>, u16), ()> {
        if rsp.len() < 2 {
            return Err(());
        }
        if rsp.len() == 2 {
            return Ok((Vec::new(), u16::from_be_bytes([rsp[0], rsp[1]])));
        }

        self.ssc = self.ssc.checked_add(1).ok_or(())?;
        let mut mac_input = Vec::new();
        append_ssc(&mut mac_input, self.ssc);

        let mut off = 0;
        let mut encrypted: Option<&[u8]> = None;
        let mut sw = None;
        while off < rsp.len() {
            let item = tlv::parse_one(&rsp[off..]).ok_or(())?;
            if item.tag == 0x8E {
                if item.value.len() != 8 {
                    return Err(());
                }
                let mac = aes_cmac_trunc8(&self.k_mac, &iso_padded(&mac_input))?;
                if mac.ct_eq(item.value).unwrap_u8() != 1 {
                    return Err(());
                }
                let mut plain = Vec::new();
                if let Some(ciphertext) = encrypted {
                    let iv = self.derive_iv(self.ssc);
                    let padded = aes256_cbc_decrypt(&self.k_enc, &iv, ciphertext)?;
                    plain.extend_from_slice(unpad_iso(&padded).unwrap_or(&padded));
                }
                return Ok((plain, sw.unwrap_or(0x9000)));
            }

            mac_input.extend_from_slice(&rsp[off..off + item.total_len]);
            match item.tag {
                0x87 | 0x85 if !item.value.is_empty() => {
                    encrypted = if item.tag == 0x87
                        && item.value[0] == 0x01
                        && item.value.len() > 1
                        && (item.value.len() - 1) % 16 == 0
                    {
                        Some(&item.value[1..])
                    } else {
                        Some(item.value)
                    };
                }
                0x99 if item.value.len() == 2 => {
                    sw = Some(u16::from_be_bytes([item.value[0], item.value[1]]));
                }
                _ => {}
            }
            off += item.total_len;
        }
        Err(())
    }

    fn derive_iv(&self, ssc: u64) -> [u8; 16] {
        let mut encoded = [0u8; 16];
        encoded[8..].copy_from_slice(&ssc.to_be_bytes());
        aes256_ecb_encrypt_block(&self.k_enc, encoded)
    }
}

struct PaceInfo {
    oid_der: Vec<u8>,
    parameter_id: u8,
}

pub fn establish(card: &Card, can: &str) -> Result<SecureMessaging, ()> {
    crate::log_info!("PACE begin: reading EF.CardAccess");
    let info = read_card_access(card)?;
    crate::log_info!(
        "PACE EF.CardAccess parsed: protocol=id-PACE-ECDH-IM-AES-CBC-CMAC-256, parameter_id={}",
        info.parameter_id
    );
    crate::log_info!("PACE MSE:Set AT begin");
    mse_set_at(card, &info)?;
    crate::log_info!("PACE MSE:Set AT succeeded");
    perform_pace_im(card, can, &info)
}

fn read_card_access(card: &Card) -> Result<PaceInfo, ()> {
    crate::log_debug!("PACE EF.CardAccess SELECT by FID begin");
    transmit_ok(
        card,
        &apdu::encode(0, 0xA4, 0x02, 0x0C, &[0x01, 0x1C], None)?,
    )?;
    crate::log_debug!("PACE EF.CardAccess SELECT by FID succeeded");

    let first = read_binary(card, 0, 8)?;
    let total = tlv::total_from_prefix(&first).ok_or(())?;
    crate::log_debug!(
        "PACE EF.CardAccess prefix read: prefix_len={}, total_len={}",
        first.len(),
        total
    );
    let mut card_access = first;
    while card_access.len() < total {
        let le = (total - card_access.len()).min(0xDF) as u32;
        let chunk = read_binary(card, card_access.len() as u16, le)?;
        if chunk.is_empty() {
            return Err(());
        }
        card_access.extend_from_slice(&chunk);
        crate::log_trace!(
            "PACE EF.CardAccess chunk read: accumulated_len={}, total_len={}",
            card_access.len(),
            total
        );
    }
    parse_card_access(&card_access)
}

fn parse_card_access(card_access: &[u8]) -> Result<PaceInfo, ()> {
    let outer = tlv::parse_one(card_access).ok_or(())?;
    if outer.tag != 0x31 {
        return Err(());
    }
    let mut off = 0;
    while off < outer.value.len() {
        let seq = tlv::parse_one(&outer.value[off..]).ok_or(())?;
        if seq.tag == 0x30 {
            let oid = tlv::parse_one(seq.value).ok_or(())?;
            crate::log_trace!(
                "PACEInfo candidate found: oid_len={}, supported={}",
                oid.value.len(),
                oid.tag == 0x06 && oid.value == PACE_ECDH_IM_AES_CBC_CMAC_256_OID
            );
            if oid.tag == 0x06 && oid.value == PACE_ECDH_IM_AES_CBC_CMAC_256_OID {
                let rest = &seq.value[oid.total_len..];
                let version = tlv::parse_one(rest).ok_or(())?;
                let param = tlv::parse_one(&rest[version.total_len..]).ok_or(())?;
                if version.tag == 0x02
                    && param.tag == 0x02
                    && param.value.len() == 1
                    && param.value[0] != 0
                {
                    return Ok(PaceInfo {
                        oid_der: oid.value.to_vec(),
                        parameter_id: param.value[0],
                    });
                }
            }
        }
        off += seq.total_len;
    }
    crate::log_warn!(
        "EF.CardAccess did not contain supported id-PACE-ECDH-IM-AES-CBC-CMAC-256 PACEInfo"
    );
    Err(())
}

fn mse_set_at(card: &Card, info: &PaceInfo) -> Result<(), ()> {
    let mut body = Vec::new();
    append_tlv(&mut body, 0x80, &info.oid_der)?;
    append_tlv(&mut body, 0x83, &[PASSWORD_REF_CAN])?;
    append_tlv(&mut body, 0x84, &[info.parameter_id])?;
    transmit_ok(card, &apdu::encode(0, 0x22, 0xC1, 0xA4, &body, None)?)
}

fn perform_pace_im(card: &Card, can: &str, _info: &PaceInfo) -> Result<SecureMessaging, ()> {
    crate::log_info!("PACE IM begin: requesting encrypted nonce");
    let enc_nonce = general_authenticate(card, 0x10, None, 0, 0x80)?;
    crate::log_debug!("PACE IM encrypted nonce received: len={}", enc_nonce.len());
    crate::log_info!("PACE IM decrypting nonce with configured CAN");
    let nonce_s = decrypt_nonce(can, &enc_nonce)?;
    crate::log_debug!("PACE IM nonce decrypted: len={}", nonce_s.len());
    let nonce_t = random_32()?;
    crate::log_info!("PACE IM nonce mapping exchange begin");
    let _picc_mapping = general_authenticate(card, 0x10, Some((0x81, &nonce_t)), 0, 0x82)?;
    crate::log_debug!("PACE IM nonce mapping exchange succeeded");

    crate::log_info!("PACE IM mapped generator derivation begin");
    let x = im_prf(&nonce_s, &nonce_t)?;
    let mapped_generator = icart_point_encode(&x)?;
    crate::log_debug!("PACE IM mapped generator derived");
    let private_scalar = random_scalar()?;
    let pcd_point = mapped_generator * private_scalar;
    let pcd_pub = encode_point(&pcd_point.to_affine());
    crate::log_info!("PACE IM ephemeral public key exchange begin");
    let picc_pub = general_authenticate(card, 0x10, Some((0x83, &pcd_pub)), 0, 0x84)?;
    if picc_pub.len() != 65 {
        crate::log_warn!(
            "PACE IM unexpected PICC public key length: len={}",
            picc_pub.len()
        );
        return Err(());
    }
    crate::log_debug!("PACE IM PICC public key received: len={}", picc_pub.len());
    let picc_point = decode_point(&picc_pub)?;
    let shared = picc_point * private_scalar;
    let shared_x = affine_x(&shared.to_affine())?;
    crate::log_info!("PACE IM shared secret derived; deriving secure messaging keys");
    let k_enc = kdf(&shared_x, 1);
    let k_mac = kdf(&shared_x, 2);

    let pcd_token = auth_token(&k_mac, &picc_pub)?;
    let expected_picc_token = auth_token(&k_mac, &pcd_pub)?;
    crate::log_debug!(
        "PACE IM authentication tokens computed: encoding=domain-parameters, token_len={}",
        pcd_token.len()
    );
    crate::log_info!("PACE IM authentication token exchange begin");
    let picc_token = general_authenticate(card, 0, Some((0x85, &pcd_token)), 0, 0x86)?;
    if picc_token.ct_eq(&expected_picc_token).unwrap_u8() != 1 {
        crate::log_warn!(
            "PACE IM PICC authentication token verification failed: token_len={}",
            picc_token.len()
        );
        return Err(());
    }
    crate::log_info!("PACE IM authentication token verified; secure messaging ready");
    Ok(SecureMessaging::new(k_enc, k_mac))
}

fn general_authenticate(
    card: &Card,
    cla: u8,
    payload: Option<(u8, &[u8])>,
    le: u32,
    response_tag: u32,
) -> Result<Vec<u8>, ()> {
    crate::log_debug!(
        "PACE GENERAL AUTHENTICATE begin: cla={cla:02X}, payload_tag={}, response_tag={response_tag:02X}",
        payload
            .map(|(tag, _)| format!("{tag:02X}"))
            .unwrap_or_else(|| "none".to_owned())
    );
    let mut inner = Vec::new();
    if let Some((tag, value)) = payload {
        append_tlv(&mut inner, tag, value)?;
    }
    let mut body = Vec::new();
    append_tlv(&mut body, 0x7C, &inner)?;
    let rsp = transmit_raw(card, &apdu::encode(cla, 0x86, 0, 0, &body, Some(le))?)?;
    let (plain, sw) = split_status(&rsp)?;
    crate::log_debug!(
        "PACE GENERAL AUTHENTICATE complete: cla={cla:02X}, response_len={}, sw={sw:04X}",
        plain.len()
    );
    if sw != 0x9000 {
        crate::log_warn!(
            "PACE GENERAL AUTHENTICATE failed: cla={cla:02X}, response_tag={response_tag:02X}, sw={sw:04X}"
        );
        return Err(());
    }
    let outer = tlv::parse_one(plain).ok_or(())?;
    if outer.tag != 0x7C {
        return Err(());
    }
    let mut off = 0;
    while off < outer.value.len() {
        let child = tlv::parse_one(&outer.value[off..]).ok_or(())?;
        if child.tag == response_tag {
            crate::log_trace!(
                "PACE GENERAL AUTHENTICATE response DO found: tag={response_tag:02X}, len={}",
                child.value.len()
            );
            return Ok(child.value.to_vec());
        }
        off += child.total_len;
    }
    crate::log_warn!("PACE GENERAL AUTHENTICATE response DO missing: tag={response_tag:02X}");
    Err(())
}

fn read_binary(card: &Card, offset: u16, le: u32) -> Result<Vec<u8>, ()> {
    crate::log_trace!("PACE READ BINARY begin: offset={offset}, le={le}");
    let apdu = apdu::encode(0, 0xB0, (offset >> 8) as u8, offset as u8, &[], Some(le))?;
    let rsp = transmit_raw(card, &apdu)?;
    let (plain, sw) = split_status(&rsp)?;
    crate::log_trace!(
        "PACE READ BINARY complete: offset={offset}, len={}, sw={sw:04X}",
        plain.len()
    );
    if sw == 0x9000 {
        Ok(plain.to_vec())
    } else {
        Err(())
    }
}

fn transmit_ok(card: &Card, apdu: &[u8]) -> Result<(), ()> {
    let rsp = transmit_raw(card, apdu)?;
    let (_, sw) = split_status(&rsp)?;
    crate::log_debug!("PACE command status: sw={sw:04X}");
    (sw == 0x9000).then_some(()).ok_or(())
}

fn transmit_raw(card: &Card, apdu: &[u8]) -> Result<Vec<u8>, ()> {
    let mut recv = [0u8; 8192];
    card.transmit(apdu, &mut recv)
        .map(|rsp| rsp.to_vec())
        .map_err(|_| ())
}

fn split_status(rsp: &[u8]) -> Result<(&[u8], u16), ()> {
    if rsp.len() < 2 {
        return Err(());
    }
    Ok((
        &rsp[..rsp.len() - 2],
        u16::from_be_bytes([rsp[rsp.len() - 2], rsp[rsp.len() - 1]]),
    ))
}

fn decrypt_nonce(can: &str, enc_nonce: &[u8]) -> Result<[u8; 32], ()> {
    if enc_nonce.len() != 32 {
        return Err(());
    }
    let key = kdf(can.as_bytes(), 3);
    let plain = aes256_cbc_decrypt(&key, &[0u8; 16], enc_nonce)?;
    plain.try_into().map_err(|_| ())
}

fn kdf(seed: &[u8], mode: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update([0, 0, 0, mode]);
    h.finalize().into()
}

fn im_prf(s: &[u8; 32], t: &[u8; 32]) -> Result<[u8; 32], ()> {
    const C0: [u8; 32] = [
        0xD4, 0x63, 0xD6, 0x52, 0x34, 0x12, 0x4E, 0xF7, 0x89, 0x70, 0x54, 0x98, 0x6D, 0xCA, 0x0A,
        0x17, 0x4E, 0x28, 0xDF, 0x75, 0x8C, 0xBA, 0xA0, 0x3F, 0x24, 0x06, 0x16, 0x41, 0x4D, 0x5A,
        0x16, 0x76,
    ];
    const C1: [u8; 32] = [
        0x54, 0xBD, 0x72, 0x55, 0xF0, 0xAA, 0xF8, 0x31, 0xBE, 0xC3, 0x42, 0x3F, 0xCF, 0x39, 0xD6,
        0x9B, 0x6C, 0xBF, 0x06, 0x66, 0x77, 0xD0, 0xFA, 0xAE, 0x5A, 0xAD, 0xD9, 0x9D, 0xF8, 0xE5,
        0x35, 0x17,
    ];
    let key = aes256_cbc_encrypt(t, &[0u8; 16], s)?;
    let key: [u8; 32] = key.try_into().map_err(|_| ())?;
    let next_key = aes256_cbc_encrypt(&key, &[0u8; 16], &C0)?;
    let x = aes256_cbc_encrypt(&key, &[0u8; 16], &C1)?;
    drop(next_key);
    let p = BigUint::from_bytes_be(BP256_P);
    let v = BigUint::from_bytes_be(&x) % p;
    Ok(fixed_32(&v))
}

fn icart_point_encode(t: &[u8; 32]) -> Result<ProjectivePoint, ()> {
    let p = BigUint::from_bytes_be(BP256_P);
    let a = BigUint::from_bytes_be(BP256_A);
    let b = BigUint::from_bytes_be(BP256_B);
    let one = BigUint::one();
    let t = BigUint::from_bytes_be(t) % &p;

    let alpha = mod_sub(&mod_sub(&one, &mod_mul(&t, &t, &p), &p), &one, &p);
    let alpha_sq = mod_mul(&alpha, &alpha, &p);
    let alpha_sum = mod_add(&alpha, &alpha_sq, &p);
    let tmp = mod_add(&one, &alpha_sum, &p);
    let den = mod_mul(&a, &alpha_sum, &p);
    let inv_den = mod_inv(&den, &p)?;
    let x2 = mod_mul(
        &mod_sub(&mod_sub(&one, &mod_mul(&b, &tmp, &p), &p), &one, &p),
        &inv_den,
        &p,
    );
    let x3 = mod_mul(&alpha, &x2, &p);
    let h2 = curve_rhs(&x2, &a, &b, &p);
    let u = mod_mul(&mod_mul(&mod_mul(&t, &t, &p), &t, &p), &h2, &p);
    let exp = &p - BigUint::one() - ((&p + BigUint::one()) >> 2usize);
    let aa = mod_pow(&h2, &exp, &p);
    let check = mod_mul(&mod_mul(&aa, &aa, &p), &h2, &p);
    let (x, y) = if check == one {
        (x2, mod_mul(&aa, &h2, &p))
    } else {
        (x3, mod_mul(&aa, &u, &p))
    };
    decode_point(&sec1(&fixed_32(&x), &fixed_32(&y)))
}

fn curve_rhs(x: &BigUint, a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    mod_add(
        &mod_add(&mod_mul(&mod_mul(x, x, p), x, p), &mod_mul(a, x, p), p),
        b,
        p,
    )
}

fn auth_token(k_mac: &[u8; 32], pubkey: &[u8]) -> Result<[u8; 8], ()> {
    let mut data = Vec::new();
    data.extend_from_slice(&[0x06, 0x0A]);
    data.extend_from_slice(PACE_ECDH_IM_AES_CBC_CMAC_256_OID);
    append_tlv(&mut data, 0x81, BP256_P)?;
    append_tlv(&mut data, 0x82, BP256_A)?;
    append_tlv(&mut data, 0x83, BP256_B)?;
    append_tlv(&mut data, 0x84, BP256_G)?;
    append_tlv(&mut data, 0x85, BP256_ORDER)?;
    append_tlv(&mut data, 0x86, pubkey)?;
    append_tlv(&mut data, 0x87, BP256_COFACTOR)?;
    let mut outer = Vec::new();
    outer.extend_from_slice(&[0x7F, 0x49]);
    append_ber_len(&mut outer, data.len())?;
    outer.extend_from_slice(&data);
    aes_cmac_trunc8(k_mac, &outer)
}

fn decode_point(sec1: &[u8]) -> Result<ProjectivePoint, ()> {
    let encoded = Sec1Point::from_bytes(sec1).map_err(|_| ())?;
    let affine = AffinePoint::from_sec1_point(&encoded)
        .into_option()
        .ok_or(())?;
    Ok(ProjectivePoint::from(affine))
}

fn encode_point(point: &AffinePoint) -> Vec<u8> {
    point.to_sec1_point(false).as_bytes().to_vec()
}

fn affine_x(point: &AffinePoint) -> Result<[u8; 32], ()> {
    let encoded = point.to_sec1_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() == 65 && bytes[0] == 0x04 {
        bytes[1..33].try_into().map_err(|_| ())
    } else {
        Err(())
    }
}

fn random_scalar() -> Result<Scalar, ()> {
    loop {
        let bytes = random_32()?;
        let repr = FieldBytes::from(bytes);
        if let Some(scalar) = Scalar::from_repr(repr).into_option() {
            if !bool::from(scalar.is_zero()) {
                return Ok(scalar);
            }
        }
    }
}

fn random_32() -> Result<[u8; 32], ()> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|_| ())?;
    Ok(out)
}

fn aes256_ecb_encrypt_block(key: &[u8; 32], block: [u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new(&Array::from(*key));
    let mut out = Array::from(block);
    cipher.encrypt_block(&mut out);
    out.into()
}

fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, ()> {
    if input.len() % 16 != 0 {
        return Err(());
    }
    let cipher = Aes256::new(&Array::from(*key));
    let mut prev = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        let mut block = Array::from(block);
        cipher.encrypt_block(&mut block);
        prev.copy_from_slice(&block);
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, ()> {
    if input.is_empty() || input.len() % 16 != 0 {
        return Err(());
    }
    let cipher = Aes256::new(&Array::from(*key));
    let mut prev = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let encrypted = block;
        let mut block = Array::from(block);
        cipher.decrypt_block(&mut block);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        out.extend_from_slice(&block);
        prev = encrypted;
    }
    Ok(out)
}

fn aes_cmac_trunc8(key: &[u8; 32], input: &[u8]) -> Result<[u8; 8], ()> {
    let mut mac = <Cmac<Aes256> as KeyInit>::new_from_slice(key).map_err(|_| ())?;
    mac.update(input);
    let full = mac.finalize().into_bytes();
    full[..8].try_into().map_err(|_| ())
}

fn append_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<(), ()> {
    out.push(tag);
    append_ber_len(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn append_ber_len(out: &mut Vec<u8>, len: usize) -> Result<(), ()> {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len <= 0xFFFF {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        return Err(());
    }
    Ok(())
}

fn append_ssc(out: &mut Vec<u8>, ssc: u64) {
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&ssc.to_be_bytes());
}

fn append_iso_pad(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0);
    }
}

fn iso_padded(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    append_iso_pad(&mut out, data);
    out
}

fn unpad_iso(padded: &[u8]) -> Option<&[u8]> {
    let mut end = padded.len();
    while end > 0 && padded[end - 1] == 0 {
        end -= 1;
    }
    (end > 0 && padded[end - 1] == 0x80).then_some(&padded[..end - 1])
}

fn mod_add(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    (a + b) % m
}

fn mod_sub(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    if a >= b { (a - b) % m } else { (a + m - b) % m }
}

fn mod_mul(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    (a * b) % m
}

fn mod_pow(a: &BigUint, e: &BigUint, m: &BigUint) -> BigUint {
    a.modpow(e, m)
}

fn mod_inv(a: &BigUint, m: &BigUint) -> Result<BigUint, ()> {
    if a.is_zero() {
        Err(())
    } else {
        Ok(a.modpow(&(m - BigUint::from(2u8)), m))
    }
}

fn fixed_32(v: &BigUint) -> [u8; 32] {
    let bytes = v.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    out
}

const fn sec1(x: &[u8; 32], y: &[u8; 32]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    let mut i = 0;
    while i < 32 {
        out[1 + i] = x[i];
        out[33 + i] = y[i];
        i += 1;
    }
    out
}

const fn hex_bytes(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_kdf_matches_sha256_counter_encoding() {
        let mut h = Sha256::new();
        h.update(b"123456");
        h.update([0, 0, 0, 3]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(kdf(b"123456", 3), expected);
    }

    #[test]
    fn secure_messaging_wrap_uses_protected_cla_and_mac() {
        let mut sm = SecureMessaging::new([1; 32], [2; 32]);
        let apdu = sm.wrap_apdu(0, 0xA4, 0x04, 0, b"abc", Some(256)).unwrap();
        assert_eq!(&apdu[..4], &[0x0C, 0xA4, 0x04, 0x00]);
        assert!(apdu.windows(1).any(|b| b == [0x87]));
        assert!(apdu.windows(1).any(|b| b == [0x97]));
        assert!(apdu.windows(1).any(|b| b == [0x8E]));
    }

    #[test]
    fn parses_supported_card_access_pace_info() {
        let card_access = [
            0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04,
            0x04, 0x04, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D,
        ];
        let info = parse_card_access(&card_access).unwrap();
        assert_eq!(info.oid_der, PACE_ECDH_IM_AES_CBC_CMAC_256_OID);
        assert_eq!(info.parameter_id, 0x0D);
    }

    #[test]
    fn iso_unpad_roundtrips() {
        let padded = iso_padded(b"hello");
        assert_eq!(unpad_iso(&padded), Some(&b"hello"[..]));
    }
}
