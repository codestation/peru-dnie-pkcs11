use crate::{apdu, config, pace, tlv};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};
use x509_cert::{
    Certificate,
    der::{Decode, DecodePem, Encode},
};
use zeroize::Zeroize;

/// Maximum number of issuer certificates exposed as PKCS#11 certificate
/// objects after signing has loaded the chain.
pub const MAX_CHAIN_CERTS: usize = 4;

const APPLET_IDA_IAS_ECC: &[u8] = &[
    0xA0, 0x00, 0x00, 0x00, 0x77, 0x03, 0x0C, 0x60, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x05, 0x00,
];
const LEGACY_PKI_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x00, 0x70, 0x0A, 0x10, 0x00, 0xF1, 0x00, 0x00, 0x01, 0x00,
];
const ADF_PKI: &[u8] = &[
    0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x50, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63,
];
const SIGN_CERT_ID: &[u8] = &[0xCE, 0x82];
const V2_SIGN_CERT_ID: &[u8] = &[0x00, 0x1D];
const DNI_VALUE: &[u8] = &[0xD0, 0x03];
const LEGACY_MF: &[u8] = &[0x3F, 0x00];
const LEGACY_DF_PKI: &[u8] = &[0x50, 0x15];
const LEGACY_SIGN_CERT_ID: &[u8] = &[0x34, 0x02];
const SIGN_MSE: &[u8] = &[0x84, 0x01, 0x82, 0x80, 0x01, 0x42];
const V2_SIGN_MSE: &[u8] = &[0x80, 0x01, 0x8A, 0x84, 0x01, 0x81];
const LEGACY_SIGN_MSE: &[u8] = &[0x80, 0x01, 0x11, 0x83, 0x01, 0x02];
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

/// DNIe generation detected by ATR or application selection probes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Profile {
    Unknown,
    V3,
    V2,
    V1,
}

/// PKCS#11-relevant certificate data extracted from an X.509 certificate.
#[derive(Clone, Default)]
pub struct CertObject {
    pub der: Vec<u8>,
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    pub serial: Vec<u8>,
}

/// Connected DNIe card state.
///
/// The leaf signing certificate is loaded lazily. Intermediate certificates are
/// loaded only immediately before signing, either from `PERU_DNIE_CERT_CHAIN`
/// or from AIA discovery/cache policy.
pub struct DnieCard {
    pcsc: Option<Card>,
    pub present: bool,
    pub profile: Profile,
    pub atr: Vec<u8>,
    pub pin_verified: bool,
    cached_pin: Vec<u8>,
    pub certificate: CertObject,
    pub chain: Vec<CertObject>,
    pub public_modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub public_modulus_bits: usize,
    pub token_serial: Option<String>,
    secure_messaging: Option<pace::SecureMessaging>,
}

impl Default for DnieCard {
    fn default() -> Self {
        Self {
            pcsc: None,
            present: false,
            profile: Profile::Unknown,
            atr: Vec::new(),
            pin_verified: false,
            cached_pin: Vec::new(),
            certificate: CertObject::default(),
            chain: Vec::new(),
            public_modulus: Vec::new(),
            public_exponent: Vec::new(),
            public_modulus_bits: 0,
            token_serial: None,
            secure_messaging: None,
        }
    }
}

impl Drop for DnieCard {
    fn drop(&mut self) {
        self.logout();
    }
}

impl DnieCard {
    pub fn open() -> Result<Self, i32> {
        let cfg = config::load();
        crate::log_info!(
            "opening DNIe card: configured_chain_paths={}",
            cfg.cert_chain.len()
        );

        let (pcsc, profile, atr) = find_peru_dnie()?;
        let mut card = Self::default();
        card.pcsc = Some(pcsc);
        card.present = true;
        card.profile = profile;
        card.atr = atr;
        crate::log_info!("DNIe card connected");
        if let Some(can) = cfg.can.as_deref() {
            crate::log_info!("CAN configured; starting PACE");
            let sm = pace::establish(card.pcsc.as_ref().ok_or(-1)?, can).map_err(|_| {
                crate::log_warn!("PACE failed; refusing plaintext fallback");
                -1
            })?;
            card.secure_messaging = Some(sm);
            crate::log_info!("PACE secure messaging established");
        } else {
            crate::log_debug!("CAN not configured; using plaintext card communication");
        }
        Ok(card)
    }

    pub fn ensure_signing_certificate(&mut self) -> Result<(), i32> {
        if !self.certificate.der.is_empty() {
            return Ok(());
        }
        crate::log_info!(
            "loading DNIe signing certificate on demand: profile={}",
            self.profile_name()
        );
        match self.profile {
            Profile::V1 => self.load_v1_certificate()?,
            Profile::V2 => self.load_v2_certificate()?,
            Profile::V3 => self.load_v3_certificate()?,
            Profile::Unknown => return Err(-1),
        }
        crate::log_info!(
            "DNIe signing certificate loaded: bytes={}",
            self.certificate.der.len()
        );
        Ok(())
    }

    pub fn ensure_token_serial(&mut self) -> Result<&str, i32> {
        if self.token_serial.is_none() {
            let serial = self
                .read_dni_serial()
                .unwrap_or_else(|_| atr_serial_fallback(&self.atr));
            self.token_serial = Some(serial);
        }
        Ok(self.token_serial.as_deref().unwrap_or("unknown"))
    }

    pub fn close(&mut self) {
        self.logout();
        self.pcsc.take();
        self.present = false;
    }

    pub fn login(&mut self, pin: &[u8]) -> Result<(), i32> {
        if !self.present {
            return Err(-1);
        }
        self.select_signing_context().map_err(|_| -3)?;
        let pin_data = self.pin_data(pin).ok_or(-3)?;
        let pin_ref = match self.profile {
            Profile::V2 => 0x81,
            Profile::V1 => 0x04,
            _ => 0x03,
        };
        crate::log_info!(
            "PIN VERIFY begin: profile={}, pin_ref={pin_ref:02X}",
            self.profile_name()
        );
        let (_, sw) = self.transmit(0x00, 0x20, 0x00, pin_ref, &pin_data, Some(0))?;
        if sw == 0x9000 {
            crate::log_info!("PIN VERIFY succeeded");
            self.pin_verified = true;
            self.cached_pin = pin_data;
            Ok(())
        } else if sw & 0xfff0 == 0x63c0 {
            crate::log_warn!("PIN VERIFY failed with retries status: sw={sw:04X}");
            Err(-4)
        } else {
            crate::log_warn!("PIN VERIFY failed: sw={sw:04X}");
            Err(-3)
        }
    }

    pub fn logout(&mut self) {
        self.pin_verified = false;
        self.cached_pin.zeroize();
        self.cached_pin.clear();
    }

    pub fn sign(
        &mut self,
        mechanism: u64,
        data: &[u8],
        sig: Option<&mut [u8]>,
    ) -> Result<usize, i32> {
        if !self.present {
            return Err(-1);
        }
        if !self.pin_verified {
            return Err(-2);
        }
        crate::log_info!(
            "card sign begin: profile={}, mechanism=0x{:X}, input_len={}, chain_count={}",
            self.profile_name(),
            mechanism,
            data.len(),
            self.chain.len()
        );
        self.ensure_signing_certificate()?;
        self.ensure_chain_certs()?;
        let out_len = self.public_modulus.len().max(256);
        let Some(sig) = sig else {
            crate::log_debug!("signature length requested: bytes={out_len}");
            return Ok(out_len);
        };
        let digest = digest_for_sign(mechanism, data).ok_or(-3)?;
        crate::log_debug!(
            "card sign digest prepared: digest_len={}, modulus_len={}",
            digest.len(),
            self.public_modulus.len()
        );
        let (mse, pso_data_storage);
        let pso_data: &[u8] = match self.profile {
            Profile::V2 => {
                mse = V2_SIGN_MSE;
                pso_data_storage = digest_info(&digest);
                &pso_data_storage
            }
            Profile::V1 => {
                mse = LEGACY_SIGN_MSE;
                pso_data_storage = digest_info(&digest);
                &pso_data_storage
            }
            _ => {
                mse = SIGN_MSE;
                &digest
            }
        };
        crate::log_debug!(
            "card sign PSO input prepared: pso_data_len={}",
            pso_data.len()
        );
        let (_, sw) = self.transmit(0x00, 0x22, 0x41, 0xB6, mse, None)?;
        if sw != 0x9000 {
            crate::log_warn!("MSE SET for signing failed: sw={sw:04X}");
            return Err(-3);
        }
        let (plain, sw) = self.transmit(0x00, 0x2A, 0x9E, 0x9A, pso_data, Some(0))?;
        if sw == 0x6982 {
            // Okular can trigger a post-context-change sign attempt that returns
            // 6982 unless the PIN is re-verified first.
            self.refresh_pin()?;
            let (_, sw) = self.transmit(0x00, 0x22, 0x41, 0xB6, mse, None)?;
            if sw != 0x9000 {
                crate::log_warn!("MSE SET after PIN refresh failed: sw={sw:04X}");
                return Err(-2);
            }
            let (plain, sw) = self.transmit(0x00, 0x2A, 0x9E, 0x9A, pso_data, Some(0))?;
            if sw != 0x9000 {
                self.pin_verified = false;
                crate::log_warn!("PSO SIGN after PIN refresh failed: sw={sw:04X}");
                return Err(-2);
            }
            crate::log_info!(
                "card sign complete after PIN refresh: signature_len={}",
                plain.len()
            );
            return copy_signature(&plain, sig);
        }
        if sw != 0x9000 {
            crate::log_warn!("PSO SIGN failed: sw={sw:04X}");
            return Err(-3);
        }
        crate::log_info!("card sign complete: signature_len={}", plain.len());
        copy_signature(&plain, sig)
    }

    pub(crate) fn profile_name(&self) -> &'static str {
        match self.profile {
            Profile::Unknown => "unknown",
            Profile::V3 => "v3",
            Profile::V2 => "v2",
            Profile::V1 => "v1",
        }
    }

    fn select_signing_context(&mut self) -> Result<(), i32> {
        match self.profile {
            Profile::V3 => {
                self.select_v3_ias_ecc_applet()?;
                self.select_adf_pki()
            }
            Profile::V2 => self.select_adf_pki(),
            Profile::V1 => {
                let (_, sw) = self.transmit(0x00, 0xA4, 0x04, 0x00, LEGACY_PKI_AID, Some(0))?;
                if sw == 0x9000 { Ok(()) } else { Err(-1) }
            }
            Profile::Unknown => Err(-1),
        }
    }

    fn refresh_pin(&mut self) -> Result<(), i32> {
        if self.cached_pin.is_empty() {
            return Err(-2);
        }
        let pin_ref = match self.profile {
            Profile::V2 => 0x81,
            Profile::V1 => 0x04,
            _ => 0x03,
        };
        crate::log_info!(
            "PIN VERIFY refresh begin: profile={}, pin_ref={pin_ref:02X}",
            self.profile_name()
        );
        let cached_pin = std::mem::take(&mut self.cached_pin);
        let refresh_result = self.transmit(0x00, 0x20, 0x00, pin_ref, &cached_pin, Some(0));
        self.cached_pin = cached_pin;
        let (_, sw) = match refresh_result {
            Ok(result) => result,
            Err(e) => {
                crate::log_warn!("PIN VERIFY refresh transmit failed: error={e}");
                self.pin_verified = false;
                return Err(-2);
            }
        };
        if sw == 0x9000 {
            crate::log_info!("PIN VERIFY refresh succeeded");
            self.pin_verified = true;
            Ok(())
        } else if sw & 0xfff0 == 0x63c0 {
            crate::log_warn!("PIN VERIFY refresh failed with retries status: sw={sw:04X}");
            self.pin_verified = false;
            Err(-2)
        } else {
            crate::log_warn!("PIN VERIFY refresh failed: sw={sw:04X}");
            self.pin_verified = false;
            Err(-2)
        }
    }

    fn pin_data(&self, pin: &[u8]) -> Option<Vec<u8>> {
        if pin.len() < 4 || pin.len() > 8 {
            return None;
        }
        match self.profile {
            Profile::V3 => {
                let mut out = vec![0xff; 12];
                out[..pin.len()].copy_from_slice(pin);
                Some(out)
            }
            Profile::V2 => Some(pin.to_vec()),
            Profile::V1 => {
                let mut out = vec![0xff; 8];
                out[..pin.len()].copy_from_slice(pin);
                Some(out)
            }
            Profile::Unknown => None,
        }
    }

    fn load_v3_certificate(&mut self) -> Result<(), i32> {
        crate::log_debug!("loading v3 signing certificate");
        self.select_v3_ias_ecc_applet()?;
        self.select_adf_pki()?;
        self.select_file(SIGN_CERT_ID, 0x02, 0x0c, "v3 signing certificate")?;
        let cert = self.read_binary_chunks(255, false)?;
        self.store_sign_certificate(&cert)
    }

    fn load_v2_certificate(&mut self) -> Result<(), i32> {
        self.select_adf_pki()?;
        let (_, sw) = self.transmit(0x00, 0xA4, 0x02, 0x04, V2_SIGN_CERT_ID, Some(0))?;
        if sw != 0x9000 {
            return Err(-1);
        }
        let mut cert = Vec::new();
        let mut offset = 0usize;
        loop {
            let offset_do = [0x54, 0x02, (offset >> 8) as u8, offset as u8];
            let (plain, sw) = self.transmit(0x00, 0xB1, 0x00, 0x00, &offset_do, Some(255))?;
            if sw == 0x6b00 {
                break;
            }
            if sw != 0x9000 && sw != 0x6282 {
                return Err(-1);
            }
            if plain.len() < 4 {
                return Err(-1);
            }
            cert.extend_from_slice(&plain[3..plain.len() - 1]);
            offset += plain.len() - 4;
            if sw == 0x6282 || plain.len() == 4 {
                break;
            }
        }
        self.profile = Profile::V2;
        self.store_sign_certificate(&cert)
    }

    fn load_v1_certificate(&mut self) -> Result<(), i32> {
        let (_, sw) = self.transmit(0x00, 0xA4, 0x04, 0x00, LEGACY_PKI_AID, Some(0))?;
        if sw != 0x9000 {
            return Err(-1);
        }
        self.select_file(LEGACY_MF, 0x00, 0x00, "v1 MF")?;
        self.select_file(LEGACY_DF_PKI, 0x00, 0x00, "v1 DF PKI")?;
        self.select_file(LEGACY_SIGN_CERT_ID, 0x00, 0x00, "v1 signing certificate")?;
        let cert = self.read_binary_chunks(255, true)?;
        self.profile = Profile::V1;
        self.store_sign_certificate(&cert)
    }

    fn read_dni_serial(&mut self) -> Result<String, i32> {
        crate::log_debug!("reading token serial from DNI file");
        let (_, sw) = self.transmit(0x00, 0xA4, 0x02, 0x04, DNI_VALUE, Some(0))?;
        if sw != 0x9000 {
            crate::log_warn!("DNI file SELECT failed: sw={sw:04X}");
            return Err(-1);
        }
        let bytes = self.read_binary_chunks(255, true)?;
        let serial = dni_serial_from_file(&bytes).unwrap_or_else(|| atr_serial_fallback(&self.atr));
        crate::log_info!("DNI serial loaded from file");
        Ok(serial)
    }

    fn select_v3_ias_ecc_applet(&mut self) -> Result<(), i32> {
        let (_, sw) = self.transmit(0x00, 0xA4, 0x04, 0x0C, APPLET_IDA_IAS_ECC, Some(0))?;
        if sw == 0x9000 {
            Ok(())
        } else {
            crate::log_warn!("Peru certificate applet SELECT failed: sw={sw:04X}");
            Err(-1)
        }
    }

    fn select_adf_pki(&mut self) -> Result<(), i32> {
        let (_, sw) = self.transmit(0x00, 0xA4, 0x04, 0x04, ADF_PKI, Some(0))?;
        if sw == 0x9000 {
            Ok(())
        } else {
            crate::log_warn!("ADF PKI SELECT failed: sw={sw:04X}");
            Err(-1)
        }
    }

    fn select_file(&mut self, fid: &[u8], p1: u8, p2: u8, label: &str) -> Result<(), i32> {
        let (_, sw) = self.transmit(0x00, 0xA4, p1, p2, fid, Some(0))?;
        if sw == 0x9000 {
            Ok(())
        } else {
            crate::log_warn!("{label} SELECT failed: sw={sw:04X}");
            Err(-1)
        }
    }

    fn read_binary_chunks(&mut self, le: u32, break_on_short: bool) -> Result<Vec<u8>, i32> {
        let mut cert = Vec::new();
        let mut expected_total = None;
        let mut offset = 0usize;
        loop {
            let (plain, sw) =
                self.transmit(0x00, 0xB0, (offset >> 8) as u8, offset as u8, &[], Some(le))?;
            if sw != 0x9000 && sw != 0x6282 {
                crate::log_warn!("READ BINARY failed: offset={offset}, sw={sw:04X}");
                return Err(-1);
            }
            if plain.is_empty() {
                crate::log_warn!(
                    "READ BINARY returned empty response: offset={offset}, sw={sw:04X}"
                );
                return Err(-1);
            }
            cert.extend_from_slice(&plain);
            if expected_total.is_none() && cert.len() >= 4 {
                expected_total = tlv::total_from_prefix(&cert);
            }
            offset += plain.len();
            if sw == 0x6282
                || expected_total.is_some_and(|n| cert.len() >= n)
                || (break_on_short && plain.len() < le as usize)
            {
                break;
            }
            if offset > 0x7fff {
                return Err(-1);
            }
        }
        Ok(cert)
    }

    fn store_sign_certificate(&mut self, cert: &[u8]) -> Result<(), i32> {
        let Some(tlv) = tlv::parse_one(cert) else {
            return Err(-1);
        };
        if tlv.tag != 0x30 || tlv.value.is_empty() {
            return Err(-1);
        }
        let der = &cert[..tlv.total_len];
        let obj = parse_cert_object(der).map_err(|_| -1)?;
        let (modulus, exponent, modulus_bits) = parse_rsa_public_key_from_cert(der)?;
        self.public_modulus = modulus;
        self.public_exponent = exponent;
        self.public_modulus_bits = modulus_bits;
        self.certificate = obj;
        Ok(())
    }

    pub(crate) fn ensure_chain_certs(&mut self) -> Result<(), i32> {
        if !self.chain.is_empty() {
            crate::log_debug!(
                "certificate chain already available: count={}",
                self.chain.len()
            );
            return Ok(());
        }
        let cfg = config::load();
        crate::log_info!(
            "certificate chain missing; loading before signing: configured_chain_paths={}",
            cfg.cert_chain.len()
        );
        self.load_chain_certs_nonfatal(cfg.cert_chain);
        if self.chain.is_empty() {
            crate::log_error!("certificate chain unavailable; signing cannot continue");
            return Err(-6);
        }
        crate::log_info!("certificate chain available: count={}", self.chain.len());
        Ok(())
    }

    fn load_chain_certs_nonfatal(&mut self, configured: Vec<PathBuf>) {
        if configured.is_empty() {
            crate::log_debug!("no configured certificate chain; trying AIA");
            self.load_aia_chain_certs();
        } else {
            crate::log_info!(
                "loading configured certificate chain: paths={}",
                configured.len()
            );
            self.load_configured_chain_certs(configured);
        }
    }

    fn load_configured_chain_certs(&mut self, configured: Vec<PathBuf>) {
        for path in configured {
            crate::log_debug!(
                "loading configured chain certificate: path={}",
                path.display()
            );
            match self.load_chain_cert(&path) {
                Ok(()) => crate::log_info!(
                    "configured chain certificate loaded: path={}, total_count={}",
                    path.display(),
                    self.chain.len()
                ),
                Err(_) => crate::log_warn!(
                    "configured chain certificate could not be loaded: path={}",
                    path.display()
                ),
            }
            if self.chain.len() >= MAX_CHAIN_CERTS {
                break;
            }
        }
    }

    fn load_chain_cert(&mut self, path: &Path) -> Result<(), i32> {
        let bytes = fs::read(path).map_err(|_| -1)?;
        self.load_chain_cert_bytes(&bytes)
    }

    fn load_aia_chain_certs(&mut self) {
        if self.certificate.der.is_empty() || self.chain.len() >= MAX_CHAIN_CERTS {
            return;
        }
        let urls = aia_http_urls(&self.certificate.der);
        crate::log_info!("AIA issuer URLs discovered: count={}", urls.len());
        for url in urls {
            if self.chain.len() >= MAX_CHAIN_CERTS {
                break;
            }
            let before = self.chain.len();
            let _ = self.load_aia_url(&url);
            if self.chain.len() > before {
                crate::log_info!("AIA issuer resolved; skipping remaining issuer URLs");
                break;
            }
        }
    }

    fn load_aia_url(&mut self, url: &str) -> Result<(), i32> {
        crate::log_info!("loading AIA issuer certificate: url={url}");
        if aia_cache_enabled() {
            let cache_path = aia_cache_path(url).ok_or(-1)?;
            crate::log_debug!("AIA cache path: {}", cache_path.display());
            let before = self.chain.len();
            if self.load_chain_cert(&cache_path).is_ok() && self.chain.len() > before {
                crate::log_info!("AIA issuer certificate loaded from cache");
                return Ok(());
            }
            crate::log_info!("AIA cache miss; downloading issuer certificate");
            http_get_to_file(url, &cache_path)?;
            let before = self.chain.len();
            if self.load_chain_cert(&cache_path).is_ok() && self.chain.len() > before {
                crate::log_info!("AIA issuer certificate downloaded and cached");
                return Ok(());
            }
            let _ = fs::remove_file(cache_path);
            crate::log_warn!("downloaded AIA issuer certificate was not usable");
            return Err(-1);
        }
        crate::log_info!("AIA cache disabled; downloading issuer certificate without caching");
        let bytes = http_get(url)?;
        let before = self.chain.len();
        if self.load_chain_cert_bytes(&bytes).is_ok() && self.chain.len() > before {
            crate::log_info!("AIA issuer certificate loaded from download");
            return Ok(());
        }
        crate::log_warn!("downloaded AIA issuer certificate was not usable");
        Err(-1)
    }

    fn load_chain_cert_bytes(&mut self, bytes: &[u8]) -> Result<(), i32> {
        if self.chain.len() >= MAX_CHAIN_CERTS {
            return Err(-1);
        }
        let certs = parse_cert_der_or_pem_many(bytes)?;
        for der in certs {
            if self.chain.len() >= MAX_CHAIN_CERTS {
                break;
            }
            if der == self.certificate.der || self.chain.iter().any(|c| c.der == der) {
                continue;
            }
            self.chain.push(parse_cert_object(&der).map_err(|_| -1)?);
        }
        Ok(())
    }

    fn transmit(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Option<u32>,
    ) -> Result<(Vec<u8>, u16), i32> {
        let card = self.pcsc.as_ref().ok_or(-1)?;
        let protected = self.secure_messaging.is_some();
        crate::log_debug!(
            "transmit begin: protected={}, cla={cla:02X}, ins={ins:02X}, p1={p1:02X}, p2={p2:02X}, data_len={}, le={}",
            protected,
            data.len(),
            le.map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_owned())
        );
        let apdu = if let Some(sm) = self.secure_messaging.as_mut() {
            sm.wrap_apdu(cla, ins, p1, p2, data, le).map_err(|_| -1)?
        } else {
            apdu::encode(cla, ins, p1, p2, data, le).map_err(|_| -1)?
        };
        let mut recv = [0u8; 8192];
        let rsp = match card.transmit(&apdu, &mut recv) {
            Ok(rsp) => rsp,
            Err(_) => {
                crate::log_warn!("transmit PC/SC failed: ins={ins:02X}");
                return Err(-1);
            }
        };
        let (plain, sw) = if let Some(sm) = self.secure_messaging.as_mut() {
            sm.unwrap_response(rsp).map_err(|_| {
                crate::log_warn!("secure messaging response unwrap failed: ins={ins:02X}");
                -1
            })?
        } else {
            if rsp.len() < 2 {
                crate::log_warn!("transmit failed: response shorter than status word");
                return Err(-1);
            }
            let sw = u16::from_be_bytes([rsp[rsp.len() - 2], rsp[rsp.len() - 1]]);
            (rsp[..rsp.len() - 2].to_vec(), sw)
        };
        crate::log_debug!(
            "transmit complete: protected={}, ins={ins:02X}, plain_len={}, sw={sw:04X}",
            protected,
            plain.len()
        );
        Ok((plain, sw))
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);

    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{:02x}", b));
    }

    out
}

fn find_peru_dnie() -> Result<(Card, Profile, Vec<u8>), i32> {
    crate::log_debug!("establishing PC/SC context");
    let ctx = Context::establish(Scope::System).map_err(|_| -1)?;
    let mut readers_buf = [0; 2048];
    let readers = ctx.list_readers(&mut readers_buf).map_err(|_| -1)?;
    crate::log_debug!("PC/SC readers listed");
    for reader in readers {
        crate::log_debug!("checking reader: {}", reader.to_string_lossy());
        let Ok(card) = ctx.connect(reader, ShareMode::Shared, Protocols::ANY) else {
            crate::log_warn!("could not connect to reader: {}", reader.to_string_lossy());
            continue;
        };
        let mut names = [0u8; 512];
        let mut atr = [0u8; 64];
        let Ok(status) = card.status2(&mut names, &mut atr) else {
            crate::log_warn!("could not read card status");
            continue;
        };
        let atr = status.atr().to_vec();
        crate::log_debug!("card ATR read: {}", to_hex(&atr));

        if is_dnie_peru1(&atr, &card) {
            crate::log_info!("Peru DNIe card detected: v1");
            return Ok((card, Profile::V1, atr));
        }
        if is_dnie_peru2(&atr) {
            crate::log_info!("Peru DNIe card detected: v2");
            return Ok((card, Profile::V2, atr));
        }
        if is_dnie_peru3(&card) {
            crate::log_info!("Peru DNIe card detected: v3");
            return Ok((card, Profile::V3, atr));
        }
        crate::log_debug!("card did not match Peru DNIe probes");
    }
    crate::log_warn!("no Peru DNIe card found");
    Err(-1)
}

fn is_dnie_peru3(card: &Card) -> bool {
    select_aid(card, APPLET_IDA_IAS_ECC)
}

fn is_dnie_peru1(atr: &[u8], card: &Card) -> bool {
    const ATR_DNIE_PERU: &[u8] = &[
        0x3B, 0xDD, 0x18, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x80, 0xF9, 0xA0, 0x00, 0x00, 0x00, 0x77,
        0x01, 0x00, 0x70, 0x0A, 0x90, 0x00, 0x8B,
    ];
    if atr != ATR_DNIE_PERU {
        crate::log_warn!("ATR does not match expected pattern (1)");
        return false;
    }
    crate::log_info!("Card ATR matches expected pattern (1)");
    if is_pki_app_present1(card) {
        crate::log_info!("PKI applet detected (1)");
        return true;
    }
    false
}

fn is_dnie_peru2(atr: &[u8]) -> bool {
    const ATR_DNIE_PERU_CONTACT: &[u8] = &[
        0x3B, 0xDC, 0x18, 0xFF, 0x81, 0x91, 0xFE, 0x1F, 0xC3, 0x80, 0x73, 0xC8, 0x21, 0x13, 0x66,
        0x05, 0x03, 0x63, 0x51, 0x00, 0x02, 0x50,
    ];
    const ATR_DNIE_PERU_CONTACTLESS: &[u8] = &[0x3B, 0x80, 0x80, 0x01, 0x01];
    if atr != ATR_DNIE_PERU_CONTACT && atr != ATR_DNIE_PERU_CONTACTLESS {
        crate::log_warn!("ATR does not match expected pattern (2)");
        return false;
    }
    crate::log_info!("Card ATR matches expected pattern (2)");
    true
}

fn is_pki_app_present1(card: &Card) -> bool {
    let Ok(apdu) = apdu::encode(0x00, 0xA4, 0x04, 0x00, LEGACY_PKI_AID, Some(0)) else {
        return false;
    };
    let mut recv = [0u8; 512];
    let Ok(rsp) = card.transmit(&apdu, &mut recv) else {
        return false;
    };
    if rsp.len() < 2 {
        return false;
    }
    let sw = u16::from_be_bytes([rsp[rsp.len() - 2], rsp[rsp.len() - 1]]);
    match sw {
        0x9000 => true,
        0x6A82 => {
            crate::log_warn!("PKI application is missing or unexpected (1)");
            false
        }
        _ => {
            crate::log_warn!("Unexpected response (1)");
            false
        }
    }
}

fn select_aid(card: &Card, aid: &[u8]) -> bool {
    let Ok(apdu) = apdu::encode(0x00, 0xA4, 0x04, 0x0C, aid, Some(0)) else {
        return false;
    };
    let mut recv = [0u8; 512];
    let Ok(rsp) = card.transmit(&apdu, &mut recv) else {
        return false;
    };
    if rsp.len() < 2 {
        return false;
    }
    let sw = u16::from_be_bytes([rsp[rsp.len() - 2], rsp[rsp.len() - 1]]);
    sw == 0x9000
}

fn dni_serial_from_file(bytes: &[u8]) -> Option<String> {
    let tlv = tlv::parse_one(bytes)?;
    let value = if tlv.tag == 0x5a { tlv.value } else { bytes };
    Some(
        value
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>(),
    )
}

fn atr_serial_fallback(atr: &[u8]) -> String {
    let serial = atr.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    if serial.is_empty() {
        "unknown".to_owned()
    } else {
        serial
    }
}

fn parse_cert_object(der: &[u8]) -> Result<CertObject, ()> {
    let cert = Certificate::from_der(der).map_err(|_| ())?;
    let tbs = cert.tbs_certificate();
    Ok(CertObject {
        der: der.to_vec(),
        subject: tbs.subject().to_der().map_err(|_| ())?,
        issuer: tbs.issuer().to_der().map_err(|_| ())?,
        serial: der_encode_positive_integer(tbs.serial_number().as_bytes()),
    })
}

fn parse_rsa_public_key_from_cert(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>, usize), i32> {
    let cert = Certificate::from_der(der).map_err(|_| -1)?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid.to_string() != RSA_ENCRYPTION_OID {
        return Err(-1);
    }
    let key_der = spki.subject_public_key.as_bytes().ok_or(-1)?;
    let seq = tlv::parse_one(key_der).ok_or(-1)?;
    if seq.tag != 0x30 || seq.total_len != key_der.len() {
        return Err(-1);
    }
    let modulus_tlv = tlv::parse_one(seq.value).ok_or(-1)?;
    if modulus_tlv.tag != 0x02 {
        return Err(-1);
    }
    let exponent_tlv = tlv::parse_one(&seq.value[modulus_tlv.total_len..]).ok_or(-1)?;
    if exponent_tlv.tag != 0x02 || modulus_tlv.total_len + exponent_tlv.total_len != seq.value.len()
    {
        return Err(-1);
    }
    let modulus = der_positive_integer_magnitude(modulus_tlv.value);
    let exponent = der_positive_integer_magnitude(exponent_tlv.value);
    if modulus.is_empty() || exponent.is_empty() {
        return Err(-1);
    }
    let modulus_bits = integer_bit_len(&modulus);
    Ok((modulus, exponent, modulus_bits))
}

fn der_positive_integer_magnitude(value: &[u8]) -> Vec<u8> {
    let mut value = value;
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    value.to_vec()
}

fn integer_bit_len(value: &[u8]) -> usize {
    let Some(first) = value.first() else {
        return 0;
    };
    let leading = first.leading_zeros() as usize;
    (value.len() - 1) * 8 + (8 - leading)
}

fn parse_cert_der_or_pem_many(bytes: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    if let Ok(cert) = Certificate::from_der(bytes) {
        return cert.to_der().map(|der| vec![der]).map_err(|_| -1);
    }

    let text = std::str::from_utf8(bytes).map_err(|_| -1)?;
    let mut out = Vec::new();
    let mut rest = text;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while let Some(begin) = rest.find(BEGIN) {
        let after_begin = &rest[begin..];
        let end = after_begin.find(END).ok_or(-1)?;
        let block_end = end + END.len();
        let block = &after_begin[..block_end];
        let cert = Certificate::from_pem(block.as_bytes()).map_err(|_| -1)?;
        out.push(cert.to_der().map_err(|_| -1)?);
        rest = &after_begin[block_end..];
    }
    if out.is_empty() {
        return Err(-1);
    }
    Ok(out)
}

fn der_encode_positive_integer(value: &[u8]) -> Vec<u8> {
    let mut content = if value.is_empty() {
        vec![0]
    } else {
        value.to_vec()
    };
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    let mut out = vec![0x02];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else if content.len() <= 0xff {
        out.extend_from_slice(&[0x81, content.len() as u8]);
    } else {
        out.extend_from_slice(&[0x82, (content.len() >> 8) as u8, content.len() as u8]);
    }
    out.extend_from_slice(&content);
    out
}

fn digest_for_sign(mechanism: u64, data: &[u8]) -> Option<Vec<u8>> {
    const CKM_RSA_PKCS: u64 = 0x00000001;
    const CKM_SHA256_RSA_PKCS: u64 = 0x00000040;
    if mechanism == CKM_SHA256_RSA_PKCS {
        return Some(Sha256::digest(data).to_vec());
    }
    if mechanism == CKM_RSA_PKCS && data.len() == 32 {
        return Some(data.to_vec());
    }
    if mechanism == CKM_RSA_PKCS
        && data.len() == SHA256_DIGEST_INFO_PREFIX.len() + 32
        && data.starts_with(SHA256_DIGEST_INFO_PREFIX)
    {
        return Some(data[SHA256_DIGEST_INFO_PREFIX.len()..].to_vec());
    }
    if mechanism == CKM_RSA_PKCS && !data.is_empty() {
        return Some(Sha256::digest(data).to_vec());
    }
    None
}

fn digest_info(digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + digest.len());
    out.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
    out.extend_from_slice(digest);
    out
}

fn copy_signature(src: &[u8], dst: &mut [u8]) -> Result<usize, i32> {
    if dst.len() < src.len() {
        return Err(-5);
    }
    dst[..src.len()].copy_from_slice(src);
    Ok(src.len())
}

fn aia_http_urls(cert_der: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut pos = 0usize;
    while let Some(idx) = find_bytes(&cert_der[pos..], b"http://") {
        let start = pos + idx;
        let Some(len) = asn1_uri_len(cert_der, start) else {
            pos = start + 1;
            continue;
        };
        let end = start + len;
        if end > start {
            let mut url = String::from_utf8_lossy(&cert_der[start..end]).into_owned();
            rewrite_reniec_aia_url(&mut url);
            if !urls.iter().any(|u| u == &url) {
                urls.push(url);
            }
        }
        pos = end.max(start + 1);
    }
    urls
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn asn1_uri_len(input: &[u8], value_start: usize) -> Option<usize> {
    if value_start < 2 {
        return None;
    }
    let tag = input[value_start - 2];
    let len = input[value_start - 1] as usize;
    if tag == 0x86 && len > 0 && value_start + len <= input.len() {
        return Some(len);
    }
    if value_start < 3 || input[value_start - 3] != 0x86 || input[value_start - 2] != 0x81 {
        return None;
    }
    let len = input[value_start - 1] as usize;
    (len > 0 && value_start + len <= input.len()).then_some(len)
}

fn rewrite_reniec_aia_url(url: &mut String) {
    let old = "www.reniec.gob.pe/crt/sha2";
    let new = "crl.reniec.gob.pe/crt/sha2";
    if url.contains(old) {
        *url = url.replace(old, new);
    }
}

fn aia_cache_path(url: &str) -> Option<PathBuf> {
    let base = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    let dir = base.join("peru-dnie-pkcs11");
    fs::create_dir_all(&dir).ok()?;
    let digest = Sha256::digest(url.as_bytes());
    let mut name = String::with_capacity(digest.len() * 2 + ".certs".len());
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut name, "{byte:02x}");
    }
    name.push_str(".certs");
    Some(dir.join(name))
}

fn aia_cache_enabled() -> bool {
    !env::var("PERU_DNIE_AIA_CACHE").is_ok_and(|v| v == "0")
}

fn http_get_to_file(url: &str, path_out: &Path) -> Result<(), i32> {
    let body = http_get(url)?;
    fs::write(path_out, body).map_err(|_| -1)
}

fn http_get(url: &str) -> Result<Vec<u8>, i32> {
    let (host, port, path) = parse_http_url(url)?;
    crate::log_debug!("connecting for HTTP download: host={host}, port={port}");
    let mut stream = connect_http(&host, &port)?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).map_err(|_| -1)?;
    crate::log_debug!("HTTP request sent: host={host}, path={path}");
    let mut rsp = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 4096];
    loop {
        if std::time::Instant::now() >= deadline {
            crate::log_warn!("HTTP download timed out: url={url}");
            return Err(-1);
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                rsp.extend_from_slice(&buf[..n]);
                if rsp.len() > 256 * 1024 {
                    return Err(-1);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                crate::log_warn!("HTTP read timed out: url={url}");
                return Err(-1);
            }
            Err(_) => return Err(-1),
        }
    }
    crate::log_debug!("HTTP response received: bytes={}", rsp.len());
    if !rsp.starts_with(b"HTTP/") {
        return Err(-1);
    }
    let status_ok = rsp
        .iter()
        .take(64)
        .position(|b| *b == b' ')
        .is_some_and(|i| rsp.get(i + 1..i + 5) == Some(b"200 "));
    if !status_ok {
        return Err(-1);
    }
    let Some(body_start) = rsp.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
        return Err(-1);
    };
    Ok(rsp[body_start..].to_vec())
}

fn parse_http_url(url: &str) -> Result<(String, String, String), i32> {
    let rest = url.strip_prefix("http://").ok_or(-1)?;
    let (host_port, path) = rest.split_once('/').ok_or(-1)?;
    if host_port.is_empty() {
        return Err(-1);
    }
    let (host, port) = host_port.split_once(':').unwrap_or((host_port, "80"));
    if host.is_empty() || port.is_empty() {
        return Err(-1);
    }
    Ok((host.to_owned(), port.to_owned(), format!("/{path}")))
}

fn connect_http(host: &str, port: &str) -> Result<TcpStream, i32> {
    let timeout = Duration::from_secs(5);
    let port = port.parse::<u16>().map_err(|_| -1)?;
    crate::log_debug!("resolving host: {host}");
    for addr in (host, port).to_socket_addrs().map_err(|_| -1)? {
        crate::log_debug!("connecting to address: {addr}");
        let Ok(stream) = TcpStream::connect_timeout(&addr, timeout) else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        return Ok(stream);
    }
    Err(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CKM_RSA_PKCS: u64 = 0x00000001;
    const CKM_SHA256_RSA_PKCS: u64 = 0x00000040;

    #[test]
    fn formats_pin_for_profiles_without_exposing_pin() {
        let mut card = DnieCard::default();
        card.profile = Profile::V3;
        assert_eq!(
            card.pin_data(b"1234"),
            Some(vec![
                b'1', b'2', b'3', b'4', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ])
        );

        card.profile = Profile::V1;
        assert_eq!(card.pin_data(b"12345678"), Some(b"12345678".to_vec()));

        card.profile = Profile::V2;
        assert_eq!(card.pin_data(b"1234"), Some(b"1234".to_vec()));
        assert_eq!(card.pin_data(b"123"), None);
        assert_eq!(card.pin_data(b"123456789"), None);
    }

    #[test]
    fn derives_digest_for_supported_mechanisms() {
        assert_eq!(digest_for_sign(CKM_RSA_PKCS, &[7; 32]), Some(vec![7; 32]));

        let digest_info = digest_info(&[9; 32]);
        assert_eq!(
            digest_for_sign(CKM_RSA_PKCS, &digest_info),
            Some(vec![9; 32])
        );

        let hashed = digest_for_sign(CKM_SHA256_RSA_PKCS, b"abc").unwrap();
        assert_eq!(hashed.len(), 32);

        assert_eq!(digest_for_sign(CKM_RSA_PKCS, &[]), None);
    }

    #[test]
    fn parses_and_rewrites_aia_http_urls() {
        let url = b"http://www.reniec.gob.pe/crt/sha2/a.cer";
        let mut der_fragment = vec![0x86, url.len() as u8];
        der_fragment.extend_from_slice(url);
        assert_eq!(
            aia_http_urls(&der_fragment),
            vec!["http://crl.reniec.gob.pe/crt/sha2/a.cer"]
        );
    }

    #[test]
    fn parses_plain_http_urls() {
        assert_eq!(
            parse_http_url("http://example.test:8080/path/file.cer"),
            Ok((
                "example.test".to_owned(),
                "8080".to_owned(),
                "/path/file.cer".to_owned()
            ))
        );
        assert_eq!(
            parse_http_url("http://example.test/file.cer"),
            Ok((
                "example.test".to_owned(),
                "80".to_owned(),
                "/file.cer".to_owned()
            ))
        );
        assert!(parse_http_url("https://example.test/file.cer").is_err());
        assert!(parse_http_url("http:///file.cer").is_err());
    }

    #[test]
    fn encodes_positive_der_integer() {
        assert_eq!(der_encode_positive_integer(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_encode_positive_integer(&[0x7F]), vec![0x02, 0x01, 0x7F]);
        assert_eq!(
            der_encode_positive_integer(&[0x80]),
            vec![0x02, 0x02, 0x00, 0x80]
        );
    }
}
