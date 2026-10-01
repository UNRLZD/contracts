//! Native signing helpers for tests (feature `testkit`; never in a contract build). Builds
//! MultiPayloads for every arm exactly as the clients do (packages/owner-payload), plus the
//! negative shapes the matrix needs (high-s twins, v = 27, flags without UV).
use super::*;
use ed25519_dalek::Signer as _;
use k256::ecdsa::SigningKey as K1Key;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::SigningKey as R1Key;
use sha2::{Digest, Sha256};

pub const RP_ID: &str = "signer.unrealized.trade";
pub const ORIGIN: &str = "https://signer.unrealized.trade";
/// WebAuthn flags UP | UV.
pub const FLAGS_UP_UV: u8 = 0x05;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn keccak(b: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    sha3::Keccak256::digest(b).into()
}

fn b58(b: &[u8]) -> String {
    near_sdk::bs58::encode(b).into_string()
}

/// A test key on one curve, derived from a label (`sha256("nt-owner-v16-test/<label>")`).
#[derive(Clone)]
pub enum Signer {
    Ed25519(ed25519_dalek::SigningKey),
    Secp256k1(K1Key),
    P256(R1Key),
}

impl Signer {
    fn seed(label: &str) -> [u8; 32] {
        sha256(format!("nt-owner-v16-test/{label}").as_bytes())
    }
    pub fn ed25519(label: &str) -> Self {
        Signer::Ed25519(ed25519_dalek::SigningKey::from_bytes(&Self::seed(label)))
    }
    pub fn secp256k1(label: &str) -> Self {
        Signer::Secp256k1(K1Key::from_slice(&Self::seed(label)).expect("k1 key"))
    }
    pub fn p256(label: &str) -> Self {
        Signer::P256(R1Key::from_slice(&Self::seed(label)).expect("p256 key"))
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Signer::Ed25519(k) => PublicKey::Ed25519(k.verifying_key().to_bytes()),
            Signer::Secp256k1(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                PublicKey::Secp256k1(p.as_bytes()[1..].try_into().expect("64"))
            }
            Signer::P256(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                PublicKey::P256(p.as_bytes()[1..].try_into().expect("64"))
            }
        }
    }

    /// The implicit owner id (computed natively: keccak / hex, independent of the host).
    pub fn owner_id(&self) -> String {
        match self.public_key() {
            PublicKey::Ed25519(k) => hex(&k),
            PublicKey::Secp256k1(k) => format!("0x{}", hex(&keccak(&k)[12..])),
            PublicKey::P256(k) => format!("0x{}", hex(&keccak(&[b"p256".as_slice(), &k].concat())[12..])),
        }
    }

    pub fn kind(&self) -> OwnerKind {
        self.public_key().kind()
    }

    /// The standard a client would use for this curve when none is forced: erc191 (k1),
    /// webauthn (P-256), raw_ed25519 (ed25519).
    pub fn default_standard(&self) -> Standard {
        match self {
            Signer::Ed25519(_) => Standard::RawEd25519,
            Signer::Secp256k1(_) => Standard::Erc191,
            Signer::P256(_) => Standard::WebAuthn,
        }
    }

    pub fn raw_ed25519(&self, payload: &str) -> MultiPayload {
        let Signer::Ed25519(k) = self else { panic!("raw_ed25519 needs an ed25519 key") };
        MultiPayload::RawEd25519 {
            payload: payload.into(),
            public_key: self.public_key().to_string(),
            signature: format!("ed25519:{}", b58(&k.sign(payload.as_bytes()).to_bytes())),
        }
    }

    /// v ∈ {0, 1}, low-s (k256 normalises).
    pub fn erc191(&self, payload: &str) -> MultiPayload {
        let Signer::Secp256k1(k) = self else { panic!("erc191 needs a secp256k1 key") };
        let mut m = format!("\x19Ethereum Signed Message:\n{}", payload.len()).into_bytes();
        m.extend_from_slice(payload.as_bytes());
        let (sig, rec) = k.sign_prehash_recoverable(&keccak(&m)).expect("sign");
        let mut out = sig.to_bytes().to_vec();
        out.push(rec.to_byte());
        MultiPayload::Erc191 { payload: payload.into(), signature: format!("secp256k1:{}", b58(&out)) }
    }

    pub fn nep413(&self, message: &str, nonce: [u8; 32], recipient: &str) -> MultiPayload {
        let Signer::Ed25519(k) = self else { panic!("nep413 needs an ed25519 key") };
        let p = Nep413Payload {
            message: message.into(),
            nonce: STANDARD.encode(nonce),
            recipient: recipient.into(),
            callback_url: None,
        };
        let h = nep413_native_hash(&p, &nonce);
        MultiPayload::Nep413 {
            payload: p,
            public_key: self.public_key().to_string(),
            signature: format!("ed25519:{}", b58(&k.sign(&h).to_bytes())),
        }
    }

    pub fn webauthn(&self, payload: &str) -> MultiPayload {
        self.webauthn_with(payload, FLAGS_UP_UV, "webauthn.get")
    }

    /// WebAuthn assertion over `payload` with authenticator `flags` and client data `typ`.
    pub fn webauthn_with(&self, payload: &str, flags: u8, typ: &str) -> MultiPayload {
        let cdj = format!(
            r#"{{"type":"{typ}","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(sha256(payload.as_bytes()))
        );
        let mut ad = sha256(RP_ID.as_bytes()).to_vec();
        ad.push(flags);
        ad.extend_from_slice(&[0, 0, 0, 0]);
        let mut signed = ad.clone();
        signed.extend_from_slice(&sha256(cdj.as_bytes()));
        let signature = match self {
            Signer::P256(k) => {
                let s: p256::ecdsa::Signature = k.sign_prehash(&sha256(&signed)).expect("sign");
                let s = s.normalize_s().unwrap_or(s);
                format!("p256:{}", b58(&s.to_bytes()))
            }
            Signer::Ed25519(k) => format!("ed25519:{}", b58(&k.sign(&signed).to_bytes())),
            Signer::Secp256k1(_) => panic!("webauthn needs a P-256 or ed25519 key"),
        };
        MultiPayload::WebAuthn {
            payload: payload.into(),
            public_key: self.public_key().to_string(),
            signature,
            client_data_json: cdj,
            authenticator_data: URL_SAFE_NO_PAD.encode(&ad),
        }
    }

    /// Signs a trading-account body with `standard` (nep413 splits it the intents way).
    pub fn sign_ops(&self, standard: Standard, b: &BodySpec) -> MultiPayload {
        match standard {
            Standard::Nep413 => self.nep413(&b.nep413_message("ops"), b.nonce, &b.verifying_contract),
            Standard::Erc191 => self.erc191(&b.text("ops")),
            Standard::RawEd25519 => self.raw_ed25519(&b.text("ops")),
            Standard::WebAuthn => self.webauthn(&b.text("ops")),
        }
    }

    /// Signs an intents.near body (the factory's creation intent).
    pub fn sign_intents(&self, standard: Standard, b: &BodySpec) -> MultiPayload {
        match standard {
            Standard::Nep413 => self.nep413(&b.nep413_message("intents"), b.nonce, &b.verifying_contract),
            Standard::Erc191 => self.erc191(&b.text("intents")),
            Standard::RawEd25519 => self.raw_ed25519(&b.text("intents")),
            Standard::WebAuthn => self.webauthn(&b.text("intents")),
        }
    }
}

/// What a body says. `items_json` is the JSON array of ops (or intents).
#[derive(Clone, Debug)]
pub struct BodySpec {
    pub signer_id: String,
    pub verifying_contract: String,
    pub deadline_ns: u64,
    pub nonce: [u8; 32],
    pub items_json: String,
}

impl BodySpec {
    /// Body text in the builder's key order (`signer_id, verifying_contract, deadline, nonce, <field>`).
    pub fn text(&self, field: &str) -> String {
        format!(
            r#"{{"signer_id":"{}","verifying_contract":"{}","deadline":"{}","nonce":"{}","{field}":{}}}"#,
            self.signer_id,
            self.verifying_contract,
            iso(self.deadline_ns),
            STANDARD.encode(self.nonce),
            self.items_json
        )
    }

    pub fn nep413_message(&self, field: &str) -> String {
        format!(
            r#"{{"signer_id":"{}","deadline":"{}","{field}":{}}}"#,
            self.signer_id,
            iso(self.deadline_ns),
            self.items_json
        )
    }
}

/// ns → `YYYY-MM-DDTHH:MM:SS.mmmZ` (milliseconds, as JS `toISOString`); sub-ms is truncated.
pub fn iso(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let ms = (ns % 1_000_000_000) / 1_000_000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // civil from days (H. Hinnant)
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

/// Native NEP-413 hash (independent of the host implementation, for cross-checks).
pub fn nep413_native_hash(p: &Nep413Payload, nonce: &[u8; 32]) -> [u8; 32] {
    let mut m = NEP413_TAG.to_le_bytes().to_vec();
    for (i, s) in [&p.message, &p.recipient].into_iter().enumerate() {
        m.extend_from_slice(&(s.len() as u32).to_le_bytes());
        m.extend_from_slice(s.as_bytes());
        if i == 0 {
            m.extend_from_slice(nonce);
        }
    }
    match &p.callback_url {
        None => m.push(0),
        Some(u) => {
            m.push(1);
            m.extend_from_slice(&(u.len() as u32).to_le_bytes());
            m.extend_from_slice(u.as_bytes());
        }
    }
    sha256(&m)
}

/// The high-s twin of a valid signature (erc191: s → n − s and the recovery bit flipped;
/// webauthn P-256: s → n − s). Both are mathematically valid signatures.
pub fn with_high_s(mp: &MultiPayload) -> MultiPayload {
    let mut mp = mp.clone();
    match &mut mp {
        MultiPayload::Erc191 { signature, .. } => {
            let mut b = near_sdk::bs58::decode(&signature["secp256k1:".len()..]).into_vec().expect("b58");
            let s = k256::ecdsa::Signature::from_slice(&b[..64]).expect("sig");
            let (r, s) = s.split_scalars();
            let hs = k256::ecdsa::Signature::from_scalars(r, -*s).expect("twin");
            b[..64].copy_from_slice(&hs.to_bytes());
            b[64] ^= 1;
            *signature = format!("secp256k1:{}", b58(&b));
        }
        MultiPayload::WebAuthn { signature, .. } if signature.starts_with("p256:") => {
            let b = near_sdk::bs58::decode(&signature["p256:".len()..]).into_vec().expect("b58");
            let s = p256::ecdsa::Signature::from_slice(&b).expect("sig");
            let (r, s) = s.split_scalars();
            let hs = p256::ecdsa::Signature::from_scalars(r, -*s).expect("twin");
            *signature = format!("p256:{}", b58(&hs.to_bytes()));
        }
        _ => panic!("high-s twin: erc191 or webauthn P-256 only"),
    }
    mp
}

/// erc191 with `v + 27` (what wallets return before normalisation).
pub fn with_v27(mp: &MultiPayload) -> MultiPayload {
    let mut mp = mp.clone();
    let MultiPayload::Erc191 { signature, .. } = &mut mp else { panic!("erc191 only") };
    let mut b = near_sdk::bs58::decode(&signature["secp256k1:".len()..]).into_vec().expect("b58");
    b[64] += 27;
    *signature = format!("secp256k1:{}", b58(&b));
    mp
}
