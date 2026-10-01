//! Owner-signed payloads (docs/owner-v16-spec.md §2, §6 "owner-auth API (frozen)").
//!
//! Parses and verifies a near/intents `MultiPayload` (pinned: near/intents
//! `fa44ede9e874931c39a6c4246de82bc40f4f8d99`, what mainnet `intents.near` 0.4.2 runs) for the
//! arms `erc191`, `raw_ed25519`, `nep413` and `webauthn` (P-256 and ed25519), with NEAR host
//! functions only (`ed25519_verify`, `p256_verify`, `ecrecover`). No state, no promises: the
//! trading account and the factory own their storage and call these pure checks.
//!
//! Every failure is a `&'static str` error code (the contracts panic with it, or, in the
//! factory's `on_auth`, refund with it).
use near_sdk::base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use near_sdk::base64::Engine;
use near_sdk::serde::de::DeserializeOwned;
use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};
use near_sdk::{env, near, serde_json};

#[cfg(feature = "testkit")]
pub mod testkit;
#[cfg(test)]
mod tests;

/// The near/intents commit whose payload formats this crate implements.
pub const INTENTS_REF: &str = "near/intents@fa44ede9e874931c39a6c4246de82bc40f4f8d99";
/// Max bytes of the signed body text (`payload`, or `payload.message` for nep413).
pub const MAX_PAYLOAD_LEN: usize = 4_096;
/// Max bytes of a webauthn `client_data_json`.
pub const MAX_CLIENT_DATA_LEN: usize = 1_024;
/// A signed owner payload lives at most this long (deadline and nonce deadline, spec §2.2/§2.3).
pub const OWNER_PAYLOAD_TTL_NS: u64 = 15 * 60 * 1_000_000_000;
/// Live used nonces a trading account keeps (spec §4.1).
pub const MAX_OWNER_NONCES: usize = 32;
/// Auth (backup) keys per trading account (spec §4.4).
pub const MAX_AUTH_KEYS: usize = 4;
/// intents `VersionedNonce` magic prefix.
pub const NONCE_MAGIC: [u8; 4] = [0x56, 0x28, 0xf6, 0xc6];
/// NEP-413 borsh tag: 2^31 + 413.
pub const NEP413_TAG: u32 = 2_147_484_061;

pub const E_PAYLOAD_SIZE: &str = "E_PAYLOAD_SIZE";
pub const E_PAYLOAD: &str = "E_PAYLOAD";
pub const E_SIG: &str = "E_SIG";
pub const E_HIGH_S: &str = "E_HIGH_S";
pub const E_WEBAUTHN: &str = "E_WEBAUTHN";
pub const E_DEADLINE: &str = "E_DEADLINE";
pub const E_NONCE_SALT: &str = "E_NONCE_SALT";
pub const E_NONCE_DEADLINE: &str = "E_NONCE_DEADLINE";
pub const E_NONCE_USED: &str = "E_NONCE_USED";
pub const E_NONCES_FULL: &str = "E_NONCES_FULL";
pub const E_KEY_FORMAT: &str = "E_KEY_FORMAT";

// ---------------------------------------------------------------- envelope (spec §2.1)

/// near/intents `MultiPayload` restricted to the four arms we accept. Unknown fields and unknown
/// `standard`s are refused by serde.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde", tag = "standard", rename_all = "snake_case", deny_unknown_fields)]
pub enum MultiPayload {
    Erc191 {
        payload: String,
        /// `secp256k1:` + base58(r ‖ s ‖ v), v ∈ {0, 1}
        signature: String,
    },
    RawEd25519 {
        payload: String,
        public_key: String,
        signature: String,
    },
    Nep413 {
        payload: Nep413Payload,
        public_key: String,
        signature: String,
    },
    #[serde(rename = "webauthn")]
    WebAuthn {
        payload: String,
        /// `p256:` + base58(X ‖ Y) or `ed25519:` + base58(32)
        public_key: String,
        /// `p256:` + base58(r ‖ s) or `ed25519:` + base58(64)
        signature: String,
        client_data_json: String,
        /// base64url, no padding
        authenticator_data: String,
    },
}

/// NEP-413 payload as intents serialises it (`callbackUrl`, camelCase).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase", deny_unknown_fields)]
pub struct Nep413Payload {
    pub message: String,
    /// base64 (standard, padded) of 32 bytes
    pub nonce: String,
    pub recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Standard {
    Erc191,
    RawEd25519,
    Nep413,
    /// P-256 or ed25519 (the key says which)
    WebAuthn,
}

impl Standard {
    pub fn as_str(self) -> &'static str {
        match self {
            Standard::Erc191 => "erc191",
            Standard::RawEd25519 => "raw_ed25519",
            Standard::Nep413 => "nep413",
            Standard::WebAuthn => "webauthn",
        }
    }
}

impl MultiPayload {
    pub fn standard(&self) -> Standard {
        match self {
            MultiPayload::Erc191 { .. } => Standard::Erc191,
            MultiPayload::RawEd25519 { .. } => Standard::RawEd25519,
            MultiPayload::Nep413 { .. } => Standard::Nep413,
            MultiPayload::WebAuthn { .. } => Standard::WebAuthn,
        }
    }

    /// The signed body text: `payload`, or `payload.message` for nep413.
    pub fn text(&self) -> &str {
        match self {
            MultiPayload::Erc191 { payload, .. }
            | MultiPayload::RawEd25519 { payload, .. }
            | MultiPayload::WebAuthn { payload, .. } => payload,
            MultiPayload::Nep413 { payload, .. } => &payload.message,
        }
    }
}

// ---------------------------------------------------------------- keys and owner ids (spec §3)

/// A signing key. Borsh layout is part of the trading account's `ow` record (spec §4.1).
#[near(serializers = [borsh])]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    /// uncompressed X ‖ Y
    Secp256k1([u8; 64]),
    /// uncompressed X ‖ Y
    P256([u8; 64]),
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnerKind {
    /// Any NEAR account id that is not key-derived: predecessor path only.
    Named,
    /// 64 lowercase hex = hex(pk)
    Ed25519,
    /// `0x` + 40 lowercase hex = keccak256(X ‖ Y)[12..]
    Secp256k1,
    /// `0x` + 40 lowercase hex = keccak256("p256" ‖ X ‖ Y)[12..]
    P256,
}

/// Default native chain of an `Ed25519` owner's cross-chain home (spec §3, §5.2).
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Home {
    Near,
    Solana,
}

/// What the factory passes to the trading account's `init` for a signed creation.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnerAuthInit {
    pub kind: OwnerKind,
    pub home: Home,
}

impl OwnerKind {
    /// The id rule (spec §3) for accounts created or migrated without a verified key: 64-hex →
    /// `Ed25519`, `0x` + 40 hex → `Secp256k1` (the only `0x` owners before 1.6.0), else `Named`.
    pub fn from_id(id: &str) -> Self {
        if is_lower_hex(id, 64) {
            OwnerKind::Ed25519
        } else if id.len() == 42 && id.starts_with("0x") && is_lower_hex(&id[2..], 40) {
            OwnerKind::Secp256k1
        } else {
            OwnerKind::Named
        }
    }

    pub fn is_signer(self) -> bool {
        self != OwnerKind::Named
    }
}

/// `raw_ed25519` (Solana wallets) → `Solana`; every other standard → `Near`.
pub fn home_for(standard: Standard) -> Home {
    if standard == Standard::RawEd25519 {
        Home::Solana
    } else {
        Home::Near
    }
}

impl PublicKey {
    /// `ed25519:` + b58(32), `secp256k1:` + b58(64), `p256:` + b58(64). Else `E_KEY_FORMAT`.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if let Some(r) = s.strip_prefix("ed25519:") {
            b58::<32>(r).map(PublicKey::Ed25519)
        } else if let Some(r) = s.strip_prefix("secp256k1:") {
            b58::<64>(r).map(PublicKey::Secp256k1)
        } else if let Some(r) = s.strip_prefix("p256:") {
            b58::<64>(r).filter(p256_on_curve).map(PublicKey::P256)
        } else {
            None
        }
        .ok_or(E_KEY_FORMAT)
    }

    /// The owner kind this key's curve belongs to.
    pub fn kind(&self) -> OwnerKind {
        match self {
            PublicKey::Ed25519(_) => OwnerKind::Ed25519,
            PublicKey::Secp256k1(_) => OwnerKind::Secp256k1,
            PublicKey::P256(_) => OwnerKind::P256,
        }
    }

    /// The owner id this key implies (the intents implicit account id).
    pub fn implicit_id(&self) -> String {
        match self {
            PublicKey::Ed25519(k) => hex(k),
            PublicKey::Secp256k1(k) => format!("0x{}", hex(&env::keccak256_array(k)[12..])),
            PublicKey::P256(k) => {
                let mut m = Vec::with_capacity(68);
                m.extend_from_slice(b"p256");
                m.extend_from_slice(k);
                format!("0x{}", hex(&env::keccak256_array(&m)[12..]))
            }
        }
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (p, b): (&str, &[u8]) = match self {
            PublicKey::Ed25519(k) => ("ed25519", k),
            PublicKey::Secp256k1(k) => ("secp256k1", k),
            PublicKey::P256(k) => ("p256", k),
        };
        write!(f, "{p}:{}", near_sdk::bs58::encode(b).into_string())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PublicKey::parse(&s).map_err(near_sdk::serde::de::Error::custom)
    }
}

/// A small-order (torsion) ed25519 point in any encoding: refused as an auth key (spec §4.4).
/// Such a key "verifies" forged signatures for some messages under non-strict verifiers.
pub fn is_small_order_ed25519(pk: &[u8; 32]) -> bool {
    let mut y = *pk;
    y[31] &= 0x7f; // drop the x sign bit
    const P_MINUS_1: [u8; 32] = p_plus(-1);
    const P: [u8; 32] = p_plus(0);
    const P_PLUS_1: [u8; 32] = p_plus(1);
    // y of the two order-8 point pairs (little endian)
    const Y8A: [u8; 32] = [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5,
        0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
    ];
    const Y8B: [u8; 32] = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a,
        0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    ];
    let mut one = [0u8; 32];
    one[0] = 1;
    [[0u8; 32], one, P_MINUS_1, P, P_PLUS_1, Y8A, Y8B].contains(&y)
}

/// 2^255 − 19 + d (little endian), for d ∈ {−1, 0, 1}.
const fn p_plus(d: i8) -> [u8; 32] {
    let mut b = [0xffu8; 32];
    b[31] = 0x7f;
    b[0] = (0xed_i16 + d as i16) as u8;
    b
}

// ---------------------------------------------------------------- body (spec §2.2)

/// The parsed body, whatever arm carried it. `items` = `ops` (trading account) or `intents`
/// (the factory's creation intent).
#[derive(Debug, PartialEq)]
pub struct Body<T> {
    pub signer_id: String,
    pub verifying_contract: String,
    pub deadline_ns: u64,
    pub nonce: [u8; 32],
    pub items: T,
}

macro_rules! body_structs {
    ($full:ident, $msg:ident, $field:ident) => {
        #[derive(Deserialize)]
        #[serde(crate = "near_sdk::serde", deny_unknown_fields)]
        struct $full<T> {
            signer_id: String,
            verifying_contract: String,
            deadline: String,
            nonce: String,
            $field: T,
        }

        /// nep413 `message`: verifying_contract = `recipient`, nonce = `payload.nonce`.
        #[derive(Deserialize)]
        #[serde(crate = "near_sdk::serde", deny_unknown_fields)]
        struct $msg<T> {
            signer_id: String,
            deadline: String,
            $field: T,
        }
    };
}
body_structs!(OpsFull, OpsMsg, ops);
body_structs!(IntentsFull, IntentsMsg, intents);

/// Size + shape of a trading-account payload (`{signer_id, verifying_contract, deadline, nonce,
/// ops}`; nep413: `{signer_id, deadline, ops}`). Errors: `E_PAYLOAD_SIZE`, `E_PAYLOAD` (JSON,
/// unknown or duplicate keys, nonce not base64 of 32 bytes, nep413 `callbackUrl` present),
/// `E_DEADLINE` (not strict `YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z`). The signature is NOT checked.
pub fn parse_ops<T: DeserializeOwned>(mp: &MultiPayload) -> Result<Body<T>, &'static str> {
    check_size(mp)?;
    match mp {
        MultiPayload::Nep413 { payload, .. } => {
            let m: OpsMsg<T> = json(&payload.message)?;
            nep413_body(payload, m.signer_id, m.deadline, m.ops)
        }
        _ => {
            let b: OpsFull<T> = json(mp.text())?;
            full_body(b.signer_id, b.verifying_contract, b.deadline, b.nonce, b.ops)
        }
    }
}

/// As [`parse_ops`] for an intents.near payload (`intents` instead of `ops`), used by the factory.
pub fn parse_intents<T: DeserializeOwned>(mp: &MultiPayload) -> Result<Body<T>, &'static str> {
    check_size(mp)?;
    match mp {
        MultiPayload::Nep413 { payload, .. } => {
            let m: IntentsMsg<T> = json(&payload.message)?;
            nep413_body(payload, m.signer_id, m.deadline, m.intents)
        }
        _ => {
            let b: IntentsFull<T> = json(mp.text())?;
            full_body(b.signer_id, b.verifying_contract, b.deadline, b.nonce, b.intents)
        }
    }
}

fn check_size(mp: &MultiPayload) -> Result<(), &'static str> {
    if mp.text().len() > MAX_PAYLOAD_LEN {
        return Err(E_PAYLOAD_SIZE);
    }
    Ok(())
}

fn json<T: DeserializeOwned>(s: &str) -> Result<T, &'static str> {
    serde_json::from_str(s).map_err(|_| E_PAYLOAD)
}

fn full_body<T>(
    signer_id: String,
    verifying_contract: String,
    deadline: String,
    nonce: String,
    items: T,
) -> Result<Body<T>, &'static str> {
    Ok(Body {
        signer_id,
        verifying_contract,
        deadline_ns: iso_ns(&deadline).ok_or(E_DEADLINE)?,
        nonce: nonce32(&nonce)?,
        items,
    })
}

fn nep413_body<T>(
    p: &Nep413Payload,
    signer_id: String,
    deadline: String,
    items: T,
) -> Result<Body<T>, &'static str> {
    if p.callback_url.is_some() {
        return Err(E_PAYLOAD);
    }
    full_body(signer_id, p.recipient.clone(), deadline, p.nonce.clone(), items)
}

fn nonce32(s: &str) -> Result<[u8; 32], &'static str> {
    STANDARD.decode(s).ok().and_then(|v| v.try_into().ok()).ok_or(E_PAYLOAD)
}

// ---------------------------------------------------------------- signatures (spec §2.1)

/// Verifies the signature of `mp` and returns the signing key. Errors: `E_SIG` (bad encoding,
/// v ∉ {0,1}, failed verification, secp256k1 high-s via the host malleability flag), `E_HIGH_S`
/// (P-256 s > n/2), `E_WEBAUTHN` (authenticator data / client data rules). Does not look at the
/// body (see [`parse_ops`]).
pub fn verify(mp: &MultiPayload) -> Result<PublicKey, &'static str> {
    match mp {
        MultiPayload::RawEd25519 { payload, public_key, signature } => {
            let (pk, sig) = (ed_key(public_key)?, ed_sig(signature)?);
            ed_verify(&sig, payload.as_bytes(), &pk)
        }
        MultiPayload::Erc191 { payload, signature } => {
            let sig = signature.strip_prefix("secp256k1:").and_then(b58::<65>).ok_or(E_SIG)?;
            // the host aborts the whole call for v >= 4: check first for a clean E_SIG
            if sig[64] > 1 {
                return Err(E_SIG);
            }
            // malleability_flag = true: the host refuses high-s
            env::ecrecover(&erc191_hash(payload), &sig[..64], sig[64], true)
                .map(PublicKey::Secp256k1)
                .ok_or(E_SIG)
        }
        MultiPayload::Nep413 { payload, public_key, signature } => {
            let (pk, sig) = (ed_key(public_key)?, ed_sig(signature)?);
            let nonce = nonce32(&payload.nonce)?;
            ed_verify(&sig, &nep413_hash(payload, &nonce), &pk)
        }
        MultiPayload::WebAuthn { payload, public_key, signature, client_data_json, authenticator_data } => {
            let ad = URL_SAFE_NO_PAD.decode(authenticator_data).map_err(|_| E_WEBAUTHN)?;
            // flags: UP (0x01) and UV (0x04) required (intents ignores UV: the TA is stricter);
            // BS (0x10) needs BE (0x08)
            let ok_flags =
                ad.len() >= 37 && ad[32] & 0x05 == 0x05 && (ad[32] & 0x10 == 0 || ad[32] & 0x08 != 0);
            if !ok_flags || client_data_json.len() > MAX_CLIENT_DATA_LEN {
                return Err(E_WEBAUTHN);
            }
            let c: ClientData = serde_json::from_str(client_data_json).map_err(|_| E_WEBAUTHN)?;
            let challenge = URL_SAFE_NO_PAD.decode(&c.challenge).map_err(|_| E_WEBAUTHN)?;
            if c.typ != "webauthn.get" || challenge != env::sha256_array(payload.as_bytes()) {
                return Err(E_WEBAUTHN);
            }
            let mut signed = ad;
            signed.extend_from_slice(&env::sha256_array(client_data_json.as_bytes()));
            if let Some(k) = public_key.strip_prefix("p256:") {
                // V16-14: the whole point must be on the curve (the host only sees X and Y's parity)
                let pk = b58::<64>(k).filter(p256_on_curve).ok_or(E_SIG)?;
                let sig = signature.strip_prefix("p256:").and_then(b58::<64>).ok_or(E_SIG)?;
                // low-s only: the host accepts both halves
                if sig[32..] > P256_HALF_N[..] {
                    return Err(E_HIGH_S);
                }
                let mut c33 = [0u8; 33];
                c33[0] = 2 + (pk[63] & 1);
                c33[1..].copy_from_slice(&pk[..32]);
                if env::p256_verify(&sig, &env::sha256_array(&signed), &c33) {
                    Ok(PublicKey::P256(pk))
                } else {
                    Err(E_SIG)
                }
            } else {
                let (pk, sig) = (ed_key(public_key)?, ed_sig(signature)?);
                // ed25519 signs the raw bytes (not prehashed)
                ed_verify(&sig, &signed, &pk)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
}

/// n/2 of P-256 (big endian): s must be ≤ this.
pub const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde,
    0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

fn ed_key(s: &str) -> Result<[u8; 32], &'static str> {
    s.strip_prefix("ed25519:").and_then(b58::<32>).ok_or(E_SIG)
}

fn ed_sig(s: &str) -> Result<[u8; 64], &'static str> {
    s.strip_prefix("ed25519:").and_then(b58::<64>).ok_or(E_SIG)
}

fn ed_verify(sig: &[u8; 64], msg: &[u8], pk: &[u8; 32]) -> Result<PublicKey, &'static str> {
    if env::ed25519_verify(sig, msg, pk) {
        Ok(PublicKey::Ed25519(*pk))
    } else {
        Err(E_SIG)
    }
}

/// keccak256("\x19Ethereum Signed Message:\n" + len(payload) + payload)
pub fn erc191_hash(payload: &str) -> [u8; 32] {
    let mut m = format!("\x19Ethereum Signed Message:\n{}", payload.len()).into_bytes();
    m.extend_from_slice(payload.as_bytes());
    env::keccak256_array(&m)
}

/// sha256(borsh(u32 NEP413_TAG) ‖ borsh(Nep413Payload)), with the decoded 32-byte nonce.
pub fn nep413_hash(p: &Nep413Payload, nonce: &[u8; 32]) -> [u8; 32] {
    let mut m = NEP413_TAG.to_le_bytes().to_vec();
    let s = |m: &mut Vec<u8>, x: &str| {
        m.extend_from_slice(&(x.len() as u32).to_le_bytes());
        m.extend_from_slice(x.as_bytes());
    };
    s(&mut m, &p.message);
    m.extend_from_slice(nonce);
    s(&mut m, &p.recipient);
    match &p.callback_url {
        None => m.push(0),
        Some(u) => {
            m.push(1);
            s(&mut m, u);
        }
    }
    env::sha256_array(&m)
}

// ---------------------------------------------------------------- deadline and nonce (§2.2, §2.3)

/// `now ≤ deadline ≤ now + ttl`, else `E_DEADLINE`.
pub fn check_deadline(deadline_ns: u64, now: u64, ttl_ns: u64) -> Result<(), &'static str> {
    if deadline_ns < now || deadline_ns > now.saturating_add(ttl_ns) {
        return Err(E_DEADLINE);
    }
    Ok(())
}

/// intents `VersionedNonce::V1` with `salt`: `magic ‖ 0 ‖ salt[4] ‖ deadline i64 LE ns ‖ 15`.
/// Checks, in the intents order: magic/version/salt (`E_NONCE_SALT`), then
/// `deadline_ns ≤ nonce deadline ≤ now + OWNER_PAYLOAD_TTL_NS` (`E_NONCE_DEADLINE`). Returns the
/// nonce deadline (when a used-nonce entry may be pruned). "Used" is the caller's store.
pub fn check_nonce(
    nonce: &[u8; 32],
    salt: &[u8; 4],
    deadline_ns: u64,
    now: u64,
) -> Result<u64, &'static str> {
    if nonce[..4] != NONCE_MAGIC || nonce[4] != 0 || nonce[5..9] != salt[..] {
        return Err(E_NONCE_SALT);
    }
    let mut d = [0u8; 8];
    d.copy_from_slice(&nonce[9..17]);
    let nd = i64::from_le_bytes(d);
    if nd < 0 || (nd as u64) < deadline_ns || nd as u64 > now.saturating_add(OWNER_PAYLOAD_TTL_NS) {
        return Err(E_NONCE_DEADLINE);
    }
    Ok(nd as u64)
}

/// Builds a nonce (clients, tests).
pub fn versioned_nonce(salt: [u8; 4], deadline_ns: u64, random: [u8; 15]) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..4].copy_from_slice(&NONCE_MAGIC);
    n[5..9].copy_from_slice(&salt);
    n[9..17].copy_from_slice(&(deadline_ns as i64).to_le_bytes());
    n[17..].copy_from_slice(&random);
    n
}

/// Used nonces with the time after which each may be pruned (its nonce deadline): a replay after
/// that fails `E_DEADLINE` / `E_NONCE_DEADLINE`, so pruning never re-opens a nonce.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NonceStore(pub Vec<([u8; 32], u64)>);

impl NonceStore {
    /// Drops entries with `expires_ns < now`.
    pub fn prune(&mut self, now: u64) {
        self.0.retain(|(_, e)| *e >= now);
    }

    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.0.iter().any(|(n, _)| n == nonce)
    }

    /// prune, then `E_NONCE_USED` / `E_NONCES_FULL` (at MAX_OWNER_NONCES live entries), then add.
    pub fn insert(&mut self, nonce: [u8; 32], expires_ns: u64, now: u64) -> Result<(), &'static str> {
        self.check(&nonce, now)?;
        self.prune(now);
        self.0.push((nonce, expires_ns));
        Ok(())
    }

    /// The checks of [`insert`](Self::insert) without writing (views).
    pub fn check(&self, nonce: &[u8; 32], now: u64) -> Result<(), &'static str> {
        let live = self.0.iter().filter(|(_, e)| *e >= now);
        if live.clone().any(|(n, _)| n == nonce) {
            return Err(E_NONCE_USED);
        }
        if live.count() >= MAX_OWNER_NONCES {
            return Err(E_NONCES_FULL);
        }
        Ok(())
    }

    pub fn live(&self, now: u64) -> usize {
        self.0.iter().filter(|(_, e)| *e >= now).count()
    }
}

/// Strict `YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z` (UTC, years 1970..=2500, real calendar days) → unix ns.
pub fn iso_ns(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if *b.last()? != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        let d = b.get(r)?;
        if !d.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(d.iter().fold(0u64, |a, c| a * 10 + u64::from(c - b'0')))
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let nanos = match &b[19..b.len() - 1] {
        [] => 0,
        [b'.', digits @ ..] if (1..=9).contains(&digits.len()) => {
            num(20..20 + digits.len())? * 10u64.pow(9 - digits.len() as u32)
        }
        _ => return None,
    };
    if !(1970..=2500).contains(&y) || !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if d == 0 || d > mdays[(mo - 1) as usize] {
        return None;
    }
    // days from civil (H. Hinnant), y >= 1970
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let doy = (153 * ((mo + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    ((days * 86_400 + h * 3_600 + mi * 60 + sec) * 1_000_000_000).checked_add(nanos)
}

// ---------------------------------------------------------------- helpers

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// 64-hex (an Ed25519 owner id) → the 32 key bytes.
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    if !is_lower_hex(s, 64) {
        return None;
    }
    let nib = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
    let mut k = [0u8; 32];
    for (i, p) in s.as_bytes().chunks(2).enumerate() {
        k[i] = nib(p[0]) << 4 | nib(p[1]);
    }
    Some(k)
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn b58<const N: usize>(s: &str) -> Option<[u8; N]> {
    near_sdk::bs58::decode(s).into_vec().ok()?.try_into().ok()
}

// ---------------------------------------------------------------- P-256 point check (V16-14)

type U256 = [u64; 4]; // little-endian limbs

const P256_P: U256 =
    [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0x0000_0000_0000_0000, 0xffff_ffff_0000_0001];
const P256_B: U256 =
    [0x3bce_3c3e_27d2_604b, 0x651d_06b0_cc53_b0f6, 0xb3eb_bd55_7698_86bc, 0x5ac6_35d8_aa3a_93e7];

fn u256_be(b: &[u8]) -> U256 {
    let mut r = [0u64; 4];
    for (i, c) in b.chunks(8).enumerate() {
        r[3 - i] = u64::from_be_bytes(c.try_into().unwrap_or([0; 8]));
    }
    r
}

fn u256_ge(a: &U256, b: &U256) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn u256_sub(a: &U256, b: &U256) -> U256 {
    let mut r = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        r[i] = d;
        borrow = b1 || b2;
    }
    r
}

/// (a + b) mod p for a, b < p.
fn add_mod(a: &U256, b: &U256) -> U256 {
    let mut r = [0u64; 4];
    let mut carry = false;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(u64::from(carry));
        r[i] = s2;
        carry = c1 || c2;
    }
    if carry || u256_ge(&r, &P256_P) {
        r = u256_sub(&r, &P256_P); // wraps correctly when carry: r + 2^256 - p < p
    }
    r
}

/// (a · b) mod p by double-and-add (a, b < p).
fn mul_mod(a: &U256, b: &U256) -> U256 {
    let mut r = [0u64; 4];
    for i in (0..256).rev() {
        r = add_mod(&r, &r);
        if (b[i / 64] >> (i % 64)) & 1 == 1 {
            r = add_mod(&r, a);
        }
    }
    r
}

/// `X ‖ Y` (big endian) is a point of P-256: x, y < p and y² = x³ − 3x + b (mod p).
pub fn p256_on_curve(xy: &[u8; 64]) -> bool {
    let (x, y) = (u256_be(&xy[..32]), u256_be(&xy[32..]));
    if u256_ge(&x, &P256_P) || u256_ge(&y, &P256_P) {
        return false;
    }
    let x3 = mul_mod(&mul_mod(&x, &x), &x);
    let three_x = add_mod(&add_mod(&x, &x), &x);
    let minus_3x = if three_x == [0; 4] { three_x } else { u256_sub(&P256_P, &three_x) };
    let rhs = add_mod(&add_mod(&x3, &minus_3x), &P256_B);
    mul_mod(&y, &y) == rhs
}
