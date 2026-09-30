//! Factory (spec: docs/contract-spec.md v1). Creates one trading account per owner at
//! `<hex16(sha256(owner))>.<factory>` running the global contract by code hash.
use near_sdk::json_types::{Base58CryptoHash, U128};
use near_sdk::serde::Serialize;
use near_sdk::store::LookupSet;
use near_sdk::{
    env, near, serde_json, AccountId, Allowance, Gas, NearToken, PanicOnDefault, Promise, PublicKey,
};

/// Must equal trading-account DEVICE_METHODS (v1.3 adds the order methods, v1.4 the intents ones).
pub const DEVICE_METHODS: &str = "execute,withdraw_to_owner,lower_caps,place_order,cancel_order,revoke_automation,withdraw_cross_chain,remove_withdraw_destination,withdraw_from_intents,execute_order";
pub const MIN_FUNDING: NearToken = NearToken::from_millinear(200);
pub const MAX_DEVICE_KEYS: usize = 4;
/// v1.2: the account's init temporarily deposits DCL's 0.5 NEAR registration minimum on each
/// DCL-kind DEX (0.4 returns in the same receipt, 0.1 stays locked and is reclaimable).
pub const DCL_REGISTRATION: NearToken = NearToken::from_millinear(500);
const MAX_FEE_BPS: u16 = 100;
// init also schedules wrap.storage_deposit (10 TGas, v1.1) + DCL registration (20 TGas per DCL dex, v1.2)
const GAS_INIT: Gas = Gas::from_tgas(50);
/// v1.4.7: init also installs the automation key (AddKey batch + 5 TGas on_automation_set).
const GAS_INIT_AUTOMATION: Gas = Gas::from_tgas(70);
/// v1.4.7: trading-account MIN_AUTOMATION_ALLOWANCE (the account re-checks it in init).
const MIN_AUTOMATION_ALLOWANCE: u128 = 500_000_000_000_000_000_000_000;
/// v1.4.7: "no cap" (trading-account UNLIMITED); used when create_account gets no caps.
pub const UNLIMITED: u128 = u128::MAX;
const GAS_CALLBACK: Gas = Gas::from_tgas(10);

/// Same JSON shape as trading-account's Caps / Dex (passed through to `init`).
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Caps {
    pub max_trade_yocto: U128,
    pub daily_cap_yocto: U128,
}

/// v1.4.7: an automation key (24/7 orders) the account installs in `init`. Same JSON shape as
/// trading-account's AutomationInit.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct AutomationInit {
    pub public_key: PublicKey,
    pub allowance: U128,
    /// 1.1.1 (account v1.4.8): None = no weekly relayer limit (the default); Some = opt-in
    pub weekly_yocto: Option<U128>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub enum DexKind {
    RheaClassic,
    RheaDcl,
    Plach,
    /// 1.2.0 (account v1.5.0): Shards tokens; `id` = the Shards factory (tokens `<label>.<id>`).
    ShardsToken,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Dex {
    pub id: AccountId,
    pub kind: DexKind,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct FeeConfig {
    pub fee_bps: u16,
    pub fee_recipient: AccountId,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Factory {
    admin: AccountId,
    code_hash: Base58CryptoHash,
    fee_config: FeeConfig,
    dex_allowlist: Vec<Dex>,
    wrap: AccountId,
    /// Accounts created or being created (sync E_EXISTS; removed again on failure).
    created: LookupSet<AccountId>,
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct InitArgs<'a> {
    owner: &'a AccountId,
    fee_config: &'a FeeConfig,
    caps: &'a Caps,
    dex_allowlist: &'a [Dex],
    wrap: &'a AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    automation: Option<&'a AutomationInit>,
}

#[near(serializers = [json])]
pub struct FactoryConfig {
    pub admin: AccountId,
    pub code_hash: Base58CryptoHash,
    pub fee_config: FeeConfig,
    pub dex_allowlist: Vec<Dex>,
    pub wrap: AccountId,
}

#[near]
impl Factory {
    #[init]
    pub fn new(
        admin: AccountId,
        code_hash: Base58CryptoHash,
        fee_config: FeeConfig,
        dex_allowlist: Vec<Dex>,
        wrap: AccountId,
    ) -> Self {
        if fee_config.fee_bps > MAX_FEE_BPS {
            env::panic_str("E_FEE");
        }
        Self { admin, code_hash, fee_config, dex_allowlist, wrap, created: LookupSet::new(b"c") }
    }

    /// Affects NEW accounts only; existing accounts change code only via owner_upgrade.
    #[payable]
    pub fn set_code_hash(&mut self, code_hash: Base58CryptoHash) {
        if env::predecessor_account_id() != self.admin {
            env::panic_str("E_NOT_ADMIN");
        }
        near_sdk::assert_one_yocto();
        self.code_hash = code_hash;
    }

    /// `device_public_key` (single, v1 form) and/or `device_public_keys` (v1.3: 1-4 keys, so
    /// onboarding is one owner signature); all become FunctionCall keys to the account with
    /// DEVICE_METHODS. v1.2.1: the factory's own `created` entry storage is paid from the
    /// deposit (spam can't drain the factory); the rest goes to the account.
    #[payable]
    /// v1.4.7: `caps` optional (default: no cap, UNLIMITED); optional `automation` = the owner's
    /// automation key, installed by the account's `init` in the same batch (one signature).
    /// 1.1.1: `automation.weekly_yocto` optional, None = no weekly relayer limit (v1.4.8 code).
    pub fn create_account(
        &mut self,
        device_public_key: Option<PublicKey>,
        device_public_keys: Option<Vec<PublicKey>>,
        caps: Option<Caps>,
        automation: Option<AutomationInit>,
    ) -> Promise {
        let caps =
            caps.unwrap_or(Caps { max_trade_yocto: U128(UNLIMITED), daily_cap_yocto: U128(UNLIMITED) });
        let owner = env::predecessor_account_id();
        let account = self.account_for(owner.clone());
        let full_deposit = env::attached_deposit();
        if full_deposit < self.min_funding() {
            env::panic_str("E_MIN_FUNDING");
        }
        let mut keys: Vec<PublicKey> = device_public_key.into_iter().collect();
        keys.extend(device_public_keys.unwrap_or_default());
        if keys.is_empty()
            || keys.len() > MAX_DEVICE_KEYS
            || (1..keys.len()).any(|i| keys[..i].contains(&keys[i]))
        {
            env::panic_str("E_BAD_KEYS");
        }
        if let Some(a) = &automation {
            if keys.contains(&a.public_key) {
                env::panic_str("E_BAD_KEYS"); // a device key can't also be the relayer
            }
            if a.allowance.0 < MIN_AUTOMATION_ALLOWANCE {
                env::panic_str("E_ALLOWANCE");
            }
        }
        if !self.created.insert(account.clone()) {
            env::panic_str("E_EXISTS");
        }
        // LookupSet record: key = prefix(1) + borsh(AccountId) (4 + len), empty value, plus the
        // protocol's 40 bytes per storage record.
        let entry_bytes = 1 + 4 + account.as_str().len() as u128 + 40;
        let entry_cost = env::storage_byte_cost().saturating_mul(entry_bytes);
        let deposit = full_deposit.saturating_sub(entry_cost);
        let args = serde_json::to_vec(&InitArgs {
            owner: &owner,
            fee_config: &self.fee_config,
            caps: &caps,
            dex_allowlist: &self.dex_allowlist,
            wrap: &self.wrap,
            automation: automation.as_ref(),
        })
        .unwrap_or_else(|_| env::panic_str("E_JSON"));
        let mut batch = Promise::new(account.clone())
            .create_account()
            .transfer(deposit)
            .use_global_contract(self.code_hash);
        for k in keys {
            batch = batch.add_access_key_allowance(k, Allowance::Unlimited, account.clone(), DEVICE_METHODS);
        }
        // on failure the entry is removed again (its storage freed), so the FULL deposit is refunded
        let gas_init = if automation.is_some() { GAS_INIT_AUTOMATION } else { GAS_INIT };
        batch.function_call("init", args, NearToken::from_yoctonear(0), gas_init).then(
            Self::ext(env::current_account_id()).with_static_gas(GAS_CALLBACK).on_create(
                owner,
                account,
                U128(full_deposit.as_yoctonear()),
            ),
        )
    }

    #[private]
    pub fn on_create(&mut self, owner: AccountId, account: AccountId, deposit: U128) -> Option<AccountId> {
        let ok = near_sdk::is_promise_success();
        let ev = if ok { "account_created" } else { "create_failed" };
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"{ev}\",\"data\":{{\"owner\":\"{owner}\",\"account\":\"{account}\"}}}}"
        ));
        if ok {
            return Some(account);
        }
        self.created.remove(&account);
        Promise::new(owner).transfer(NearToken::from_yoctonear(deposit.0)).detach();
        None
    }

    pub fn account_for(&self, owner: AccountId) -> AccountId {
        let h = env::sha256_array(owner.as_bytes());
        let mut name = String::with_capacity(17 + 64);
        for b in &h[..8] {
            name.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            name.push(char::from_digit((b & 15) as u32, 16).unwrap_or('0'));
        }
        name.push('.');
        name.push_str(env::current_account_id().as_str());
        name.parse().unwrap_or_else(|_| env::panic_str("E_ACCOUNT_ID"))
    }

    /// 0.2 NEAR + 0.5 NEAR per DCL-kind allowlisted DEX (v1.2).
    pub fn min_funding(&self) -> NearToken {
        let n = self.dex_allowlist.iter().filter(|d| matches!(d.kind, DexKind::RheaDcl)).count() as u128;
        MIN_FUNDING.saturating_add(DCL_REGISTRATION.saturating_mul(n))
    }

    pub fn get_config(&self) -> FactoryConfig {
        FactoryConfig {
            admin: self.admin.clone(),
            code_hash: self.code_hash,
            fee_config: self.fee_config.clone(),
            dex_allowlist: self.dex_allowlist.clone(),
            wrap: self.wrap.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn factory_at(id: &str) -> Factory {
        testing_env!(VMContextBuilder::new().current_account_id(id.parse().unwrap()).build());
        Factory::new(
            "admin.near".parse().unwrap(),
            [7u8; 32].into(),
            FeeConfig { fee_bps: 100, fee_recipient: "fees.near".parse().unwrap() },
            vec![],
            "wrap.near".parse().unwrap(),
        )
    }

    /// v1.4.5 (INV-69): E_ACCOUNT_ID. `account_for` = 16 hex + "." + factory id, always a valid
    /// account id while the factory id is <= 47 chars (64 - 17); any owner id works.
    #[test]
    fn inv69_account_for_valid_up_to_47_char_factory() {
        let f = factory_at(&format!("{}.near", "f".repeat(42))); // 47 chars
        for owner in [
            "a.near",
            "owner.near",
            &"9".repeat(64),
            "x.y.z.tg",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let a = f.account_for(owner.parse().unwrap());
            assert_eq!(a.as_str().len(), 17 + 47);
        }
    }

    /// A factory account id of 48+ chars makes every name too long: E_ACCOUNT_ID (a deploy-config
    /// condition, checked by contracts/scripts/check-factory.sh's pinned factory id in practice).
    #[test]
    fn inv69_account_for_rejects_overlong_factory_id() {
        let f = factory_at(&format!("{}.near", "f".repeat(43))); // 48 chars
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.account_for("a.near".parse().unwrap())
        }));
        let e = r.expect_err("expected E_ACCOUNT_ID");
        let m = e.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(m.contains("E_ACCOUNT_ID"), "{m}");
    }
}
