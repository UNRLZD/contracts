//! TEST ONLY: the slice of Plach (dex.intear.near) needed for the stuck-output scenario:
//! NEP-141 deposits credit an inner balance (msg = account to credit, simulating output
//! re-credited after a failed Withdraw), and `withdraw` has Plach's exact signature.
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue};

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub enum DirectWithdrawAmount {
    Full { at_least: Option<U128> },
    Exact(U128),
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockPlach {
    balances: LookupMap<String, u128>, // "<account>|<asset_id>"
}

#[near]
impl MockPlach {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b") }
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let who = if msg.is_empty() { sender_id.to_string() } else { msg };
        let key = format!("{who}|nep141:{}", env::predecessor_account_id());
        let b = self.balances.get(&key).copied().unwrap_or(0);
        self.balances.insert(key, b + amount.0);
        PromiseOrValue::Value(U128(0))
    }

    /// TEST ONLY (v1.4.3 ORDER-001 regression): a HOSTILE `deposit_near` that keeps the NEAR
    /// and reports "0" used (the real Plach returns `()`, and refunds only by failing).
    #[payable]
    pub fn deposit_near(&mut self, operations: Option<near_sdk::serde_json::Value>) -> U128 {
        let _ = operations;
        U128(0)
    }

    pub fn balance_of(&self, account_id: AccountId, asset_id: String) -> U128 {
        U128(self.balances.get(&format!("{account_id}|{asset_id}")).copied().unwrap_or(0))
    }

    #[payable]
    pub fn withdraw(
        &mut self,
        asset_id: String,
        amount: DirectWithdrawAmount,
        withdraw_to: Option<AccountId>,
    ) {
        assert_eq!(env::attached_deposit(), NearToken::from_yoctonear(1), "one yocto");
        let from = env::predecessor_account_id();
        let key = format!("{from}|{asset_id}");
        let bal = self.balances.get(&key).copied().unwrap_or(0);
        let amt = match amount {
            DirectWithdrawAmount::Full { at_least } => {
                assert!(bal >= at_least.map_or(0, |a| a.0), "at_least");
                bal
            }
            DirectWithdrawAmount::Exact(x) => x.0,
        };
        assert!(amt <= bal, "insufficient");
        self.balances.insert(key, bal - amt);
        let token: AccountId = asset_id.strip_prefix("nep141:").expect("nep141 only").parse().unwrap();
        let to = withdraw_to.unwrap_or(from);
        Promise::new(token)
            .function_call(
                "ft_transfer",
                format!("{{\"receiver_id\":\"{to}\",\"amount\":\"{amt}\"}}").into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(10),
            )
            .detach();
    }
}
