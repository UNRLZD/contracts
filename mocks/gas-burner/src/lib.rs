//! TEST ONLY (audit fix 1): a hostile "token" whose ft_transfer_call / ft_transfer burn
//! (nearly) all attached gas and report nothing used. Also accepts storage deposits (keeps them).
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId};

#[near(contract_state)]
#[derive(Default)]
pub struct Burner {}

fn burn() {
    let mut h = [0u8; 32];
    while env::used_gas().as_gas() < env::prepaid_gas().as_gas() / 10 * 9 {
        h = env::sha256_array(h);
    }
}

#[near]
impl Burner {
    #[payable]
    pub fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, msg: String) -> U128 {
        let _ = (receiver_id, amount, msg);
        burn();
        U128(0)
    }
    /// Also a BROKEN token for the v1.3.2 withdraw tests: reports a balance, but every
    /// transfer burns the attached gas and then fails.
    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
        let _ = (receiver_id, amount);
        burn();
        env::panic_str("broken token");
    }
    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        let _ = account_id;
        U128(1000)
    }
    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>, registration_only: Option<bool>) {
        let _ = (account_id, registration_only);
    }
}
