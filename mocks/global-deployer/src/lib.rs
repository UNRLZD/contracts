//! TEST ONLY: deploys raw wasm as a NEP-591 global contract (codeHash mode).
//! near-workspaces 0.23 has no DeployGlobalContract action.
use near_sdk::{env, near, Promise};

#[near(contract_state)]
#[derive(Default)]
pub struct Deployer {}

#[near]
impl Deployer {
    pub fn deploy(&mut self, #[serializer(borsh)] code: Vec<u8>) {
        Promise::new(env::current_account_id()).deploy_global_contract(code).detach();
    }
}
