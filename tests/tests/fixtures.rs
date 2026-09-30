//! v1.4.8 (UNR-A-07): every legacy wasm the upgrade / migrate tests load is committed under
//! `tests/fixtures/` and matches `tests/fixtures/SHA256SUMS`, so the sandbox suite is
//! reproducible from a clean checkout (no sandbox needed for this check). RED on v1.4.7
//! (no fixtures in the tree).
use sha2::{Digest, Sha256};

#[test]
fn legacy_fixtures_present_and_match_sha256sums() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");
    let sums = std::fs::read_to_string(format!("{dir}/SHA256SUMS")).expect("tests/fixtures/SHA256SUMS");
    let mut n = 0;
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (hex, name) = line.split_once("  ").expect("sha256sum format");
        let code =
            std::fs::read(format!("{dir}/{name}")).unwrap_or_else(|_| panic!("fixture {name} missing"));
        let got: String = Sha256::digest(&code).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, hex, "{name}");
        n += 1;
    }
    // every legacy name the suite loads
    for name in [
        "trading_account_v1_2",
        "trading_account_v1_3_2",
        "trading_account_v1_4_0",
        "trading_account_v1_4_1",
        "trading_account_v1_4_2",
        "trading_account_v1_4_3",
        "trading_account_v1_4_4",
        "factory_v1_2",
        "factory_v1_3_2",
        "factory_v1_4_0",
        "factory_v1_4_1",
        "factory_v1_4_3",
        "factory_v1_4_4",
    ] {
        assert!(sums.contains(&format!("  {name}.wasm")), "{name} not in SHA256SUMS");
    }
    assert_eq!(n, 13);
}
