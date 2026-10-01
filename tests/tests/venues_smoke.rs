//! v1.6 venue harness smoke: a directly deployed trading account accepts the new DexKind
//! entries and refuses a curve op on a venue that is not allowlisted.
mod venues_common;
use anyhow::Result;
use integration_tests::*;
use serde_json::json;
use venues_common::*;

#[tokio::test]
async fn venues_harness_smoke() -> Result<()> {
    let e = venv().await?;
    let t = e
        .ta(
            "smoke",
            5 * NEAR,
            (2 * NEAR, 4 * NEAR),
            vec![json!({"id": "nearrr-fun.near", "kind": {"FactoryCurve": "Nearrr"}})],
        )
        .await?;
    let cfg: serde_json::Value = e.worker.view(&t.id, "get_config").await?.json()?;
    assert_eq!(cfg["dex_allowlist"][0]["kind"]["FactoryCurve"], "Nearrr");
    let op = json!([{"CurveBuy": {"venue": "dragonpad.near", "market": "x.dragonpad.near", "amount": NEAR.to_string(),
        "min_out": "1", "gas": (100 * TGAS).to_string()}}]);
    let r = e.exec(&t, op, "s1", NEAR).await?;
    fails_with(&r, "E_BAD_DEX");
    Ok(())
}
