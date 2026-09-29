//! contracts/scripts/check-factory.sh <factory> <expected.json> [hash] against live sandbox factories
//! (v1.4.4; v1.4.5 RA4-2: pinned
//! admin / wrap / allowlist / factory code, required account hash). Every negative case must
//! fail closed (exit 1).
use integration_tests::*;
use serde_json::{json, Value};

fn check(rpc: &str, args: &[&str], env_admin: Option<&str>) -> (bool, String) {
    // NT_CHECK_FACTORY: another copy of the script (red run against an older commit)
    let script = std::env::var("NT_CHECK_FACTORY")
        .unwrap_or_else(|_| format!("{}/../scripts/check-factory.sh", env!("CARGO_MANIFEST_DIR")));
    let mut c = std::process::Command::new("sh");
    c.arg(script)
        .args(args)
        .env("RPC", rpc)
        .env("FINALITY", "optimistic")
        .env_remove("EXPECTED_ADMIN")
        .env_remove("FACTORY_CONFIG_JSON");
    if let Some(a) = env_admin {
        c.env("EXPECTED_ADMIN", a);
    }
    let o = c.output().unwrap();
    (
        o.status.success(),
        format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
    )
}

fn write(dir: &std::path::Path, name: &str, v: &Value) -> String {
    let p = dir.join(name);
    std::fs::write(&p, v.to_string()).unwrap();
    p.to_string_lossy().into_owned()
}

#[tokio::test]
async fn v145_factory_check_script_fails_closed() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let rpc = env.worker.rpc_addr();
    let dir = std::env::temp_dir().join(format!("nt-fc-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let allow = json!([{"id": env.rhea.id(), "kind": "RheaClassic"}, {"id": env.dcl.id(), "kind": "RheaDcl"},
        {"id": env.plach.id(), "kind": "Plach"}]);
    let good = json!({"admin": env.admin.id(), "fee_recipient": env.fees.id(), "fee_bps": FEE_BPS, "wrap": env.wrap.id(),
        "dex_allowlist": allow, "max_fee_bps": 100, "factory_code_hash": code_hash(&out("factory")),
        "account_code_hash": env.code_hash});
    let with = |k: &str, v: Value| {
        let mut e = good.clone();
        e[k] = v;
        e
    };
    let f = env.factory.id().to_string();
    let h = env.code_hash.clone();
    let ok_file = write(&dir, "good.json", &good);
    // positive
    let (ok1, o) = check(&rpc, &[&f, &ok_file, &h], None);
    println!("{o}");
    assert!(ok1, "standard factory must pass: {o}");
    // negatives: (name, args, EXPECTED_ADMIN, expected message)
    let bad_admin = write(&dir, "admin.json", &with("admin", json!("evil.test.near")));
    let no_admin = write(&dir, "noadmin.json", &with("admin", json!("")));
    let bad_wrap = write(&dir, "wrap.json", &with("wrap", json!("evilwrap.test.near")));
    let bad_allow = write(
        &dir,
        "allow.json",
        &with(
            "dex_allowlist",
            json!([{"id": "evil.test.near", "kind": "RheaClassic"}, {"id": env.dcl.id(), "kind": "RheaDcl"}, {"id": env.plach.id(), "kind": "Plach"}]),
        ),
    );
    let bad_fcode =
        write(&dir, "fcode.json", &with("factory_code_hash", json!("11111111111111111111111111111111")));
    let missing = dir.join("missing.json").to_string_lossy().into_owned();
    // v1.4.6 (RA5-3): fee recipient, exact fee_bps and a pinned account hash
    let bad_rcpt = write(&dir, "rcpt.json", &with("fee_recipient", json!("evil.test.near")));
    let no_rcpt = write(&dir, "norcpt.json", &with("fee_recipient", json!("")));
    let bad_bps = write(&dir, "bps.json", &with("fee_bps", json!(0)));
    // v1.4.6 (RA6-5): fee_bps must be a JSON integer: "100" (string) and 100.9 fail
    let str_bps = write(&dir, "bpsstr.json", &with("fee_bps", json!(FEE_BPS.to_string())));
    let float_bps = write(&dir, "bpsfloat.json", &with("fee_bps", json!(FEE_BPS as f64 + 0.9)));
    let no_pin = write(&dir, "nopin.json", &with("account_code_hash", json!("")));
    let other_pin =
        write(&dir, "otherpin.json", &with("account_code_hash", json!("11111111111111111111111111111111")));
    let cases: Vec<(&str, Vec<&str>, Option<&str>, &str)> = vec![
        ("missing expected-file argument", vec![&f], None, "missing <expected.json>"),
        ("fee_recipient differs", vec![&f, &bad_rcpt, "-"], None, "fee_recipient"),
        ("fee_recipient not pinned", vec![&f, &no_rcpt, "-"], None, "fee_recipient"),
        ("fee_bps differs", vec![&f, &bad_bps, "-"], None, "fee_bps"),
        ("fee_bps as a string", vec![&f, &str_bps, "-"], None, "fee_bps"),
        ("fee_bps as a float", vec![&f, &float_bps, "-"], None, "fee_bps"),
        ("account hash not pinned", vec![&f, &no_pin, "-"], None, "not pinned"),
        // get_config's own hash as the argument can't pass when the pin differs
        ("argument = get_config's hash, pin differs", vec![&f, &other_pin, &h], None, "pinned"),
        (
            "wrong account hash",
            vec![&f, &ok_file, "11111111111111111111111111111111"], // argument != pin
            None,
            "account code_hash",
        ),
        ("wrong admin", vec![&f, &bad_admin, &h], None, "admin"),
        ("empty admin", vec![&f, &no_admin, &h], None, "expected admin not set"),
        ("EXPECTED_ADMIN overrides", vec![&f, &ok_file, &h], Some("evil.test.near"), "admin"),
        ("wrong wrap", vec![&f, &bad_wrap, &h], None, "wrap"),
        ("wrong allowlist", vec![&f, &bad_allow, &h], None, "dex_allowlist"),
        ("factory code != audited", vec![&f, &bad_fcode, &h], None, "factory code"),
        ("missing expected file", vec![&f, &missing, &h], None, "expected-values file not found"),
    ];
    for (name, args, admin, msg) in cases {
        let (ok, o) = check(&rpc, &args, admin);
        println!("-- {name}: exit {}\n{o}", if ok { 0 } else { 1 });
        assert!(!ok && o.contains(msg), "{name}: {o}");
    }
    // a factory with two DCL-kind entries
    let f2 = sub(&env.root, "tt2", 50 * NEAR).await?.deploy(&out("factory")).await?.into_result()?;
    let allow2 = json!([{"id": env.dcl.id(), "kind": "RheaDcl"}, {"id": env.plach.id(), "kind": "RheaDcl"}]);
    ok(f2
        .call("new")
        .args_json(json!({"admin": env.admin.id(), "code_hash": h,
            "fee_config": {"fee_bps": FEE_BPS, "fee_recipient": env.fees.id()}, "dex_allowlist": allow2, "wrap": env.wrap.id()}))
        .transact()
        .await?)?;
    let two = write(&dir, "two.json", &with("dex_allowlist", allow2));
    let (ok2, o) = check(&rpc, &[f2.id().as_str(), &two, &h], None);
    println!("-- two DCL\n{o}");
    assert!(!ok2 && o.contains("2 RheaDcl"), "{o}");
    // a different factory binary with the right config (code hash of the factory itself)
    let f3 = sub(&env.root, "tt3", 50 * NEAR).await?.deploy(&out("factory_v1_4_1")).await?.into_result()?;
    ok(f3
        .call("new")
        .args_json(json!({"admin": env.admin.id(), "code_hash": h,
            "fee_config": {"fee_bps": FEE_BPS, "fee_recipient": env.fees.id()}, "dex_allowlist": allow, "wrap": env.wrap.id()}))
        .transact()
        .await?)?;
    let (ok3, o) = check(&rpc, &[f3.id().as_str(), &ok_file, &h], None);
    println!("-- other factory binary\n{o}");
    assert!(!ok3 && o.contains("factory code"), "{o}");
    // a factory id of 48 chars: every account name would exceed 64 (E_ACCOUNT_ID)
    let long =
        sub(&env.root, &"f".repeat(38), 50 * NEAR).await?.deploy(&out("factory")).await?.into_result()?;
    ok(long
        .call("new")
        .args_json(json!({"admin": env.admin.id(), "code_hash": h,
            "fee_config": {"fee_bps": FEE_BPS, "fee_recipient": env.fees.id()}, "dex_allowlist": allow, "wrap": env.wrap.id()}))
        .transact()
        .await?)?;
    let (ok4, o) = check(&rpc, &[long.id().as_str(), &ok_file, &h], None);
    println!("-- 48-char factory id\n{o}");
    assert!(!ok4 && o.contains("max 47"), "{o}");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
