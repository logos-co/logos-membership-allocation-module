use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use auth_vector::VerifyRegistry;
use auth_vectors::authoriser::{Allowlist, Any, Attestation, PowClaim};
use auth_vectors::scheme::{Eth, Keycard, Lez, Logos, Peer};
use membership_allocation_action::{
    self as action, commitment_refusal, Grant, ACTION_KIND, AUTH_DOMAIN, CODEC, COMMITMENT_LEN,
};
use paymaster_service::{Configured, Denial, Engine, ExecError, ServeState, Service};
use paymaster_wire::canonical_account;
use serde_json::{json, Value};

use crate::lp;

pub(crate) const REGISTRY_MODULE: &str = "rln_lez_module";

const REGISTER_TIMEOUT_MS: i32 = 190_000;
const CONFIRM_POLL_S: u64 = 2;
const GET_MEMBERSHIP_TIMEOUT_MS: i32 = 30_000;
const DEFAULT_MAX_RATE: u64 = 100;

#[derive(Debug)]
struct RegistryCfg {
    max_rate_limit: u64,
}

pub(crate) struct ServerCfg {
    default_config: String,
    registries: HashMap<String, RegistryCfg>,
}

impl ServerCfg {
    fn resolve_registry(&self, requested: Option<&str>) -> Result<(String, u64), String> {
        let registry = match requested.map(str::trim).filter(|s| !s.is_empty()) {
            Some(r) => canonical_account(r).map_err(|e| format!("registry: {e}"))?,
            None => self.default_config.clone(),
        };
        match self.registries.get(&registry) {
            Some(r) => Ok((registry, r.max_rate_limit)),
            None => Err(format!("registry not served: {registry}")),
        }
    }
}

fn parse_registries(
    a: &Value,
    default_config: &str,
    global_cap: u64,
) -> Result<(HashMap<String, RegistryCfg>, Vec<String>), String> {
    let mut map = HashMap::new();
    let mut order = Vec::new();
    let mut add = |config: &str, cap: u64| -> Result<(), String> {
        let key = canonical_account(config).map_err(|e| format!("registries: {e}"))?;
        if map
            .insert(
                key.clone(),
                RegistryCfg {
                    max_rate_limit: cap,
                },
            )
            .is_some()
        {
            return Err(format!("registries: {key} is listed twice"));
        }
        order.push(key);
        Ok(())
    };
    add(default_config, global_cap)?;
    match a.get("registries") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                match item {
                    Value::String(s) => add(s, global_cap)?,
                    Value::Object(o) => {
                        let config = o
                            .get("config")
                            .and_then(Value::as_str)
                            .ok_or("registries: an object entry needs a config")?;
                        let cap = match o.get("maxRateLimit") {
                            None | Some(Value::Null) => global_cap,
                            Some(v) => v
                                .as_u64()
                                .ok_or("registries: maxRateLimit must be an unsigned integer")?,
                        };
                        add(config, cap)?;
                    }
                    _ => return Err(
                        r#"registries must be an array of "<config>" | {config, maxRateLimit?}"#
                            .into(),
                    ),
                }
            }
        }
        Some(_) => {
            return Err(
                r#"registries must be an array of "<config>" | {config, maxRateLimit?}"#.into(),
            )
        }
    }
    Ok((map, order))
}

pub(crate) struct Registration {
    commitment: [u8; COMMITMENT_LEN],
    rate_limit: Option<u64>,
}

pub(crate) struct Job {
    registry: String,
    rate: u64,
}

pub(crate) struct Membership;

impl Service for Membership {
    type Cfg = ServerCfg;
    type Body = Registration;
    type Job = Job;
    type Grant = Grant;

    const NAME: &'static str = "membership_allocation";
    const CODEC: &'static str = CODEC;
    const DOMAIN: &'static str = AUTH_DOMAIN;
    const ACTION_KIND: &'static str = ACTION_KIND;

    fn configure(&self, a: &Value) -> Result<Configured<ServerCfg>, String> {
        let config = a
            .get("config")
            .and_then(Value::as_str)
            .ok_or("missing config")?;
        let max_rate_limit = a
            .get("maxRateLimit")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_MAX_RATE);
        let (registries, served) = parse_registries(a, config, max_rate_limit)?;
        let reply = json!({ "registries": served });
        let default_config = served[0].clone();
        Ok(Configured {
            cfg: ServerCfg {
                default_config,
                registries,
            },
            scopes: served,
            reply,
        })
    }

    fn parse(&self, bytes: &[u8]) -> Result<Registration, String> {
        let (commitment, rate_limit) = action::split(bytes)?;
        Ok(Registration {
            commitment: *commitment,
            rate_limit,
        })
    }

    fn precheck(&self, reg: &Registration) -> Result<(), String> {
        match commitment_refusal(&reg.commitment) {
            Some(why) => Err(why.to_string()),
            None => Ok(()),
        }
    }

    fn admit(
        &self,
        cfg: &ServerCfg,
        scope: Option<&str>,
        reg: &Registration,
    ) -> Result<Job, Denial> {
        let (registry, max_rate_limit) = cfg.resolve_registry(scope).map_err(Denial::scope)?;
        let rate = reg
            .rate_limit
            .unwrap_or(DEFAULT_MAX_RATE)
            .min(max_rate_limit);
        Ok(Job { registry, rate })
    }

    fn scope<'a>(&self, job: &'a Job) -> &'a str {
        &job.registry
    }

    fn settled(&self, _cfg: &ServerCfg, reg: &Registration, job: &Job) -> Option<Grant> {
        registered_membership(&job.registry, &reg.commitment)
    }

    fn execute(
        &self,
        _cfg: &ServerCfg,
        reg: &Registration,
        job: &Job,
        confirm_budget_s: u64,
    ) -> Result<Grant, ExecError> {
        register(&job.registry, &reg.commitment, job.rate, confirm_budget_s)
    }

    fn encode_grant(&self, grant: &Grant) -> Vec<u8> {
        grant.encode()
    }
}

fn vectors() -> VerifyRegistry {
    VerifyRegistry::new()
        .scheme(Eth)
        .scheme(Lez)
        .scheme(Logos)
        .scheme(Keycard)
        .scheme(Peer)
        .authoriser(Allowlist)
        .authoriser(Any)
        .authoriser(Attestation)
        .authoriser(PowClaim)
}

fn engine() -> Engine<Membership> {
    Engine::with_vectors(Membership, vectors())
}

static ENGINE: LazyLock<Arc<Engine<Membership>>> = LazyLock::new(|| Arc::new(engine()));

pub fn serve(state: &mut ServeState, args_json: &str) -> Result<Value, String> {
    ENGINE.serve(state, args_json)
}

fn registered_membership(registry: &str, id_commitment: &[u8]) -> Option<Grant> {
    let m = lp::call_module_json(
        REGISTRY_MODULE,
        "get_membership",
        &json!([registry, hex::encode(id_commitment)]),
        GET_MEMBERSHIP_TIMEOUT_MS,
    )
    .ok()?;
    Some(Grant {
        leaf_index: confirmed_leaf(&m)?,
        tx_hash: String::new(),
        registry: registry.to_string(),
    })
}

fn refusal(reply: &Value) -> Option<&str> {
    reply.get("error").and_then(Value::as_str)
}

fn confirmed_leaf(reply: &Value) -> Option<u64> {
    if reply.get("registered").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    match reply.get("state").and_then(Value::as_str) {
        Some("active") | Some("grace_period") => {}
        _ => return None,
    }
    reply.get("leaf_index").and_then(Value::as_u64)
}

const REGISTRY_MODULE_PAYER: &str = "";

fn register(
    registry: &str,
    id_commitment: &[u8],
    rate: u64,
    confirm_budget_s: u64,
) -> Result<Grant, ExecError> {
    let idc_hex = hex::encode(id_commitment);
    let reply = lp::call_module_json_classified(
        REGISTRY_MODULE,
        "register_member",
        &json!([registry, REGISTRY_MODULE_PAYER, idc_hex, rate]),
        REGISTER_TIMEOUT_MS,
    )
    .map_err(|e| match e {
        lp::CallError::Failed(m) => ExecError::NotSubmitted(m),
        lp::CallError::Unanswered(m) => ExecError::Unconfirmed(format!("{m}; it may still land")),
    })?;
    if let Some(why) = refusal(&reply) {
        return Err(ExecError::NotSubmitted(format!(
            "register_member refused: {why}"
        )));
    }
    if reply.get("already_registered").and_then(Value::as_bool) == Some(true) {
        let m = lp::call_module_json(
            REGISTRY_MODULE,
            "get_membership",
            &json!([registry, idc_hex]),
            GET_MEMBERSHIP_TIMEOUT_MS,
        )
        .map_err(ExecError::NotSubmitted)?;
        return match confirmed_leaf(&m) {
            Some(leaf_index) => Ok(Grant {
                leaf_index,
                tx_hash: String::new(),
                registry: registry.to_string(),
            }),
            None => Err(ExecError::NotSubmitted(format!(
                "commitment already registered on {registry} with a membership in state {}",
                m.get("state").and_then(Value::as_str).unwrap_or("unknown")
            ))),
        };
    }

    let mut tx_hash_bytes = Vec::new();
    if let Some(tx_result) = reply.get("tx_result").and_then(Value::as_str) {
        if let Ok(inner) = serde_json::from_str::<Value>(tx_result) {
            if let Some(txh) = inner.get("tx_hash").and_then(Value::as_str) {
                tx_hash_bytes = hex::decode(txh.trim_start_matches("0x")).unwrap_or_default();
            }
        }
    }

    let deadline = lp::now_s() + confirm_budget_s;
    loop {
        if let Ok(m) = lp::call_module_json(
            REGISTRY_MODULE,
            "get_membership",
            &json!([registry, idc_hex]),
            GET_MEMBERSHIP_TIMEOUT_MS,
        ) {
            if let Some(leaf_index) = confirmed_leaf(&m) {
                return Ok(Grant {
                    leaf_index,
                    tx_hash: hex::encode(&tx_hash_bytes),
                    registry: registry.to_string(),
                });
            }
        }
        if lp::now_s() >= deadline {
            return Err(ExecError::Unconfirmed(format!(
                "registration submitted (tx {}) but not on chain within {confirm_budget_s}s; it may still land",
                hex::encode(&tx_hash_bytes)
            )));
        }
        lp::sleep_s(CONFIRM_POLL_S);
    }
}

#[cfg(test)]
mod tests {
    use paymaster_service::{nullifiers, DEFAULT_CONFIRM_BUDGET_S};
    use paymaster_wire::envelope::{SponsorRequest, SponsorResponse, Status};

    use super::*;

    fn acct(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn fresh() -> Arc<Engine<Membership>> {
        Arc::new(engine())
    }

    fn serve_on(e: &Arc<Engine<Membership>>, args_json: &str) -> Result<Value, String> {
        e.serve(&mut ServeState::default(), args_json)
    }

    fn serve(args_json: &str) -> Result<Value, String> {
        serve_on(&fresh(), args_json)
    }

    fn handle(e: &Engine<Membership>, buf: &[u8], peer_id: Option<&str>) -> SponsorResponse {
        SponsorResponse::decode(&e.handle_request(buf, peer_id)).unwrap()
    }

    fn commitment() -> [u8; COMMITMENT_LEN] {
        let mut idc = [0xab; COMMITMENT_LEN];
        idc[COMMITMENT_LEN - 1] = 0x0a;
        idc
    }

    fn registration(request_id: &str, auth_type: &str, registry: Option<String>) -> SponsorRequest {
        SponsorRequest {
            request_id: request_id.into(),
            authentication_type: auth_type.as_bytes().to_vec(),
            authentication_payload: Vec::new(),
            action_kind: ACTION_KIND.into(),
            action: action::encode(&commitment(), None),
            scope: registry,
        }
    }

    fn granted(resp: &SponsorResponse) -> Grant {
        assert_eq!(resp.status, Status::Granted, "{resp:?}");
        Grant::decode(resp.result.as_deref().unwrap()).unwrap()
    }

    fn served(a: &Value) -> ServerCfg {
        let (registries, served) = parse_registries(a, &acct(0xd).to_uppercase(), 100).unwrap();
        ServerCfg {
            default_config: served[0].clone(),
            registries,
        }
    }

    #[test]
    fn registries_are_the_default_plus_each_entry_with_its_own_cap() {
        let (d, m, x) = (acct(0xd), acct(0xab), acct(0xb));
        let m_b58 = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
        let cfg = served(&json!({ "registries": [m_b58, { "config": x, "maxRateLimit": 20 }] }));
        assert_eq!(cfg.resolve_registry(None).unwrap(), (d.clone(), 100));
        assert_eq!(
            cfg.resolve_registry(Some(&format!(" {} ", m.to_uppercase())))
                .unwrap(),
            (m.clone(), 100)
        );
        assert_eq!(cfg.resolve_registry(Some(m_b58)).unwrap(), (m.clone(), 100));
        assert_eq!(cfg.resolve_registry(Some(&x)).unwrap(), (x.clone(), 20));
        assert_eq!(cfg.resolve_registry(Some("")).unwrap().0, d);
        let y = acct(0xc);
        assert_eq!(
            cfg.resolve_registry(Some(&y)).unwrap_err(),
            format!("registry not served: {y}")
        );
        assert!(cfg
            .resolve_registry(Some("nope"))
            .unwrap_err()
            .starts_with("registry: account 'nope'"));
        let (_, order) = parse_registries(&json!({ "registries": [m_b58] }), &d, 1).unwrap();
        assert_eq!(order, [d.clone(), m]);
        let (_, order) = parse_registries(&json!({}), &d, 1).unwrap();
        assert_eq!(order, [d]);
    }

    #[test]
    fn serve_refuses_more_pairs_than_an_advertisement_carries() {
        let regs: Vec<String> = (1..=9u8).map(acct).collect();
        let a = format!(
            r#"{{"config":"{}","registries":{}}}"#,
            regs[0],
            serde_json::to_string(&regs[1..]).unwrap()
        );
        let e = serve(&a).unwrap_err();
        assert!(e.contains("at most 8"), "got: {e}");
    }

    #[test]
    fn malformed_registries_fail_serve() {
        let (d, m) = (acct(0xd), acct(0xa));
        for (a, needle) in [
            (json!({ "registries": [d.to_uppercase()] }), "listed twice"),
            (
                json!({ "registries": [{ "maxRateLimit": 5 }] }),
                "needs a config",
            ),
            (
                json!({ "registries": [{ "config": m, "maxRateLimit": "5" }] }),
                "unsigned integer",
            ),
            (json!({ "registries": [7] }), "must be an array"),
            (json!({ "registries": m }), "must be an array"),
            (json!({ "registries": [" "] }), "account ''"),
        ] {
            let e = parse_registries(&a, &d, 1).unwrap_err();
            assert!(e.contains(needle), "{a}: {e}");
        }
        assert!(parse_registries(&json!({}), "D", 1)
            .unwrap_err()
            .contains("account 'D'"));
        let e = serve(r#"{"config":"c"}"#).unwrap_err();
        assert!(e.contains("account 'c'"), "got: {e}");
    }

    #[test]
    fn an_unserved_registry_is_refused_before_anything_else() {
        let e = fresh();
        let _ = serve_on(
            &e,
            &json!({ "config": acct(0xd), "advertise": false }).to_string(),
        );
        let resp = handle(&e, &registration("r", "", Some(acct(0xe))).encode(), None);
        assert_eq!(resp.status, Status::Refused);
        assert_eq!(resp.code.as_deref(), Some("scope_not_served"));
        assert_eq!(
            resp.message.as_deref(),
            Some(format!("registry not served: {}", acct(0xe)).as_str())
        );
        let mut zero = registration("r", "", None);
        zero.action = action::encode(&[0u8; COMMITMENT_LEN], None);
        let resp = handle(&e, &zero.encode(), None);
        assert_eq!(
            (resp.status, resp.code.as_deref(), resp.message.as_deref()),
            (
                Status::Refused,
                Some("invalid"),
                Some("invalid_commitment: zero")
            )
        );
        let mut short = registration("r", "", None);
        short.action.truncate(10);
        assert_eq!(
            handle(&e, &short.encode(), None).code.as_deref(),
            Some("invalid")
        );
    }

    #[test]
    fn a_refused_registration_is_recognised() {
        let r = json!({"error": "invalid_commitment: not a BN254 field element"});
        assert_eq!(
            refusal(&r),
            Some("invalid_commitment: not a BN254 field element")
        );
        assert_eq!(refusal(&json!({"leaf_index": 3, "pending": true})), None);
    }

    #[test]
    fn only_a_usable_registered_membership_has_a_confirmed_leaf() {
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "active"})),
            Some(7)
        );
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "grace_period"})),
            Some(7)
        );
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "expired"})),
            None
        );
        assert_eq!(
            confirmed_leaf(&json!({"registered": true, "leaf_index": 7})),
            None
        );
        assert_eq!(confirmed_leaf(&json!({"registered": false})), None);
        assert_eq!(confirmed_leaf(&json!({"registered": true})), None);
        assert_eq!(confirmed_leaf(&json!("")), None);
    }

    fn tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "membership-allocation-srv-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    fn vector_serve(store: &str) -> String {
        json!({
            "config": acct(0xd),
            "advertise": false,
            "consumedNullifiersPath": store,
            "authVerifiers": { "t": { "module": "verifier_module" } },
        })
        .to_string()
    }

    fn vector_request(request_id: &str) -> SponsorRequest {
        registration(request_id, "t", None)
    }

    fn failure_text(resp: &SponsorResponse) -> String {
        resp.message.clone().unwrap_or_default()
    }

    const PEER: &str = "12D3KooWA1yXQfKD3c8QznGkpf1ZepPH1FQKwAwMxbTh1feQsapZ";
    const OTHER_PEER: &str = "16Uiu2HAkyiMKmjcAj4FS5jot1jMZB73mnY3wJnSTKZmTBhrFJEaT";

    #[test]
    fn the_built_in_vectors_are_the_twelve_compositions() {
        assert_eq!(
            vectors().auth_types(),
            [
                "eth-allowlist",
                "eth-any",
                "lez-allowlist",
                "lez-any",
                "logos-allowlist",
                "logos-any",
                "logos-pow-claim",
                "keycard-allowlist",
                "keycard-any",
                "keycard-attestation",
                "peer-allowlist",
                "peer-any",
            ]
        );
    }

    #[test]
    fn a_built_in_vector_is_verified_without_a_verifier_module() {
        let store = tmp("built-in");
        let e = fresh();
        lp::fake::install(Box::new(|_, method, _| match method {
            "register_member" => Ok(json!({ "leaf_index": 3 })),
            "get_membership" => {
                Ok(json!({ "registered": true, "state": "active", "leaf_index": 3 }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let args = json!({
            "config": acct(0xd),
            "advertise": false,
            "consumedNullifiersPath": store,
            "authVerifiers": {
                "peer-any": {},
                "peer-allowlist": { "config": { "allowlist": [PEER] } },
            },
        });
        assert_eq!(
            serve_on(&e, &args.to_string()).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let any = registration("r1", "peer-any", None).encode();
        assert_eq!(granted(&handle(&e, &any, Some(PEER))).leaf_index, 3);
        let listed = registration("r2", "peer-allowlist", None).encode();
        let off_the_list = handle(&e, &listed, Some(OTHER_PEER));
        assert_eq!(off_the_list.status, Status::Refused);
        let why = failure_text(&off_the_list);
        assert!(why.starts_with("peer not allowlisted: "), "{why}");
        granted(&handle(&e, &listed, Some(PEER)));
        assert!(
            !lp::fake::methods().contains(&auth_vector::VERIFY_METHOD.to_string()),
            "{:?}",
            lp::fake::methods()
        );

        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn serve_refuses_an_entry_without_a_module_it_cannot_verify_or_configure() {
        for (verifiers, needle) in [
            (
                json!({ "keycard-pow-claim": {} }),
                "authVerifiers['keycard-pow-claim'] needs a module",
            ),
            (
                json!({ "eth-allowlist": {} }),
                "authVerifiers['eth-allowlist']: config.allowlist",
            ),
        ] {
            let args =
                json!({ "config": acct(0xd), "advertise": false, "authVerifiers": verifiers });
            let err = serve(&args.to_string()).unwrap_err();
            assert!(err.contains(needle), "{args}: {err}");
        }
    }

    #[test]
    fn a_reservation_made_after_a_re_serve_lands_in_the_new_store_file() {
        let (old, new) = (tmp("reserve-old"), tmp("reserve-new"));
        let re_serve = vector_serve(&new);
        let e = fresh();
        let e2 = Arc::clone(&e);
        lp::fake::install(Box::new(move |_, method, _| match method {
            auth_vector::VERIFY_METHOD => {
                let _ = serve_on(&e2, &re_serve);
                Ok(json!({ "ok": true, "nullifier": " AA " }))
            }
            "register_member" => Ok(json!({ "leaf_index": 3 })),
            "get_membership" => {
                Ok(json!({ "registered": true, "state": "active", "leaf_index": 3 }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve_on(&e, &vector_serve(&old)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let resp = handle(&e, &vector_request("r1").encode(), Some("peer"));
        granted(&resp);
        let nul = auth_vector::namespaced_nullifier(&acct(0xd), "t", "aa");
        assert!(
            nullifiers::load_nullifiers(&new).unwrap().contains(&nul),
            "the reservation is in the file serve named last"
        );
        assert!(!nullifiers::load_nullifiers(&old).unwrap().contains(&nul));

        lp::fake::clear();
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn a_release_after_a_re_serve_takes_the_line_out_of_the_new_store_file() {
        let (old, new) = (tmp("release-old"), tmp("release-new"));
        let re_serve = vector_serve(&new);
        let e = fresh();
        let e2 = Arc::clone(&e);
        lp::fake::install(Box::new(move |_, method, _| match method {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "bb" })),
            "register_member" => {
                let _ = serve_on(&e2, &re_serve);
                Ok(json!({ "error": "full: the registry is full" }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve_on(&e, &vector_serve(&old)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let refused = "register_member refused: full: the registry is full";
        let resp = handle(&e, &vector_request("r2").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);
        let nul = auth_vector::namespaced_nullifier(&acct(0xd), "t", "bb");
        assert!(
            !nullifiers::load_nullifiers(&new).unwrap().contains(&nul),
            "the release rewrote the file serve named last"
        );
        let resp = handle(&e, &vector_request("r3").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);

        lp::fake::clear();
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn a_registration_is_paid_by_the_registry_modules_own_payer() {
        let store = tmp("module-payer");
        let e = fresh();
        lp::fake::install(Box::new(|_, method, _| match method {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "ee" })),
            "register_member" => Ok(json!({ "leaf_index": 3 })),
            "get_membership" => {
                Ok(json!({ "registered": true, "state": "active", "leaf_index": 3 }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve_on(&e, &vector_serve(&store)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let resp = handle(&e, &vector_request("r6").encode(), Some("peer"));
        granted(&resp);
        let payers: Vec<Value> = lp::fake::calls()
            .into_iter()
            .filter(|(m, _)| m == "register_member")
            .map(|(_, mut args)| args[1].take())
            .collect();
        assert_eq!(payers, [json!("")]);

        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn an_unconfirmed_registration_is_answered_after_the_configured_budget() {
        let store = tmp("confirm-budget");
        let e = fresh();
        lp::fake::install(Box::new(|_, method, _| match method {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "ff" })),
            "register_member" => Ok(json!({ "leaf_index": 3 })),
            "get_membership" => Ok(json!({ "registered": false })),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let args = json!({
            "config": acct(0xd),
            "advertise": false,
            "consumedNullifiersPath": store,
            "confirmBudgetSec": 7,
            "authVerifiers": { "t": { "module": "verifier_module" } },
        })
        .to_string();
        assert_eq!(
            serve_on(&e, &args).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let start = lp::now_s();
        let resp = handle(&e, &vector_request("r7").encode(), Some("peer"));
        assert_eq!(
            failure_text(&resp),
            "registration submitted (tx ) but not on chain within 7s; it may still land"
        );
        let waited = lp::now_s() - start;
        assert!(
            (7..DEFAULT_CONFIRM_BUDGET_S).contains(&waited),
            "waited {waited}s"
        );
        let nul = auth_vector::namespaced_nullifier(&acct(0xd), "t", "ff");
        assert!(nullifiers::load_nullifiers(&store).unwrap().contains(&nul));

        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn serve_rejects_a_confirm_budget_that_is_not_a_positive_integer() {
        for bad in [json!(0), json!("150"), json!(-5), json!(1.5)] {
            let args = json!({ "config": acct(1), "confirmBudgetSec": bad }).to_string();
            let e = serve(&args).unwrap_err();
            assert!(e.contains("confirmBudgetSec"), "{bad}: {e}");
        }
    }

    fn lez_call_error(code: &str, message: &str) -> String {
        json!({ "code": code, "message": message, "origin": REGISTRY_MODULE }).to_string()
    }

    const REGISTER_TIMED_OUT: &str =
        "call to 'rln_lez_module.register_member' timed out after 190000ms";
    const LEZ_NOT_LOADED: &str = "replica for 'rln_lez_module' is gone";

    #[test]
    fn a_register_member_timeout_keeps_the_reservation() {
        let store = tmp("register-timeout");
        let e = fresh();
        lp::fake::install(Box::new(|_, method, _| match method {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "cc" })),
            "register_member" => Err(lez_call_error("timeout", REGISTER_TIMED_OUT)),
            "get_membership" => Ok(json!({ "registered": false })),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve_on(&e, &vector_serve(&store)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let resp = handle(&e, &vector_request("r4").encode(), Some("peer"));
        let nul = auth_vector::namespaced_nullifier(&acct(0xd), "t", "cc");
        assert!(
            nullifiers::load_nullifiers(&store).unwrap().contains(&nul),
            "the reservation stays in the store file"
        );
        assert_eq!(resp.status, Status::Unconfirmed);
        assert_eq!(
            failure_text(&resp),
            format!(
                "{}; it may still land",
                lez_call_error("timeout", REGISTER_TIMED_OUT)
            )
        );
        let resp = handle(&e, &vector_request("r5").encode(), Some("peer"));
        assert_eq!(
            failure_text(&resp),
            format!("credential already used: {nul}")
        );
        let registers = lp::fake::methods()
            .into_iter()
            .filter(|m| m == "register_member")
            .count();
        assert_eq!(registers, 1);

        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn a_register_member_call_the_module_never_ran_releases_the_reservation() {
        let store = tmp("register-not-run");
        let e = fresh();
        lp::fake::install(Box::new(|_, method, _| match method {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "dd" })),
            "register_member" => Err(lez_call_error("object_unavailable", LEZ_NOT_LOADED)),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            serve_on(&e, &vector_serve(&store)).unwrap_err(),
            "mountProtocol: refused in test"
        );

        let refused = lez_call_error("object_unavailable", LEZ_NOT_LOADED);
        let resp = handle(&e, &vector_request("r6").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);
        let nul = auth_vector::namespaced_nullifier(&acct(0xd), "t", "dd");
        assert!(!nullifiers::load_nullifiers(&store).unwrap().contains(&nul));
        let resp = handle(&e, &vector_request("r7").encode(), Some("peer"));
        assert_eq!(failure_text(&resp), refused);

        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }
}
