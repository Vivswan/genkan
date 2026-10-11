use super::*;
use serde_json::json;

/// Values differing from the deny baseline only in `hostReverifyMs`.
fn with_reverify(ms: u32) -> PolicyValues {
    PolicyValues {
        host_reverify_ms: Ms::from(ms),
        ..PolicyValues::default()
    }
}

/// Values differing from the deny baseline only in `disabledTools`.
fn with_tools(tools: &[&str]) -> PolicyValues {
    PolicyValues {
        disabled_tools: tools.iter().map(|t| t.to_string()).collect(),
        ..PolicyValues::default()
    }
}

/// `field` at its permissive pole and at its restrictive pole, every other
/// field at the deny baseline, read from the catalogue's declared direction.
fn poles(field: PolicyField) -> (PolicyValues, PolicyValues) {
    let mut lax = PolicyValues::default();
    let mut tight = PolicyValues::default();
    match field.kind() {
        FieldKind::Bool(f) => {
            let grant = f.pole() == BoolPole::TruePermissive;
            *lax.bool_mut(f) = grant;
            *tight.bool_mut(f) = !grant;
        }
        FieldKind::Ms(f) => {
            let (l, t) = match f.order() {
                MsOrder::GrowsPermissive => (Ms::from(2u32), Ms::from(1u32)),
                MsOrder::GrowsPermissiveZeroTop => (Ms::ZERO, Ms::from(1u32)),
            };
            *lax.ms_mut(f) = l;
            *tight.ms_mut(f) = t;
        }
        FieldKind::ToolSet(f) => {
            *lax.tools_mut(f) = Vec::new();
            *tight.tools_mut(f) = vec!["page_eval".into()];
        }
    }
    (lax, tight)
}

#[test]
fn every_field_relaxes_exactly_toward_its_declared_pole() {
    // The direction table is the only owner of what relaxes: a field's
    // permissive pole relaxes its restrictive pole, no other field moves, and
    // the reverse never relaxes, for every catalogue field.
    for field in PolicyField::ALL {
        let (lax, tight) = poles(*field);
        let relaxed: Vec<PolicyField> = PolicyField::ALL
            .iter()
            .copied()
            .filter(|f| field_relaxes(*f, &lax, &tight))
            .collect();
        assert_eq!(
            relaxed,
            vec![*field],
            "{} alone must relax toward its declared permissive pole",
            field.wire_name()
        );
        assert!(
            !relaxes(&tight, &lax) && restricts_or_equal(&tight, &lax),
            "{} must not relax away from its declared permissive pole",
            field.wire_name()
        );
    }
}

#[test]
fn policy_equality_reads_the_tool_list_as_a_set_and_every_other_field_exactly() {
    assert_eq!(with_tools(&["a", "b"]), with_tools(&["b", "a"]));
    assert_eq!(with_tools(&["a", "b"]), with_tools(&["b", "a", "a"]));
    assert_ne!(with_tools(&["a", "b"]), with_tools(&["a"]));
    assert_ne!(with_reverify(0), with_reverify(1));
}

#[test]
fn the_orders_a_naive_comparator_gets_wrong() {
    // hostReverifyMs: 0 = never re-verify = MOST permissive, above every
    // positive interval. disabledTools: a set, where dropping any anchor
    // entry relaxes whatever else the candidate adds, and order or
    // duplicates carry no meaning.
    let anchor_tools = with_tools(&["page_eval", "page_upload"]);
    let cases = [
        (
            "reverify 0 over 60000",
            with_reverify(0),
            with_reverify(60_000),
            true,
        ),
        (
            "reverify 60000 over 0",
            with_reverify(60_000),
            with_reverify(0),
            false,
        ),
        (
            "reverify 60000 over 1000",
            with_reverify(60_000),
            with_reverify(1_000),
            true,
        ),
        (
            "reverify 1000 over 60000",
            with_reverify(1_000),
            with_reverify(60_000),
            false,
        ),
        (
            "same tool set",
            anchor_tools.clone(),
            anchor_tools.clone(),
            false,
        ),
        (
            "tool superset",
            with_tools(&["page_eval", "page_upload", "tab_close"]),
            anchor_tools.clone(),
            false,
        ),
        (
            "reordered tool set with a duplicate",
            with_tools(&["page_upload", "page_eval", "page_eval"]),
            anchor_tools.clone(),
            false,
        ),
        (
            "one tool dropped",
            with_tools(&["page_eval"]),
            anchor_tools.clone(),
            true,
        ),
        (
            "one tool dropped while another is added",
            with_tools(&["page_eval", "tab_close"]),
            anchor_tools.clone(),
            true,
        ),
        (
            "every tool dropped",
            with_tools(&[]),
            anchor_tools.clone(),
            true,
        ),
    ];
    for (name, candidate, anchor, expected) in cases {
        assert_eq!(relaxes(&candidate, &anchor), expected, "{name}");
        assert_eq!(restricts_or_equal(&candidate, &anchor), !expected, "{name}");
    }
}

#[test]
fn serialized_bytes_are_the_signed_wire_contract() {
    // The signature covers these exact bytes and the extension strict-parses
    // them, so key spelling, key order, and value encoding are an external
    // contract: the bytes must never move.
    let values = PolicyValues {
        cdp_mode: true,
        file_upload_enabled: false,
        handle_dialog_enabled: true,
        page_eval_enabled: false,
        confirm_high_risk_click: false,
        confirm_page_eval: true,
        presence_confirm: false,
        confirm_tab_close: true,
        warn_precise_snapshot: false,
        eval_mask: true,
        host_reverify_ms: Ms::from(1u32),
        confirm_grace_ms: Ms::from(2u32),
        click_toast_timeout_ms: Ms::from(3u32),
        eval_toast_timeout_ms: Ms::try_from(JS_SAFE_INT_MAX).unwrap(),
        disabled_tools: vec!["page_eval".into(), "tab_close".into()],
    };
    let fields = concat!(
        r#""cdpMode":true,"#,
        r#""fileUploadEnabled":false,"#,
        r#""handleDialogEnabled":true,"#,
        r#""pageEvalEnabled":false,"#,
        r#""confirmHighRiskClick":false,"#,
        r#""confirmPageEval":true,"#,
        r#""presenceConfirm":false,"#,
        r#""confirmTabClose":true,"#,
        r#""warnPreciseSnapshot":false,"#,
        r#""evalMask":true,"#,
        r#""hostReverifyMs":1,"#,
        r#""confirmGraceMs":2,"#,
        r#""clickToastTimeoutMs":3,"#,
        r#""evalToastTimeoutMs":9007199254740991,"#,
        r#""disabledTools":["page_eval","tab_close"]"#
    );
    assert_eq!(
        serde_json::to_string(&values).unwrap(),
        format!("{{{fields}}}")
    );
    let decoded = serde_json::from_str::<PolicyValues>(&format!("{{{fields}}}")).unwrap();
    assert_eq!(decoded, values);
    // The wire's tool order round-trips as written; policy equality alone reads the list as a set.
    assert_eq!(decoded.disabled_tools, values.disabled_tools);

    let mut overlay = PolicyOverlay::default();
    for field in PolicyField::ALL {
        overlay.set_from(*field, &values);
    }
    assert_eq!(
        serde_json::to_string(&overlay).unwrap(),
        format!("{{{fields}}}")
    );
    assert_eq!(
        serde_json::from_str::<PolicyOverlay>(&format!("{{{fields}}}")).unwrap(),
        overlay
    );
    assert_eq!(
        serde_json::to_string(&PolicyOverlay::default()).unwrap(),
        "{}"
    );

    let doc = PolicyDoc::from_values(
        &values,
        7,
        vec![
            PolicyField::CdpMode,
            PolicyField::EvalToastTimeoutMs,
            PolicyField::DisabledTools,
        ],
    );
    let doc_json = format!(
        r#"{{"v":1,"revision":7,"touched":["cdpMode","evalToastTimeoutMs","disabledTools"],{fields}}}"#
    );
    assert_eq!(serde_json::to_string(&doc).unwrap(), doc_json);
    assert_eq!(serde_json::from_str::<PolicyDoc>(&doc_json).unwrap(), doc);
}

/// The one refusal every bounded integer lane spells.
const BOUND_ERR: &str = "value exceeds the JS-safe integer bound (2^53 - 1)";

/// serde's "expected one of" tail for `names`, as a strict parser spells its refusal.
fn one_of(names: impl IntoIterator<Item = &'static str>) -> String {
    names
        .into_iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The catalogue's wire names in wire order: the field set every strict parser names when it refuses.
fn catalogue_names() -> impl Iterator<Item = &'static str> {
    PolicyField::ALL.iter().map(|f| f.wire_name())
}

fn default_doc_with(key: &str, value: serde_json::Value) -> serde_json::Value {
    let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
    doc[key] = value;
    doc
}

fn default_doc_with_ms(field: MsField, ms: Ms) -> PolicyDoc {
    let mut values = PolicyValues::default();
    *values.ms_mut(field) = ms;
    PolicyDoc::from_values(&values, 0, Vec::new())
}

fn overlay_with_ms(field: MsField, ms: Ms) -> PolicyOverlay {
    let mut overlay = PolicyOverlay::default();
    *overlay.ms_mut(field) = Some(ms);
    overlay
}

/// The document parser is the fail-closed half of the signed contract. The revision and every
/// millisecond field parse only inside the JS-safe bound the generated Zod (`z.int()`) shares, so a
/// value the extension would refuse never signs or stores host-side; a `touched` set names only a
/// catalogue field (`requireEnrollment` is retired, `uiLanguage` is deliberately not a policy field,
/// a case-mangled or empty name is nothing); and an unknown key fails the whole parse.
#[test]
fn document_parse_pins_the_js_safe_bounds_and_refuses_every_unknown_name() {
    type Row = (String, serde_json::Value, Result<PolicyDoc, String>);
    let unknown_variant = |bad: &str| {
        format!(
            "unknown variant `{bad}`, expected one of {}",
            one_of(catalogue_names())
        )
    };
    let unknown_field = |bad: &str| {
        format!(
            "unknown field `{bad}`, expected one of {}",
            one_of(
                ["v", "revision", "touched"]
                    .into_iter()
                    .chain(catalogue_names())
            )
        )
    };
    let mut rows: Vec<Row> = vec![
        (
            "the exact default shape".into(),
            serde_json::to_value(PolicyDoc::default()).unwrap(),
            Ok(PolicyDoc::default()),
        ),
        (
            "revision at 2^53 - 1".into(),
            default_doc_with("revision", json!(JS_SAFE_INT_MAX)),
            Ok(PolicyDoc {
                revision: JS_SAFE_INT_MAX,
                ..PolicyDoc::default()
            }),
        ),
        (
            "revision at 2^53".into(),
            default_doc_with("revision", json!(JS_SAFE_INT_MAX + 1)),
            Err(BOUND_ERR.into()),
        ),
        (
            "an unknown top-level key".into(),
            default_doc_with("surprise", json!(true)),
            Err(unknown_field("surprise")),
        ),
    ];
    for bad in ["requireEnrollment", "uiLanguage", "bogus", "cdpmode", ""] {
        rows.push((
            format!("{bad:?} in touched"),
            default_doc_with("touched", json!(["pageEvalEnabled", bad])),
            Err(unknown_variant(bad)),
        ));
    }
    for field in PolicyField::ALL {
        let FieldKind::Ms(ms) = field.kind() else {
            continue;
        };
        let name = field.wire_name();
        rows.push((
            format!("{name} at 2^53 - 1"),
            default_doc_with(name, json!(JS_SAFE_INT_MAX)),
            Ok(default_doc_with_ms(
                ms,
                Ms::try_from(JS_SAFE_INT_MAX).unwrap(),
            )),
        ));
        rows.push((
            format!("{name} at 2^53"),
            default_doc_with(name, json!(JS_SAFE_INT_MAX + 1)),
            Err(BOUND_ERR.into()),
        ));
    }
    for (label, input, expected) in rows {
        assert_eq!(
            serde_json::from_value::<PolicyDoc>(input).map_err(|e| e.to_string()),
            expected,
            "{label}"
        );
    }
}

/// `validate()` covers the constructed-in-code path the parser never sees: `set_signed` runs it
/// before any presence prompt and the read path refuses a store it could not round-trip. The version
/// must be ours, the revision must fit the JS-safe bound, and `disabledTools` must fit the bounds that
/// keep every valid document under the store's write cap and inside what the comma-joined argv
/// transport (`cli::parse_tool_list` re-splits and trims) can round-trip: a comma inside a name
/// (split in two), surrounding whitespace (trimmed away), or a whitespace-only name (trimmed to
/// empty and dropped) would sign something other than what was written, so each is REFUSED, never
/// mangled.
#[test]
fn validate_pins_the_version_the_revision_bound_and_every_disabled_tools_rule() {
    const SIZE: &str = "a disabledTools entry is empty or longer than 128 bytes";
    const COMMA: &str = "a disabledTools entry contains a comma, which the comma-joined CLI \
                         transport cannot round-trip";
    const SPACE: &str = "a disabledTools entry carries surrounding whitespace, which the CLI \
                         transport's trimming re-split cannot round-trip";
    let tools = |tools: Vec<String>| PolicyDoc {
        disabled_tools: tools,
        ..PolicyDoc::default()
    };
    let one = |name: &str| tools(vec![name.into()]);
    let rows: Vec<(&str, PolicyDoc, Result<(), &str>)> = vec![
        ("the default document", PolicyDoc::default(), Ok(())),
        (
            "revision one past the bound",
            PolicyDoc {
                revision: JS_SAFE_INT_MAX + 1,
                ..PolicyDoc::default()
            },
            Err("revision exceeds the JS-safe integer bound (2^53 - 1)"),
        ),
        (
            "a foreign document version",
            PolicyDoc {
                v: POLICY_DOC_VERSION + 1,
                ..PolicyDoc::default()
            },
            Err("unsupported policy document version"),
        ),
        (
            "ordinary names",
            tools(vec!["page_eval".into(), "tab_close".into()]),
            Ok(()),
        ),
        ("256 entries", tools(vec!["t".into(); 256]), Ok(())),
        (
            "257 entries",
            tools(vec!["t".into(); 257]),
            Err("disabledTools carries more than 256 entries"),
        ),
        ("a 128-byte name", one(&"a".repeat(128)), Ok(())),
        ("a 129-byte name", one(&"a".repeat(129)), Err(SIZE)),
        ("an empty name", one(""), Err(SIZE)),
        (
            "a NUL byte inside a name",
            one("page\0eval"),
            Err("a disabledTools entry contains a NUL byte"),
        ),
        ("a comma inside a name", one("a,b"), Err(COMMA)),
        ("a lone comma", one(","), Err(COMMA)),
        ("a trailing comma", one("page_eval,"), Err(COMMA)),
        ("leading whitespace", one(" page_eval"), Err(SPACE)),
        ("trailing whitespace", one("page_eval "), Err(SPACE)),
        ("a leading tab", one("\tx"), Err(SPACE)),
        ("a whitespace-only name", one(" "), Err(SPACE)),
    ];
    for (label, doc, expected) in rows {
        assert_eq!(doc.validate(), expected, "{label}");
    }
}

/// The overlay parser is the same fail-closed contract on the unsigned lane. A huge-but-restricting
/// millisecond value is a legal restriction under the zero-top order, so the JS-safe bound must hold
/// here as much as in the document; an absent field stays absent through the bounded deserializer;
/// and an unknown key, the retired and excluded settings.ts fields included, fails the parse.
#[test]
fn overlay_parse_pins_the_js_safe_bound_and_refuses_every_unknown_name() {
    type Row = (String, serde_json::Value, Result<PolicyOverlay, String>);
    let unknown_field = |bad: &str| {
        format!(
            "unknown field `{bad}`, expected one of {}",
            one_of(catalogue_names())
        )
    };
    let mut rows: Vec<Row> = vec![
        (
            "the empty overlay".into(),
            json!({}),
            Ok(PolicyOverlay::default()),
        ),
        (
            "one present entry".into(),
            json!({ "disabledTools": ["page_eval"] }),
            Ok(PolicyOverlay {
                disabled_tools: Some(vec!["page_eval".into()]),
                ..PolicyOverlay::default()
            }),
        ),
        (
            "an unknown key beside a present entry".into(),
            json!({ "disabledTools": ["page_eval"], "surprise": true }),
            Err(unknown_field("surprise")),
        ),
        (
            "the retired requireEnrollment".into(),
            json!({ "requireEnrollment": false }),
            Err(unknown_field("requireEnrollment")),
        ),
        (
            "the excluded uiLanguage".into(),
            json!({ "uiLanguage": "en" }),
            Err(unknown_field("uiLanguage")),
        ),
    ];
    for field in PolicyField::ALL {
        let FieldKind::Ms(ms) = field.kind() else {
            continue;
        };
        let name = field.wire_name();
        rows.push((
            format!("{name} at 2^53 - 1"),
            json!({ name: JS_SAFE_INT_MAX }),
            Ok(overlay_with_ms(ms, Ms::try_from(JS_SAFE_INT_MAX).unwrap())),
        ));
        rows.push((
            format!("{name} at 2^53"),
            json!({ name: JS_SAFE_INT_MAX + 1 }),
            Err(BOUND_ERR.into()),
        ));
    }
    for (label, input, expected) in rows {
        assert_eq!(
            serde_json::from_value::<PolicyOverlay>(input).map_err(|e| e.to_string()),
            expected,
            "{label}"
        );
    }
}

#[test]
fn the_deny_baseline_sits_at_every_boolean_restrictive_pole() {
    // The deny mechanism is grants-off plus confirmations-on, a consistency
    // between the Default table and the catalogue's declared directions that
    // neither can express alone: a new boolean field with a permissive
    // default fails here. The windows are usability defaults, not poles, and
    // hostReverifyMs keeps its decided permissive default (see `Default for
    // PolicyValues`); the deny list has no restrictive end to sit at.
    let base = PolicyValues::default();
    for field in PolicyField::ALL {
        let FieldKind::Bool(f) = field.kind() else {
            continue;
        };
        let restrictive = match direction(*field) {
            Direction::Bool(BoolPole::TruePermissive) => false,
            Direction::Bool(BoolPole::FalsePermissive) => true,
            Direction::Ms(_) | Direction::ShrinksPermissiveSet => {
                panic!("{}: boolean field declared non-boolean", field.wire_name())
            }
        };
        assert_eq!(
            base.get_bool(f),
            restrictive,
            "{} must default to its restrictive pole",
            field.wire_name()
        );
    }
}

#[test]
fn fold_applies_exactly_the_present_overlay_entries() {
    let base = PolicyValues::default();
    let overlay = PolicyOverlay {
        page_eval_enabled: Some(false),
        confirm_grace_ms: Some(Ms::ZERO),
        disabled_tools: Some(vec!["page_upload".into()]),
        ..PolicyOverlay::default()
    };
    assert_eq!(
        fold(&base, &overlay),
        PolicyValues {
            page_eval_enabled: false,
            confirm_grace_ms: Ms::ZERO,
            disabled_tools: vec!["page_upload".into()],
            ..base.clone()
        }
    );
    // An empty overlay is the identity.
    assert_eq!(fold(&base, &PolicyOverlay::default()), base);
}
