//! `seeds/classify_frame/`: every browser->host request the classifier handles, a bridge request it
//! forwards, every host->browser frame it must flag as a stray, and malformed requests. The reader
//! is the classifier itself: forwarded or handled is accepted, `Malformed` is the refusal.

use genkan_core::allowlist::{Anchor, ClientName};
use genkan_core::audit::{extension_kind_wire_names, AuditKind};
use genkan_core::enclave::{base64_encode, REASON_CODES, SIG_LEN};
use genkan_core::ipc::HashDigest;
use genkan_core::policy::{PolicyDoc, PolicyOverlay};
use genkan_core::protocol::control::{
    classify_nm_frame, AdminControl, EnclaveControl, EnrollOutcome, ExtensionAuditKind,
    FrameDisposition, HostRequest, KillStatus, PolicyControl, PolicyStatus, PresenceOutcome,
    WebAuthnControl,
};
use genkan_core::protocol::BridgeReq;
use serde_json::{json, Value};

use super::{compact, edited, tool_requests, without, Directory, Seed};
use crate::targets;

fn classifies_cleanly(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes).is_ok_and(|frame| {
        matches!(
            classify_nm_frame(&frame),
            FrameDisposition::Forward | FrameDisposition::Handle(_)
        )
    })
}

/// The `type` tag a control frame serializes under, for the seed's file name.
fn tag_of(frame: &Value) -> &str {
    frame["type"]
        .as_str()
        .expect("a control frame carries a string type tag")
}

fn presence_confirm() -> Value {
    json_of!(HostRequest::PresenceConfirm {
        nonce: "example-nonce".into(),
    })
}

pub(super) fn directory() -> Directory {
    let challenge = json_of!(HostRequest::EnclaveChallenge {
        nonce: "example-nonce".into(),
        context: Some("pair".into()),
    });
    let requests = [
        challenge.clone(),
        json_of!(HostRequest::EnclaveRevoke {}),
        presence_confirm(),
        json_of!(HostRequest::ClientList {}),
        json_of!(HostRequest::ClientRevoke {
            name: "example-client".into()
        }),
        json_of!(HostRequest::KillStatus {}),
        json_of!(HostRequest::KillEngage {}),
        json_of!(HostRequest::KillRelease {}),
        json_of!(HostRequest::PolicyGet {}),
        json_of!(HostRequest::LangGet {}),
        json_of!(HostRequest::LangSet { value: "en".into() }),
        json_of!(HostRequest::ClientPair {
            name: ClientName::try_from("example-client".to_string()).expect("a valid client name"),
            anchor: Anchor::Hash(
                HashDigest::try_from(&[0x11u8; 32][..]).expect("32 bytes is a digest width")
            ),
        }),
        json_of!(HostRequest::DoctorReport {}),
        json_of!(HostRequest::AuditRead { limit: None }),
        json_of!(HostRequest::RegistrationStatus {}),
        json_of!(HostRequest::RegistrationRepair { browsers: None }),
        json_of!(HostRequest::PolicyRestrict {
            overlay: PolicyOverlay::default()
        }),
        json_of!(HostRequest::PolicySet {
            overlay: PolicyOverlay::default()
        }),
        json_of!(HostRequest::PolicyHistory {}),
        json_of!(HostRequest::PolicyRollback {
            revision: 1,
            entry: None
        }),
        json_of!(HostRequest::EnrollBegin {}),
        json_of!(HostRequest::EnrollFinish {
            attestation_object: "example-attestation".into(),
            client_data_json: "example-client-data".into(),
        }),
        json_of!(HostRequest::PresenceBegin {
            action: "release the kill switch".into(),
            origin: "chrome-extension://example".into(),
        }),
        json_of!(HostRequest::PresenceAssert {
            credential_id: "example-credential".into(),
            authenticator_data: "example-authdata".into(),
            client_data_json: "example-client-data".into(),
            signature: "example-signature".into(),
        }),
        json_of!(HostRequest::BrowserRevoke {}),
    ];
    let mut seeds: Vec<Seed> = requests
        .iter()
        .map(|frame| {
            Seed::accepted(
                format!("request_{}", tag_of(frame)),
                compact(frame),
                classifies_cleanly,
            )
        })
        .collect();

    // One audit event per extension-owned kind, parsed through the kind's only constructor.
    let mut audit_event = None;
    for name in extension_kind_wire_names() {
        let kind: ExtensionAuditKind = serde_json::from_value(Value::String(name.clone()))
            .expect("an extension-owned kind parses");
        let frame = json_of!(HostRequest::AuditEvent {
            kind,
            outcome: Some("approved".into()),
            tool: Some("example_tool".into()),
            name: None,
            detail: None,
            cid: Some("c1".into()),
        });
        audit_event.get_or_insert_with(|| frame.clone());
        seeds.push(Seed::accepted(
            format!("request_audit_event_{name}"),
            compact(&frame),
            classifies_cleanly,
        ));
    }
    let audit_event = audit_event.expect("the extension owns at least one audit kind");

    let (_, _, command) = tool_requests()
        .into_iter()
        .next()
        .expect("the catalogue has at least one tool");
    seeds.push(Seed::accepted(
        "forward_bridge_request",
        compact(&json_of!(BridgeReq {
            id: 1,
            command,
            browser: None,
        })),
        classifies_cleanly,
    ));

    // Host->browser frames: a recognised tag the browser leg never legitimately originates, so the
    // classifier flags each as malformed and the pump drops it.
    let strays = [
        json_of!(EnclaveControl::EnclaveProof {
            sig: base64_encode(&[0u8; SIG_LEN]),
            key_id: "example-key".into(),
            pubkey: base64_encode(&[0x04u8; 65]),
        }),
        json_of!(EnclaveControl::EnclaveError {
            reason: REASON_CODES[0].into()
        }),
        json_of!(EnclaveControl::EnclaveRevoked {}),
        json_of!(WebAuthnControl::EnrollOptions {
            challenge: "example-challenge".into(),
            nonce: "example-nonce".into(),
            user_id: "example-user".into(),
            user_name: "example-browser".into(),
            exclude_credential_ids: Vec::new(),
        }),
        json_of!(EnrollOutcome::Refused {
            reason: "example".into()
        }
        .into_frame()),
        json_of!(WebAuthnControl::PresenceRequest {
            challenge: "example-challenge".into(),
            nonce: "example-nonce".into(),
            action: "release the kill switch".into(),
            allowed_credential_ids: Vec::new(),
        }),
        json_of!(PresenceOutcome::Approved.into_frame()),
        json_of!(AdminControl::ClientListResult {
            ok: true,
            enrolled: false,
            clients: Vec::new(),
            error: None,
        }),
        json_of!(AdminControl::ClientRevokeResult {
            ok: true,
            error: None
        }),
        json_of!(KillStatus::Read { killed: false }.into_frame()),
        json_of!(PolicyStatus::Present {
            baseline_b64: base64_encode(&compact(&json_of!(PolicyDoc::default()))),
            sig_b64: None,
            overlay: None,
        }
        .into_frame()),
        json_of!(PolicyControl::LangCurrent {
            value: "en".into(),
            seq: 1
        }),
        json_of!(AdminControl::ClientPairResult {
            ok: false,
            error: Some("example".into())
        }),
        json_of!(AdminControl::DoctorReportResult {
            ok: false,
            report: None,
            error: Some("example".into()),
        }),
        json_of!(AdminControl::AuditReadResult {
            ok: false,
            entries: None,
            older: None,
            path: None,
            error: Some("example".into()),
        }),
        json_of!(AdminControl::RegistrationStatusResult {
            ok: false,
            browsers: None,
            error: Some("example".into()),
        }),
        json_of!(PolicyControl::PolicyRestrictResult {
            ok: false,
            error: Some("example".into())
        }),
        json_of!(PolicyControl::PolicySetResult {
            ok: false,
            error: Some("example".into())
        }),
        json_of!(PolicyControl::PolicyHistoryResult {
            ok: false,
            entries: None,
            error: Some("example".into()),
        }),
        json_of!(PolicyControl::PolicyRollbackResult {
            ok: false,
            error: Some("example".into())
        }),
        json_of!(WebAuthnControl::BrowserRevokeResult {
            ok: false,
            reason: Some("example".into())
        }),
    ];
    seeds.extend(strays.iter().map(|frame| {
        Seed::refused(
            format!("stray_{}", tag_of(frame)),
            compact(frame),
            classifies_cleanly,
        )
    }));

    let host_kind = json_of!(AuditKind::KillEngage);
    seeds.extend([
        Seed::refused(
            "malformed_challenge_nonce_type",
            compact(&edited(&challenge, |v| v["nonce"] = json!(1))),
            classifies_cleanly,
        ),
        Seed::refused(
            "malformed_challenge_unknown_field",
            compact(&edited(&challenge, |v| v["surprise"] = json!(true))),
            classifies_cleanly,
        ),
        Seed::refused(
            "malformed_presence_confirm_missing_nonce",
            compact(&without(&presence_confirm(), "nonce")),
            classifies_cleanly,
        ),
        Seed::refused(
            "malformed_client_list_unknown_field",
            compact(&edited(&json_of!(HostRequest::ClientList {}), |v| {
                v["surprise"] = json!(true);
            })),
            classifies_cleanly,
        ),
        Seed::refused(
            "malformed_audit_event_host_kind",
            compact(&edited(&audit_event, |v| v["kind"] = host_kind)),
            classifies_cleanly,
        ),
        Seed::refused(
            "malformed_audit_event_kind_type",
            compact(&edited(&audit_event, |v| v["kind"] = json!(1))),
            classifies_cleanly,
        ),
    ]);
    Directory {
        target: targets::CLASSIFY_FRAME,
        seeds,
    }
}
