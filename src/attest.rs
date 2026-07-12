// SPDX-License-Identifier: Apache-2.0
//! Ed25519 verification of the sandbox attestation at the inject dispatch edge (ADR-010, task 010).
//!
//! Closes the unverifiable-binding gap: before task 010, `inject` bound a handle at first use to
//! whatever opaque `sandbox_id` string the caller presented, with nothing proving the caller *is*
//! that sandbox. This module verifies a host-signed attestation over the sandbox identity **before
//! any `Vault` call** (same layering as the SO_PEERCRED gate, ADR-002) and returns the *verified*
//! sandbox id, which is what then flows in as the handle binding key.
//!
//! **One payload-shape seam.** All knowledge of the attestation payload's byte shape lives in
//! [`attested_sandbox_id`]. The shape is provisional pending exec-sandbox tasks 020-021 (they own the
//! final `sandbox_identity.attestation` payload + published trust root); when it lands, ONLY that
//! function and the test fixture builder change, no trait / config / dispatch / contract change.
//!
//! The signature crate is `ed25519-compact` (verify-only usage; ADR-010 records why it was chosen
//! over `ed25519-dalek` by dep-scan measurement, chiefly that dalek pulls the BLOCKED `zeroize`).

use ed25519_compact::{PublicKey, Signature};
use serde_json::Value;

use crate::crypto::decode_base64;

/// Verification failure at the attestation edge. The dispatch caller maps these to the standard
/// fail-closed error shape `{error:{code,message,retryable:false}}`.
#[derive(Debug)]
pub enum AttestError {
    /// A trust root is configured but the request carries no `attestation` member (today's plain
    /// request shape). Maps to `attestation_missing`.
    Missing,
    /// The attestation is present but did not verify: bad base64, wrong lengths, non-JSON payload,
    /// wrong `alg`, tampered payload or signature, wrong signing key, or the signed `sandbox_id`
    /// disagrees with the outer one. Maps to `attestation_invalid`. The string is a diagnostic
    /// reason; it never contains a secret.
    Invalid(String),
}

/// The attestation-verification seam (ADR-010). `verify` returns the **verified** sandbox id on
/// success; that id, not the caller-asserted outer field, is what binds the handle.
pub trait AttestationVerifier: Send + Sync {
    fn verify(&self, sandbox_identity: &Value) -> Result<String, AttestError>;
}

/// Parse the sandbox id out of the raw decoded attestation payload bytes.
///
/// **The single payload-shape seam.** The provisional shape (pending exec-sandbox tasks 020-021) is
/// the canonical JSON `{"sandbox_id":"<id>"}`. When the real exec-sandbox shape lands, ONLY this
/// function and the test fixture builder change, no trait / config / test-harness / contract change.
pub fn attested_sandbox_id(payload_bytes: &[u8]) -> Result<String, AttestError> {
    let v: Value = serde_json::from_slice(payload_bytes)
        .map_err(|e| AttestError::Invalid(format!("attestation payload is not JSON: {e}")))?;
    match v.get("sandbox_id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => Ok(id.to_string()),
        _ => Err(AttestError::Invalid(
            "attestation payload has no non-empty sandbox_id".into(),
        )),
    }
}

/// The transitional no-trust-root verifier: extracts `sandbox_id` exactly as `dispatch` did before
/// task 010, **ignoring** any `attestation` member.
///
/// **Transitional (the gap stays open in this mode).** The unverifiable-binding gap task 010 closes
/// remains OPEN here: the returned id is caller-asserted and unauthenticated. Constructed only when
/// no trust root is configured; the intended posture is [`Ed25519Verifier`] once exec-sandbox
/// publishes its trust root (ADR-010, Decision 4).
pub struct PassthroughVerifier;

impl AttestationVerifier for PassthroughVerifier {
    fn verify(&self, sandbox_identity: &Value) -> Result<String, AttestError> {
        // Byte-for-byte today's extraction: the opaque, caller-asserted sandbox_id. No signature is
        // checked; an `attestation` member, if present, is ignored.
        Ok(sandbox_identity["sandbox_id"]
            .as_str()
            .unwrap_or("")
            .to_string())
    }
}

/// Verifies the Ed25519 attestation against the single configured 32-byte trust-root public key.
///
/// On success the returned id comes from the **signed** payload, and is additionally required to
/// equal the outer `sandbox_identity.sandbox_id` so a valid signature over a *different* identity
/// cannot bind as this one.
pub struct Ed25519Verifier {
    trust_root: PublicKey,
}

impl Ed25519Verifier {
    /// Build from the 32-byte trust-root **public** key (the loader in `main.rs` decodes/validates
    /// the key material to exactly 32 bytes before this is called).
    pub fn new(trust_root: [u8; 32]) -> Self {
        Ed25519Verifier {
            trust_root: PublicKey::new(trust_root),
        }
    }
}

impl AttestationVerifier for Ed25519Verifier {
    fn verify(&self, sandbox_identity: &Value) -> Result<String, AttestError> {
        // Missing attestation is a distinct, retryable-false error (a trust root is configured but
        // the caller sent today's plain request).
        let att = match sandbox_identity.get("attestation") {
            Some(a) if !a.is_null() => a,
            _ => return Err(AttestError::Missing),
        };
        // `alg` must be exactly "ed25519" (advisory `key_id`, if present, is never used to select a
        // key — the key is always the single configured trust root).
        if att.get("alg").and_then(Value::as_str) != Some("ed25519") {
            return Err(AttestError::Invalid(
                "attestation alg must be \"ed25519\"".into(),
            ));
        }
        let payload_b64 = att
            .get("payload")
            .and_then(Value::as_str)
            .ok_or_else(|| AttestError::Invalid("attestation missing payload".into()))?;
        let sig_b64 = att
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| AttestError::Invalid("attestation missing signature".into()))?;
        let payload_bytes = decode_base64(payload_b64).ok_or_else(|| {
            AttestError::Invalid("attestation payload is not valid base64".into())
        })?;
        let sig_bytes = decode_base64(sig_b64).ok_or_else(|| {
            AttestError::Invalid("attestation signature is not valid base64".into())
        })?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            AttestError::Invalid(format!(
                "attestation signature must be 64 bytes, got {}",
                sig_bytes.len()
            ))
        })?;
        let signature = Signature::new(sig_arr);
        // Authenticate: the signature must verify over the RAW decoded payload bytes against the
        // configured trust root. A bad key, tampered payload, or tampered signature all fail here.
        self.trust_root
            .verify(&payload_bytes, &signature)
            .map_err(|_| {
                AttestError::Invalid(
                    "attestation signature does not verify against the trust root".into(),
                )
            })?;
        // Authentic: take the verified id from the SIGNED payload (never the outer field)...
        let signed_id = attested_sandbox_id(&payload_bytes)?;
        // ...and require it to equal the outer sandbox_id, so a valid signature over a DIFFERENT
        // identity cannot bind as this one.
        let outer_id = sandbox_identity["sandbox_id"].as_str().unwrap_or("");
        if signed_id != outer_id {
            return Err(AttestError::Invalid(
                "signed payload sandbox_id does not match the outer sandbox_id".into(),
            ));
        }
        Ok(signed_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The single payload-shape seam parses the provisional canonical-JSON shape.
    #[test]
    fn attested_sandbox_id_parses_provisional_shape() {
        let bytes = serde_json::to_vec(&json!({ "sandbox_id": "sbx-9" })).unwrap();
        assert_eq!(attested_sandbox_id(&bytes).unwrap(), "sbx-9");
    }

    // Non-JSON, empty id, and missing id all fail closed (Invalid), never a silent "".
    #[test]
    fn attested_sandbox_id_rejects_non_json_empty_and_missing() {
        assert!(matches!(
            attested_sandbox_id(b"not json"),
            Err(AttestError::Invalid(_))
        ));
        let empty = serde_json::to_vec(&json!({ "sandbox_id": "" })).unwrap();
        assert!(matches!(
            attested_sandbox_id(&empty),
            Err(AttestError::Invalid(_))
        ));
        let missing = serde_json::to_vec(&json!({ "other": "x" })).unwrap();
        assert!(matches!(
            attested_sandbox_id(&missing),
            Err(AttestError::Invalid(_))
        ));
    }

    // PassthroughVerifier extracts the opaque outer id and ignores any attestation member.
    #[test]
    fn passthrough_extracts_outer_id_ignoring_attestation() {
        let sid = json!({ "sandbox_id": "sbx-x", "attestation": { "alg": "garbage" } });
        assert_eq!(PassthroughVerifier.verify(&sid).unwrap(), "sbx-x");
    }
}
