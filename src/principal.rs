// SPDX-License-Identifier: Apache-2.0
//! SPIFFE workload-identity binding seam (ADR-011, task 011).
//!
//! In spiffe mode the handle's first-use binding key is a **verified SPIFFE workload identity**
//! (`principal.spiffe_id`) instead of the opaque `sandbox_id` string, so a handle first injected by
//! one workload identity can never be presented by another. Default (sandbox) mode is unchanged.
//!
//! The `PrincipalResolver` seam is the single landing spot for agent-mesh task 008's verified
//! -principal contract `{spiffe_id, trust_tier}`. [`MockIssuerResolver`] stands in until task 008
//! ships: it validates the principal's **shape, not its provenance** (provenance is agent-mesh's
//! half). Adopting the real delivery is one new `PrincipalResolver` impl behind this seam.

use serde_json::Value;

/// agent-mesh task 008's verified-principal contract shape, verbatim.
pub struct VerifiedPrincipal {
    pub spiffe_id: String,
    /// Carried per the contract shape. Validated non-empty at resolve time; mapping it to the
    /// injection floor is future work (ADR-011 residual), so it is not yet read on the live path.
    #[allow(dead_code)]
    pub trust_tier: String,
}

/// Resolution failure in spiffe mode. The dispatch caller maps these to the standard fail-closed
/// error shape `{error:{code,message,retryable:false}}`.
#[derive(Debug)]
pub enum PrincipalError {
    /// No `principal` member on `sandbox_identity` in spiffe mode. Maps to `principal_missing`.
    Missing,
    /// The `principal` is present but malformed (bad `spiffe_id` per [`validate_spiffe_id`], or an
    /// empty/absent `trust_tier`). Maps to `principal_invalid`. The string is a diagnostic reason.
    Invalid(String),
}

/// The principal-resolution seam (ADR-011). `resolve` returns the **verified** principal on success;
/// in spiffe mode its `spiffe_id` is the handle binding key. The single documented extension point:
/// agent-mesh task 008's real verified-principal delivery lands as one new impl behind this trait.
pub trait PrincipalResolver: Send + Sync {
    fn resolve(&self, sandbox_identity: &Value) -> Result<VerifiedPrincipal, PrincipalError>;
}

/// The mock issuer: reads `sandbox_identity.principal.{spiffe_id, trust_tier}` and validates the
/// **shape** (a well-formed `spiffe_id` per the documented subset + a non-empty `trust_tier`),
/// returning the principal. It is the spiffe-mode default until agent-mesh task 008 ships.
///
/// **It validates shape, not provenance.** The mock trusts that the caller propagated a
/// genuinely-issued principal; verifying that agent-mesh actually issued/attested it is agent-mesh's
/// half (task 008), landing later as a real `PrincipalResolver` impl behind this same seam.
pub struct MockIssuerResolver;

impl PrincipalResolver for MockIssuerResolver {
    fn resolve(&self, sandbox_identity: &Value) -> Result<VerifiedPrincipal, PrincipalError> {
        let principal = match sandbox_identity.get("principal") {
            Some(p) if !p.is_null() => p,
            _ => return Err(PrincipalError::Missing),
        };
        let spiffe_id = principal
            .get("spiffe_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let trust_tier = principal
            .get("trust_tier")
            .and_then(Value::as_str)
            .unwrap_or("");
        validate_spiffe_id(spiffe_id).map_err(PrincipalError::Invalid)?;
        if trust_tier.is_empty() {
            return Err(PrincipalError::Invalid(
                "principal trust_tier is missing or empty".into(),
            ));
        }
        Ok(VerifiedPrincipal {
            spiffe_id: spiffe_id.to_string(),
            trust_tier: trust_tier.to_string(),
        })
    }
}

/// Validate a SPIFFE ID against the deliberate minimal subset (ADR-011 Decision 3), NOT the full
/// SPIFFE spec (issuance + full conformance are agent-mesh's; vault only refuses obviously-invalid
/// keys):
///
/// - scheme exactly `spiffe://`;
/// - non-empty trust domain of lowercase `[a-z0-9.-]`;
/// - non-empty path beginning `/`;
/// - no query (`?`) or fragment (`#`);
/// - total length ≤ 2048 bytes.
pub fn validate_spiffe_id(s: &str) -> Result<(), String> {
    if s.len() > 2048 {
        return Err("spiffe_id exceeds 2048 bytes".into());
    }
    if s.contains('?') {
        return Err("spiffe_id must not contain a query component".into());
    }
    if s.contains('#') {
        return Err("spiffe_id must not contain a fragment component".into());
    }
    let rest = s
        .strip_prefix("spiffe://")
        .ok_or_else(|| "spiffe_id must use the spiffe:// scheme".to_string())?;
    let slash = rest
        .find('/')
        .ok_or_else(|| "spiffe_id must have a /-prefixed path".to_string())?;
    let trust_domain = &rest[..slash];
    let path = &rest[slash..]; // begins with '/'
    if trust_domain.is_empty() {
        return Err("spiffe_id trust domain is empty".into());
    }
    if !trust_domain
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
    {
        return Err("spiffe_id trust domain must be lowercase [a-z0-9.-]".into());
    }
    // A path of just "/" carries no workload segment — reject it as empty.
    if path.len() < 2 {
        return Err("spiffe_id path must be non-empty after the leading /".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_spiffe_id_accepts_the_documented_form_and_rejects_the_table() {
        assert!(validate_spiffe_id("spiffe://secure-agents.local/exec-sandbox/sbx-1").is_ok());
        // Every malformed-table entry from the spec is rejected.
        for bad in [
            "http://x/y",            // wrong scheme
            "spiffe://",             // empty trust domain / no path
            "spiffe://domain",       // no path
            "spiffe://UPPER.case/x", // uppercase trust domain
            "spiffe://d/p?q=1",      // query
            "spiffe://d/p#f",        // fragment
            "",                      // empty
        ] {
            assert!(
                validate_spiffe_id(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        // >2048 bytes rejected.
        let long = format!("spiffe://d/{}", "a".repeat(2100));
        assert!(validate_spiffe_id(&long).is_err(), "over-2048 rejected");
    }

    #[test]
    fn mock_issuer_resolves_valid_principal_and_carries_trust_tier() {
        let sid = json!({
            "sandbox_id": "sbx-1",
            "principal": {"spiffe_id": "spiffe://secure-agents.local/exec-sandbox/sbx-1", "trust_tier": "attested"}
        });
        let p = MockIssuerResolver
            .resolve(&sid)
            .expect("valid principal resolves");
        assert_eq!(
            p.spiffe_id,
            "spiffe://secure-agents.local/exec-sandbox/sbx-1"
        );
        assert_eq!(p.trust_tier, "attested");
    }

    #[test]
    fn mock_issuer_rejects_missing_principal_and_empty_tier() {
        // No principal member → Missing.
        let no_p = json!({ "sandbox_id": "sbx-1" });
        assert!(matches!(
            MockIssuerResolver.resolve(&no_p),
            Err(PrincipalError::Missing)
        ));
        // Valid spiffe_id but empty trust_tier → Invalid.
        let empty_tier = json!({
            "principal": {"spiffe_id": "spiffe://d/w", "trust_tier": ""}
        });
        assert!(matches!(
            MockIssuerResolver.resolve(&empty_tier),
            Err(PrincipalError::Invalid(_))
        ));
        // Malformed spiffe_id → Invalid.
        let bad_id = json!({
            "principal": {"spiffe_id": "http://x/y", "trust_tier": "attested"}
        });
        assert!(matches!(
            MockIssuerResolver.resolve(&bad_id),
            Err(PrincipalError::Invalid(_))
        ));
    }
}
