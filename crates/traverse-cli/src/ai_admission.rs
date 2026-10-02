//! Publish-time registry admission checks for a contract's `ai` object
//! (Spec 056 v1.1.0 FR-014–FR-019, Decision 109).
//!
//! This is a port of the registry CI rules in
//! `traverse-framework/registry` `scripts/ci/capability_validation.py`
//! (registry Spec 001 FR-017 and Spec 026). It covers exactly the checks
//! that can be decided from the contract JSON alone. Every `capability
//! publish` adds a new registry path (FR-006), so the newly-added-contract
//! gates always apply. The checks that need the network or other files
//! (evidence digest fetches, the `model-weights.json` cross-check, and
//! rights drift) stay with registry CI (FR-015).
//!
//! Parity is proven by the registry-owned fixture corpus vendored under
//! `tests/fixtures/registry-admission/` (FR-019). Each error carries the
//! registry's own error code, so the corpus test compares code sets
//! exactly. Behaviour follows Python's semantics where they differ from
//! Rust's. For example, a JSON `null` reads as absent through `dict.get`,
//! and `$` in a pin regex also matches before one trailing newline.

use serde_json::{Map, Value};
use std::collections::BTreeSet;

const MODEL_RIGHTS_FIELDS: [&str; 3] = ["commercial_use", "redistribution", "derivatives"];
const RIGHTS_VALUES: [&str; 4] = ["allowed", "forbidden", "conditional", "unknown"];
const VERIFICATION_STATUSES_V1: [&str; 1] = ["maintainer-declared"];
const DERIVATION_TRANSFORMATIONS: [&str; 6] = [
    "quantize",
    "format-convert",
    "prune",
    "distill",
    "fine-tune",
    "other",
];
const DATA_OBLIGATION_KINDS: [&str; 3] = ["training", "labels", "eval"];
const NON_REDISTRIBUTABLE_MARKERS: [&str; 3] = ["UNLICENSED", "NONE", "LicenseRef-Proprietary"];
const REGISTRY_RELEASE_PREFIX: &str =
    "https://github.com/traverse-framework/registry/releases/download/artifacts/";

/// One registry admission failure, with the registry CI error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmissionError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Default)]
struct Errors(Vec<AdmissionError>);

impl Errors {
    fn fail(&mut self, code: &'static str, message: impl Into<String>) {
        self.0.push(AdmissionError {
            code,
            message: message.into(),
        });
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Every contract-decidable registry admission failure for the contract's
/// `ai` object, evaluated as a newly added contract. An empty result means
/// registry CI accepts the `ai` object, apart from the CI-only checks.
pub(crate) fn ai_admission_errors(contract: &Value) -> Vec<AdmissionError> {
    let mut errors = Errors::default();
    validate_ai_declaration(contract, &mut errors);
    check_new_contract_ai_models_object_shape(contract, &mut errors);
    check_new_contract_model_rights(contract, &mut errors);
    errors.0
}

/// Python `dict.get`: a JSON `null` reads as absent.
fn get<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

fn non_blank_str(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

fn model_backed_true(ai: &Map<String, Value>) -> bool {
    ai.get("model_backed") == Some(&Value::Bool(true))
}

/// Registry `validate_ai_declaration` (spec 001 FR-017, whole-tree).
fn validate_ai_declaration(contract: &Value, errors: &mut Errors) {
    let Some(ai) = contract.get("ai").filter(|value| !value.is_null()) else {
        return;
    };
    let Some(ai) = ai.as_object() else {
        errors.fail(
            "contract.invalid_ai",
            "contract 'ai' must be an object {model_backed: boolean, models?: string[] | object[]} (spec 001 FR-017)",
        );
        return;
    };
    let models = get(ai, "models");
    let models_well_formed = match models {
        None => true,
        Some(Value::Array(entries)) => ai_models_shape_ok(entries, errors),
        Some(_) => false,
    };
    if !ai.get("model_backed").is_some_and(Value::is_boolean) {
        errors.fail(
            "contract.invalid_ai",
            "ai.model_backed must be a boolean (spec 001 FR-017)",
        );
    }
    if models.is_some_and(|value| !value.is_array()) {
        errors.fail(
            "contract.invalid_ai",
            "ai.models must be an array of non-empty strings or model-reference objects (spec 001 FR-017)",
        );
    }
    let non_empty_models = models
        .and_then(Value::as_array)
        .is_some_and(|entries| !entries.is_empty());
    if model_backed_true(ai) && !(models_well_formed && non_empty_models) {
        errors.fail(
            "contract.invalid_ai",
            "ai.model_backed: true requires a non-empty ai.models array (spec 001 FR-017)",
        );
    }
}

/// Registry `_ai_models_shape_ok`: one array is either all legacy strings or
/// all `ModelRef` objects.
fn ai_models_shape_ok(models: &[Value], errors: &mut Errors) -> bool {
    if models.is_empty() {
        return true;
    }
    if models.iter().all(Value::is_string) {
        let ok = models
            .iter()
            .all(|model| non_blank_str(Some(model)).is_some());
        if !ok {
            errors.fail(
                "contract.invalid_ai",
                "ai.models (legacy string[] shape) must be an array of non-empty strings (spec 001 FR-017)",
            );
        }
        return ok;
    }
    let mut ok = true;
    for (index, model_ref) in models.iter().enumerate() {
        if let Some(reason) = model_ref_shape_error(model_ref) {
            errors.fail(
                "contract.invalid_ai",
                format!("ai.models[{index}]: {reason}"),
            );
            ok = false;
            continue;
        }
        if let Some(spdx) = model_ref
            .get("spdx_expression")
            .and_then(Value::as_str)
            .map(str::trim)
        {
            let before = errors.len();
            validate_spdx_expression(spdx, errors);
            if errors.len() != before {
                ok = false;
            }
        }
    }
    ok
}

/// Registry `_model_ref_shape_error` (spec 001 FR-017 object `ModelRef`).
fn model_ref_shape_error(model_ref: &Value) -> Option<&'static str> {
    let Some(model_ref) = model_ref.as_object() else {
        return Some("must be an object (spec 001 FR-017 object-shaped ai.models)");
    };
    if non_blank_str(get(model_ref, "id")).is_none() {
        return Some("ai.models[].id is required and must be a non-empty string");
    }
    if non_blank_str(get(model_ref, "spdx_expression")).is_none() {
        return Some("ai.models[].spdx_expression is required and must be a non-empty string");
    }
    if !get(model_ref, "attribution_required").is_some_and(Value::is_boolean) {
        return Some("ai.models[].attribution_required is required and must be a boolean");
    }
    let has_hf_pin = non_blank_str(get(model_ref, "huggingface_id")).is_some()
        && non_blank_str(get(model_ref, "revision")).is_some();
    let source_url = non_blank_str(get(model_ref, "source_url"));
    if !has_hf_pin && source_url.is_none() {
        return Some(
            "ai.models[] must include either (huggingface_id + revision) or source_url (spec 001 FR-017)",
        );
    }
    if source_url.is_some_and(|url| !is_safe_https_url(Some(url))) {
        return Some("ai.models[].source_url must be a safe https URL (spec 001 FR-017)");
    }
    if get(model_ref, "copyright").is_some_and(|value| !value.is_string()) {
        return Some("ai.models[].copyright must be a string when present (spec 001 FR-017)");
    }
    None
}

/// Registry `check_new_contract_ai_models_object_shape` (FR-017 forward gate).
fn check_new_contract_ai_models_object_shape(contract: &Value, errors: &mut Errors) {
    let Some(ai) = contract.get("ai").and_then(Value::as_object) else {
        return;
    };
    if !model_backed_true(ai) {
        return;
    }
    let Some(models) = get(ai, "models").and_then(Value::as_array) else {
        return;
    };
    if models.iter().any(Value::is_string) {
        errors.fail(
            "contract.ai_models_legacy_shape_on_new_contract",
            "newly added contract.json with ai.model_backed: true must use the object-shaped ai.models (id, spdx_expression, attribution_required, plus huggingface_id+revision or source_url); the legacy string[] shape is grandfathered on already-published contracts only (registry spec 001 FR-017)",
        );
    }
}

/// Registry `check_new_contract_model_rights` (spec 026 forward gate).
fn check_new_contract_model_rights(contract: &Value, errors: &mut Errors) {
    let Some(ai) = contract.get("ai").and_then(Value::as_object) else {
        return;
    };
    if !model_backed_true(ai) {
        return;
    }
    let Some(models) = get(ai, "models").and_then(Value::as_array) else {
        return;
    };
    for (index, model_ref) in models.iter().enumerate() {
        if let Some(model_ref) = model_ref.as_object() {
            check_model_ref_rights(index, model_ref, errors);
        }
    }
}

/// Registry `check_model_ref_rights` (spec 026 FR-001–FR-011), contract-decidable parts.
fn check_model_ref_rights(index: usize, model_ref: &Map<String, Value>, errors: &mut Errors) {
    let prefix = format!("ai.models[{index}]");
    check_rights_enums_and_contradictions(&prefix, model_ref, errors);
    let spdx = get(model_ref, "spdx_expression").and_then(Value::as_str);

    let verification = get(model_ref, "verification").and_then(Value::as_object);
    let evidence_url = verification.and_then(|verification| get(verification, "evidence_url"));
    match verification {
        None => errors.fail(
            "contract.invalid_model_rights_verification",
            format!("{prefix}.verification must be an object with status 'maintainer-declared' (spec 026 FR-001)"),
        ),
        Some(verification) => {
            let status = get(verification, "status").and_then(Value::as_str);
            if !status.is_some_and(|status| VERIFICATION_STATUSES_V1.contains(&status)) {
                errors.fail(
                    "contract.invalid_model_rights_verification",
                    format!("{prefix}.verification.status must be 'maintainer-declared' (spec 026 FR-009)"),
                );
            }
            if evidence_url.is_some_and(|url| !is_safe_https_url(url.as_str())) {
                errors.fail(
                    "contract.invalid_model_rights_url",
                    format!("{prefix}.verification.evidence_url must be a safe https URL (spec 026 FR-008)"),
                );
            }
        }
    }
    if spdx.is_some_and(|spdx| spdx.contains("LicenseRef-"))
        && !is_safe_https_url(evidence_url.and_then(Value::as_str))
    {
        errors.fail(
            "contract.model_rights_licenseref_needs_evidence",
            format!("{prefix}: a LicenseRef-* spdx_expression requires verification.evidence_url (spec 026 FR-003)"),
        );
    }

    check_evidence_files(
        &format!("{prefix}.license_files"),
        get(model_ref, "license_files"),
        true,
        false,
        errors,
    );
    check_evidence_files(
        &format!("{prefix}.notice_files"),
        get(model_ref, "notice_files"),
        model_ref.get("attribution_required") == Some(&Value::Bool(true)),
        true,
        errors,
    );

    let pinned = match get(model_ref, "revision") {
        Some(revision) => revision.as_str().is_some_and(is_commit_id),
        None => get(model_ref, "source_url")
            .and_then(Value::as_str)
            .is_some_and(contains_commit_id_segment),
    };
    if !pinned {
        errors.fail(
            "contract.model_rights_mutable_revision",
            format!("{prefix} must pin an immutable upstream commit: revision must be a full commit id, or source_url must contain one; branches and tags are mutable (spec 026 FR-008)"),
        );
    }

    check_derivation(&prefix, model_ref, errors);
    check_data_obligations(&prefix, get(model_ref, "data_obligations"), errors);

    if let Some(rights_change) = get(model_ref, "rights_change") {
        let valid = rights_change.as_object().is_some_and(|change| {
            non_blank_str(get(change, "reason")).is_some()
                && is_safe_https_url(get(change, "evidence_url").and_then(Value::as_str))
        });
        if !valid {
            errors.fail(
                "contract.invalid_model_rights_change",
                format!("{prefix}.rights_change must be {{reason, evidence_url}} with a non-empty reason and a safe https evidence_url (spec 026 FR-011)"),
            );
        }
    }
}

/// Spec 026 FR-001/FR-002 rights enums and the FR-004 hard contradictions.
fn check_rights_enums_and_contradictions(
    prefix: &str,
    model_ref: &Map<String, Value>,
    errors: &mut Errors,
) {
    for field in MODEL_RIGHTS_FIELDS {
        match get(model_ref, field).and_then(Value::as_str) {
            Some("unknown") => errors.fail(
                "contract.model_rights_unknown",
                format!("{prefix}.{field} is 'unknown'; model rights must be researched and declared (spec 026 FR-002)"),
            ),
            Some(value) if RIGHTS_VALUES.contains(&value) => {}
            _ => errors.fail(
                "contract.invalid_model_rights",
                format!("{prefix}.{field} must be one of allowed, conditional, forbidden (spec 026 FR-001/FR-002)"),
            ),
        }
    }

    let redistribution = get(model_ref, "redistribution").and_then(Value::as_str);
    if redistribution == Some("forbidden") {
        errors.fail(
            "contract.model_rights_contradiction",
            format!("{prefix}.redistribution is 'forbidden', but the Registry publicly hosts the artifact that embeds the weights (spec 026 FR-004)"),
        );
    }
    if get(model_ref, "derivatives").and_then(Value::as_str) == Some("forbidden")
        && get(model_ref, "derivation").is_some_and(Value::is_object)
    {
        errors.fail(
            "contract.model_rights_contradiction",
            format!(
                "{prefix}.derivatives is 'forbidden' but a derivation is declared (spec 026 FR-004)"
            ),
        );
    }
    let spdx = get(model_ref, "spdx_expression").and_then(Value::as_str);
    if let (Some(spdx), Some("allowed")) = (spdx, redistribution) {
        let hits: BTreeSet<&str> = spdx_tokens(spdx)
            .filter(|token| NON_REDISTRIBUTABLE_MARKERS.contains(token))
            .collect();
        if !hits.is_empty() {
            errors.fail(
                "contract.model_rights_contradiction",
                format!("{prefix}.redistribution is 'allowed' but spdx_expression contains non-redistributable marker(s) {hits:?} (spec 026 FR-004)"),
            );
        }
    }
}

/// Registry `_check_evidence_files` without the digest fetch (CI-only).
fn check_evidence_files(
    label: &str,
    files: Option<&Value>,
    required: bool,
    is_notice: bool,
    errors: &mut Errors,
) {
    let Some(files) = files else {
        if required {
            let code = if is_notice {
                "contract.model_rights_missing_notice"
            } else {
                "contract.invalid_model_rights"
            };
            errors.fail(code, format!("{label} is required (spec 026 FR-001)"));
        }
        return;
    };
    let Some(entries) = files
        .as_array()
        .filter(|entries| !(required && entries.is_empty()))
    else {
        errors.fail(
            "contract.invalid_model_rights",
            format!("{label} must be a non-empty array of {{url, sha256}} (spec 026 FR-001)"),
        );
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let entry = entry.as_object();
        let url = entry
            .and_then(|entry| get(entry, "url"))
            .and_then(Value::as_str);
        if !url.is_some_and(is_registry_release_asset_url) {
            errors.fail(
                "contract.invalid_model_rights_evidence_url",
                format!("{label}[{index}].url must be a traverse-framework/registry artifacts/ release asset (spec 026 FR-005)"),
            );
            continue;
        }
        let sha256 = entry
            .and_then(|entry| get(entry, "sha256"))
            .and_then(Value::as_str);
        if !sha256.is_some_and(is_sha256_hex) {
            errors.fail(
                "contract.invalid_model_rights",
                format!(
                    "{label}[{index}].sha256 must be 64 lowercase hex characters (spec 026 FR-005)"
                ),
            );
        }
    }
}

/// Registry `_check_derivation` without the `model-weights.json`
/// cross-check, which needs other files and stays with CI.
fn check_derivation(prefix: &str, model_ref: &Map<String, Value>, errors: &mut Errors) {
    let Some(derivation) = model_ref.get("derivation") else {
        errors.fail(
            "contract.model_rights_missing_derivation",
            format!("{prefix}.derivation is required: an object describing how the shipped weights differ from upstream, or null if shipped verbatim (spec 026 FR-006)"),
        );
        return;
    };
    if derivation.is_null() {
        return;
    }
    let Some(derivation) = derivation.as_object() else {
        errors.fail(
            "contract.invalid_model_derivation",
            format!("{prefix}.derivation must be an object or null"),
        );
        return;
    };
    let transformations_ok = get(derivation, "transformations")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            !items.is_empty()
                && items.iter().all(|item| {
                    item.as_str()
                        .is_some_and(|item| DERIVATION_TRANSFORMATIONS.contains(&item))
                })
        });
    if !transformations_ok {
        errors.fail(
            "contract.invalid_model_derivation",
            format!("{prefix}.derivation.transformations must be a non-empty array of {DERIVATION_TRANSFORMATIONS:?} (spec 026 FR-006)"),
        );
    }
    if non_blank_str(get(derivation, "description")).is_none() {
        errors.fail(
            "contract.invalid_model_derivation",
            format!("{prefix}.derivation.description must be a non-empty string (spec 026 FR-006)"),
        );
    }
    if get(derivation, "tool_url").is_some_and(|url| !is_safe_https_url(url.as_str())) {
        errors.fail(
            "contract.invalid_model_rights_url",
            format!("{prefix}.derivation.tool_url must be a safe https URL (spec 026 FR-008)"),
        );
    }
    if !get(derivation, "converted_sha256")
        .and_then(Value::as_str)
        .is_some_and(is_sha256_hex)
    {
        errors.fail(
            "contract.invalid_model_derivation",
            format!("{prefix}.derivation.converted_sha256 must be 64 lowercase hex characters (spec 026 FR-006)"),
        );
    }
}

/// Registry `_check_data_obligations` (spec 026 FR-007).
fn check_data_obligations(prefix: &str, obligations: Option<&Value>, errors: &mut Errors) {
    let Some(obligations) = obligations else {
        return;
    };
    let Some(entries) = obligations.as_array() else {
        errors.fail(
            "contract.invalid_model_data_obligations",
            format!("{prefix}.data_obligations must be an array"),
        );
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let label = format!("{prefix}.data_obligations[{index}]");
        let Some(entry) = entry.as_object() else {
            errors.fail(
                "contract.invalid_model_data_obligations",
                format!("{label} must be an object"),
            );
            continue;
        };
        for key in ["dataset", "obligation"] {
            if non_blank_str(get(entry, key)).is_none() {
                errors.fail(
                    "contract.invalid_model_data_obligations",
                    format!("{label}.{key} must be a non-empty string (spec 026 FR-007)"),
                );
            }
        }
        if !get(entry, "kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| DATA_OBLIGATION_KINDS.contains(&kind))
        {
            errors.fail(
                "contract.invalid_model_data_obligations",
                format!("{label}.kind must be one of {DATA_OBLIGATION_KINDS:?} (spec 026 FR-007)"),
            );
        }
        if !is_safe_https_url(get(entry, "source_url").and_then(Value::as_str)) {
            errors.fail(
                "contract.invalid_model_rights_url",
                format!("{label}.source_url must be a safe https URL (spec 026 FR-008)"),
            );
        }
        if let Some(spdx) = get(entry, "spdx_expression") {
            match non_blank_str(Some(spdx)) {
                Some(spdx) => validate_spdx_expression(spdx.trim(), errors),
                None => errors.fail(
                    "contract.invalid_model_data_obligations",
                    format!("{label}.spdx_expression must be a non-empty string when present"),
                ),
            }
        }
    }
}

/// Python `re.match(pattern + "$")`: `$` also matches before one trailing `\n`.
fn strip_one_trailing_newline(value: &str) -> &str {
    value.strip_suffix('\n').unwrap_or(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha256_hex(value: &str) -> bool {
    let value = strip_one_trailing_newline(value);
    value.len() == 64 && is_lower_hex(value)
}

/// Registry `COMMIT_ID_RE`: a full 40- or 64-hex commit id.
fn is_commit_id(value: &str) -> bool {
    let value = strip_one_trailing_newline(value);
    matches!(value.len(), 40 | 64) && is_lower_hex(value)
}

/// Registry `COMMIT_ID_IN_URL_RE.search`: `/<40|64 hex>` followed by `/` or the end.
fn contains_commit_id_segment(url: &str) -> bool {
    url.match_indices('/').any(|(start, _)| {
        let rest = &url[start + 1..];
        [40, 64].into_iter().any(|len| {
            rest.get(..len).is_some_and(is_lower_hex)
                && rest
                    .get(len..)
                    .is_some_and(|tail| matches!(tail, "" | "\n") || tail.starts_with('/'))
        })
    })
}

/// Registry `ARTIFACT_RELEASE_URL_RE`: an asset on this registry's `artifacts/` releases.
fn is_registry_release_asset_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix(REGISTRY_RELEASE_PREFIX) else {
        return false;
    };
    let rest = strip_one_trailing_newline(rest);
    let mut segments = rest.split('/');
    matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some(tag), Some(asset), None) if !tag.is_empty() && !asset.is_empty()
    )
}

/// Registry `is_safe_https_url`, following `urllib.parse.urlparse`: an
/// `https` scheme (case-insensitive), an authority after `//`, and no
/// credentials.
fn is_safe_https_url(url: Option<&str>) -> bool {
    let Some(url) = url else {
        return false;
    };
    if url.trim().is_empty()
        || url.starts_with('/')
        || url.starts_with("file:")
        || url.starts_with('~')
    {
        return false;
    }
    let cleaned: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let Some((scheme, rest)) = cleaned.split_once(':') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let Some(rest) = rest.strip_prefix("//") else {
        return false;
    };
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !netloc.is_empty() && !netloc.contains('@') && netloc.contains('[') == netloc.contains(']')
}

/// Registry `_spdx_tokens`: identifier-ish runs of `[A-Za-z0-9.+-]`.
fn spdx_tokens(expression: &str) -> impl Iterator<Item = &str> {
    expression
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-')))
        .filter(|token| !token.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpdxToken<'a> {
    Open,
    Close,
    And,
    Or,
    With,
    Symbol(&'a str),
}

/// Registry `validate_spdx_expression`. It mirrors the pinned
/// `license-expression` behaviour in strict mode with `validate=False`:
/// - `AND`, `OR` and `WITH` are case-insensitive.
/// - License and exception ids are matched case-insensitively against the
///   SPDX list, deprecated ids included.
/// - `+` is part of the identifier.
/// - `LicenseRef-*`, `UNLICENSED` and `NONE` are accepted as unknown keys.
/// - The right side of `WITH` must be a listed exception.
fn validate_spdx_expression(expression: &str, errors: &mut Errors) {
    match parse_spdx(expression) {
        Err(reason) => errors.fail(
            "contract.invalid_licensing_spdx",
            format!("spdx_expression is not a valid SPDX expression: {reason}"),
        ),
        Ok(unknown) => {
            for key in unknown {
                errors.fail(
                    "contract.invalid_licensing_spdx",
                    format!("spdx_expression contains unknown SPDX key {key:?}; use a listed SPDX id or LicenseRef-* (spec 025 FR-003)"),
                );
            }
        }
    }
}

fn tokenize_spdx(expression: &str) -> Result<Vec<SpdxToken<'_>>, String> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (index, c) in expression.char_indices() {
        let is_word = c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-' | '+');
        if is_word {
            start.get_or_insert(index);
            continue;
        }
        if let Some(word_start) = start.take() {
            tokens.push(word_token(&expression[word_start..index]));
        }
        match c {
            '(' => tokens.push(SpdxToken::Open),
            ')' => tokens.push(SpdxToken::Close),
            c if c.is_whitespace() => {}
            other => {
                return Err(format!(
                    "invalid character {other:?}: only letters, numbers, underscore, dot, colon, hyphen, plus and spaces are allowed"
                ));
            }
        }
    }
    if let Some(word_start) = start {
        tokens.push(word_token(&expression[word_start..]));
    }
    Ok(tokens)
}

fn word_token(word: &str) -> SpdxToken<'_> {
    if word.eq_ignore_ascii_case("and") {
        SpdxToken::And
    } else if word.eq_ignore_ascii_case("or") {
        SpdxToken::Or
    } else if word.eq_ignore_ascii_case("with") {
        SpdxToken::With
    } else {
        SpdxToken::Symbol(word)
    }
}

/// Parses `expression` and returns its unknown, non-exempt license keys.
fn parse_spdx(expression: &str) -> Result<Vec<String>, String> {
    let tokens = tokenize_spdx(expression)?;
    if tokens.is_empty() {
        return Err("expression must not be empty".to_string());
    }
    let mut parser = SpdxParser {
        tokens: &tokens,
        position: 0,
        unknown: Vec::new(),
    };
    parser.expression()?;
    if parser.position != tokens.len() {
        return Err(format!("unexpected token at position {}", parser.position));
    }
    Ok(parser.unknown)
}

struct SpdxParser<'t, 'a> {
    tokens: &'t [SpdxToken<'a>],
    position: usize,
    unknown: Vec<String>,
}

impl<'a> SpdxParser<'_, 'a> {
    fn peek(&self) -> Option<SpdxToken<'a>> {
        self.tokens.get(self.position).copied()
    }

    fn expression(&mut self) -> Result<(), String> {
        self.and_term()?;
        while self.peek() == Some(SpdxToken::Or) {
            self.position += 1;
            self.and_term()
                .map_err(|_| "OR requires two or more licenses".to_string())?;
        }
        Ok(())
    }

    fn and_term(&mut self) -> Result<(), String> {
        self.with_term()?;
        while self.peek() == Some(SpdxToken::And) {
            self.position += 1;
            self.with_term()
                .map_err(|_| "AND requires two or more licenses".to_string())?;
        }
        Ok(())
    }

    fn with_term(&mut self) -> Result<(), String> {
        match self.peek() {
            Some(SpdxToken::Open) => {
                self.position += 1;
                self.expression()?;
                if self.peek() != Some(SpdxToken::Close) {
                    return Err("unbalanced parenthesis".to_string());
                }
                self.position += 1;
                Ok(())
            }
            Some(SpdxToken::Symbol(symbol)) => {
                self.position += 1;
                self.license_symbol(symbol)?;
                if self.peek() == Some(SpdxToken::With) {
                    self.position += 1;
                    match self.peek() {
                        Some(SpdxToken::Symbol(exception)) if is_listed_exception(exception) => {
                            self.position += 1;
                        }
                        _ => {
                            return Err("WITH must be followed by a listed SPDX license exception"
                                .to_string());
                        }
                    }
                }
                Ok(())
            }
            _ => Err("expected a license or '('".to_string()),
        }
    }

    fn license_symbol(&mut self, symbol: &str) -> Result<(), String> {
        if is_listed_license(symbol) {
            return Ok(());
        }
        if is_listed_exception(symbol) {
            return Err(format!(
                "{symbol:?} is a license exception and is only valid after WITH"
            ));
        }
        if !(symbol.starts_with("LicenseRef-") || NON_REDISTRIBUTABLE_MARKERS.contains(&symbol)) {
            self.unknown.push(symbol.to_string());
        }
        Ok(())
    }
}

fn is_listed_license(symbol: &str) -> bool {
    spdx::identifiers::LICENSES
        .iter()
        .any(|license| license.name.eq_ignore_ascii_case(symbol))
}

fn is_listed_exception(symbol: &str) -> bool {
    spdx::identifiers::EXCEPTIONS
        .iter()
        .any(|exception| exception.name.eq_ignore_ascii_case(symbol))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{ai_admission_errors, contains_commit_id_segment, is_safe_https_url, parse_spdx};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    const CORPUS: &str =
        include_str!("../tests/fixtures/registry-admission/ai_admission_corpus.json");
    const PIN: &str = include_str!("../tests/fixtures/registry-admission/PIN.json");

    fn corpus() -> Value {
        serde_json::from_str(CORPUS).expect("vendored corpus must be JSON")
    }

    #[test]
    fn vendored_corpus_matches_its_pin() {
        let pin: Value = serde_json::from_str(PIN).expect("PIN.json must be JSON");
        let digest = Sha256::digest(CORPUS.as_bytes());
        let hex = digest.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        assert_eq!(
            pin["sha256"],
            hex.as_str(),
            "corpus bytes differ from PIN.json"
        );
        assert_eq!(pin["corpus_version"], corpus()["corpus_version"]);
    }

    /// Spec 056 v1.1.0 FR-019: agree with registry CI on every
    /// `contract_decidable` + `newly_added` fixture, and list the rest as skipped.
    #[test]
    fn agrees_with_every_contract_decidable_registry_fixture() {
        let corpus = corpus();
        let fixtures = corpus["fixtures"].as_array().expect("fixtures array");
        let mut checked = 0;
        let mut skipped = Vec::new();
        let mut mismatches = Vec::new();
        for fixture in fixtures {
            let name = fixture["name"].as_str().unwrap_or_default();
            if fixture["tier"] != "contract_decidable" || fixture["evaluated_as"] != "newly_added" {
                skipped.push(format!(
                    "{name} ({}, {})",
                    fixture["tier"], fixture["evaluated_as"]
                ));
                continue;
            }
            let mut contract = json!({"id": "example.detect-things", "version": "1.0.0"});
            if let Some(ai) = fixture.get("ai") {
                contract["ai"] = ai.clone();
            }
            let actual: BTreeSet<&str> = ai_admission_errors(&contract)
                .iter()
                .map(|error| error.code)
                .collect();
            let expected: BTreeSet<&str> = fixture["expect_codes"]
                .as_array()
                .expect("expect_codes array")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            if actual != expected {
                mismatches.push(format!("{name}: expected {expected:?}, got {actual:?}"));
            }
            checked += 1;
        }
        eprintln!("skipped registry fixtures (CI-only or existing-contract): {skipped:?}");
        assert!(
            mismatches.is_empty(),
            "registry parity mismatches:\n{}",
            mismatches.join("\n")
        );
        assert!(checked > 0);
    }

    /// Cases outside the corpus where the pinned `license-expression` verdict
    /// was probed directly (Decision 109).
    #[test]
    fn spdx_follows_license_expression_semantics() {
        for accepted in [
            "MIT",
            "mit",
            "MIT and apache-2.0",
            "Apache-2.0 With LLVM-exception",
            "GPL-2.0-only WITH classpath-exception-2.0",
            "((MIT))",
            "gpl-2.0+",
            "LGPL-2.1+",
            "LicenseRef-x WITH LLVM-exception",
            "LicenseRef-",
            "NONE",
            "UNLICENSED",
            "MIT\tOR Apache-2.0",
            "BSD-3-clause",
        ] {
            assert_eq!(parse_spdx(accepted), Ok(Vec::new()), "{accepted}");
        }
        for rejected in [
            "MIT OR",
            "AND",
            "(MIT",
            "MIT)",
            "()",
            "MIT Apache-2.0",
            "MIT WITH",
            "WITH MIT",
            "MIT WITH Apache-2.0",
            "MIT WITH LicenseRef-x",
            "MIT WITH LLVM-exception WITH LLVM-exception",
            "LLVM-exception",
            "MIT/Apache-2.0",
            "",
        ] {
            assert!(parse_spdx(rejected).is_err(), "{rejected}");
        }
        for unknown in [
            "MIT+",
            "Apache-2.0+",
            "licenseref-foo",
            "none",
            "OpenRAIL-M",
            "MIT:x",
        ] {
            assert_eq!(
                parse_spdx(unknown),
                Ok(vec![unknown.to_string()]),
                "{unknown}"
            );
        }
    }

    #[test]
    fn url_and_pin_helpers_follow_registry_regex_semantics() {
        assert!(is_safe_https_url(Some("HTTPS://example.org/x")));
        assert!(!is_safe_https_url(Some("https:example.org")));
        assert!(!is_safe_https_url(Some("https://[::1/x")));
        assert!(!is_safe_https_url(Some("file:///etc/passwd")));
        assert!(!is_safe_https_url(None));
        let hex40 = "0123456789abcdef0123456789abcdef01234567";
        let hex64 = "0123456789abcdef".repeat(4);
        assert!(contains_commit_id_segment(&format!("https://h/{hex40}")));
        assert!(contains_commit_id_segment(&format!("https://h/{hex64}/x")));
        assert!(contains_commit_id_segment(&format!("https://h/{hex40}\n")));
        assert!(!contains_commit_id_segment(&format!(
            "https://h/{hex40}0/x"
        )));
        assert!(!contains_commit_id_segment(&format!(
            "https://h/x{hex40}/y"
        )));
    }
}
