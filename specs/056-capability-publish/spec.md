# Feature Specification: Capability Publish CLI

**Feature Branch**: `056-capability-publish`
**Created**: 2026-07-06
**Status**: Approved
**Version**: 1.1.0
**Amended**: 2026-10-01 (Decision 109 / #1459 / PR #1597): FR-014–FR-019, publish-time registry admission parity.
**Input**: GitHub issue #543, registry decision log entry 9, registry specs `001-registry-foundation` and `002-capability-validation`, and Traverse specs `051-registry-extraction` and `054-public-scope-registry-ref`.

## Purpose

Traverse MUST provide `traverse-cli capability publish` as a governed PR automation command for submitting capability publication candidates to `traverse-framework/registry`. The command automates local validation, digest collection, branch preparation, and PR creation. It MUST NOT bypass deterministic registry CI or explicit human review.

## Requirements

- **FR-001**: `traverse-cli capability publish` MUST validate the candidate capability contract locally before creating any registry PR.
- **FR-002**: The command MUST refuse content sourced from a bundle or manifest marked `scope: private`.
- **FR-003**: The command MUST reject contracts with invalid schema, invalid semver, missing owner metadata, missing artifact metadata, or a missing digest before any PR is opened.
- **FR-004**: The command MUST compute or verify the artifact digest before preparing the publication record.
- **FR-005**: The command MUST map the candidate into the registry repo path `capabilities/<namespace>/<id>/<version>/contract.json`.
- **FR-006**: The command MUST refuse to overwrite an existing published path in a local registry checkout before opening a PR.
- **FR-007**: The command MUST create a dedicated branch in `traverse-framework/registry` for the publication candidate.
- **FR-008**: The command MUST open a pull request against `traverse-framework/registry` using `git` and `gh`, with a body that includes the relevant governing specs and validation evidence.
- **FR-009**: The command MUST preserve manual approval: no successful local command result may publish a capability without the registry PR being reviewed, approved, merged, and indexed by registry CI.
- **FR-010**: If PR creation fails after local branch or file creation, the command MUST report the partial state and next cleanup or retry command. It MUST NOT silently delete user work.
- **FR-011**: The command MUST support a dry-run mode that performs validation and reports the planned registry path, branch name, and PR title without writing to the registry repo.
- **FR-012**: The command MUST support JSON output suitable for automation.
- **FR-013**: The command MUST be idempotent enough for retry: re-running after a network or PR creation failure MUST detect existing prepared state and either reuse it or report the conflict explicitly.

### Registry Admission Parity (v1.1.0, Decision 109)

- **FR-014**: Before any registry write, in both dry-run and real runs, the command MUST check every registry admission rule that can be decided from the candidate contract JSON alone. Each failure MUST be a structured error whose code identifies the rule family and whose message names the governing registry spec and FR. Registry CI remains authoritative (see Out of Scope).
- **FR-015**: The command MUST NOT evaluate registry rules that need network access or files other than the candidate contract. Examples: fetching evidence-file digests, or cross-checking capability-src manifests in `--registry-repo`. Those rules remain registry-CI-only.
- **FR-016**: Because every publication adds a new `<namespace>/<id>/<version>` path (FR-006), the command MUST apply the registry's newly-added-contract gates to every candidate. Grandfathered shapes that the registry accepts only on already-published versions MUST be rejected.
- **FR-017**: The command MUST copy registry-only top-level fields from the author contract into the registry-bound contract verbatim. These include `use_cases`, `evidence` and `ai`. An absent or `null` field MUST be treated the way registry CI treats it; for example, `"ai": null` counts as an absent `ai`.
- **FR-018**: Applied to model attribution (registry `001` FR-017 and registry `026`), FR-014 means that a candidate with `ai.model_backed: true` MUST supply a non-empty object-shaped `ai.models`, and each entry MUST carry:
  - every registry FR-017 field;
  - an immutable upstream pin: `revision` is a 40- or 64-hex commit id, or `source_url` contains one;
  - a syntactically valid `spdx_expression`;
  - the parts of the registry `026` rights record that the contract alone decides: the rights enums (`unknown` rejected), the hard contradictions, `verification.status`, the shape of `license_files` / `notice_files` entries, the presence of the `derivation` key, and the shape of `data_obligations`.

  The command MUST NOT fetch model sources.
- **FR-019**: Parity with registry CI MUST be proven against a versioned accept/reject fixture corpus that the registry owns. Traverse MUST vendor a pinned copy. A CLI test MUST agree with the expected outcome of every fixture tagged `contract_decidable`, and MUST list every fixture tagged `ci_only` as skipped. Bumping the pin is the only way the local rule set changes.

## Command Shape

```bash
traverse-cli capability publish \
  --contract contracts/examples/traverse-starter/capabilities/process/contract.json \
  --artifact artifacts/process-agent.wasm \
  --registry-repo ../registry \
  --json
```

Successful JSON output after PR creation MUST include at least:

```json
{
  "status": "pr_opened",
  "registry_repo": "traverse-framework/registry",
  "branch": "publish/traverse-starter.process-1.0.0",
  "registry_path": "capabilities/traverse-starter/traverse-starter.process/1.0.0/contract.json",
  "pull_request_url": "https://github.com/traverse-framework/registry/pull/123"
}
```

## Acceptance Scenarios

1. **Given** a valid public capability contract and artifact, **When** `traverse-cli capability publish --json` runs, **Then** it opens a registry PR at the correct path with validation evidence in the body.
2. **Given** the source bundle is `scope: private`, **When** publish runs, **Then** it fails before branch or PR creation with an actionable private-scope refusal.
3. **Given** local validation fails, **When** publish runs, **Then** no registry branch or PR is created.
4. **Given** the target registry path already exists, **When** publish runs, **Then** it fails with an immutable-version conflict before modifying the registry checkout.
5. **Given** PR creation fails after a branch is prepared, **When** the command exits, **Then** JSON output reports the branch and files that remain for retry or cleanup.
6. **Given** a contract with `ai.model_backed: true` whose model pins `revision: "main"`, or omits the registry `026` rights record, **When** `capability publish --dry-run` runs, **Then** it fails with a model-attribution error naming the registry FR, and does not write to the registry.
7. **Given** a contract with `"ai": null`, **When** publish runs, **Then** it is treated as having no `ai` object.
8. **Given** the pinned registry admission corpus, **When** the CLI test suite runs, **Then** the outcome of every `contract_decidable` fixture matches the outcome the registry expects.

## Out of Scope

- Auto-merging registry PRs.
- Replacing registry CI validation.
- Third-party publisher onboarding and namespace claiming.
- Hosted publish APIs.
