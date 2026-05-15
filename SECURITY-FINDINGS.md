# Security Review — Findings

**Repository:** `williaby/LifeSphere`
**Branch reviewed:** `claude/security-review-python-UmAxJ`
**Review date:** 2026-05-15
**Scope:** Source-code security review (Python) + GitHub Actions hardening

---

## 1. Scope clarification — no application source code present

The review brief described this as a Python application and asked for a code-level
security audit covering credential loading, route-handler authn/authz, database
query parameterization, and external API integration. **Those checks are
not applicable to the current contents of this repository.**

Tracked files in the repo (verified via `git ls-files`):

```
.github/workflows/pr-validation.yml
.github/workflows/repo-health.yml
.github/workflows/reuse.yml
.github/workflows/scorecard.yml
.github/workflows/security-analysis.yml
CODE_OF_CONDUCT.md
GOVERNANCE.md
LICENSES/MIT.txt
Privacy_policy
REUSE.toml
privacy_policy.md
renovate.json
```

There are **zero** `.py`, `.ipynb`, `requirements*.txt`, `pyproject.toml`,
`Pipfile`, `setup.py`, or `setup.cfg` files — no application source, no
dependency manifest, no route handlers, no database calls, no API client code
to audit. The repository at this point is governance (CODE_OF_CONDUCT,
GOVERNANCE, privacy policy), licensing (REUSE), and CI configuration only.

The following review items from the brief are therefore reported as
**Not Applicable — no code exists yet**:

| Brief item                                                 | Status |
|------------------------------------------------------------|--------|
| Identify core functionality from source code               | N/A — no source code |
| Credential / API key loading (must be env vars only)       | N/A — no code |
| Route handler authn/authz                                  | N/A — no code |
| Database query parameterization                            | N/A — no code |
| External API integration & credential handling             | N/A — no code |

This finding is itself worth noting: the security-analysis workflow
(`.github/workflows/security-analysis.yml`) currently disables every active
scanner (`run-safety: false`, `run-codeql: false`, `run-dependency-review: false`,
`run-osv: false`, `run-bandit: false`). That's defensible while the repo has no
code, but **must be re-enabled the moment Python source lands**, or none of the
SAST/SCA gates will actually run.

### Context for future code (from `privacy_policy.md` / `Privacy_policy`)

The privacy policy describes "LifeSphere GPT" as a system that, when implemented,
will handle high-sensitivity personal data: **insurance records, vehicle data,
treasury reports, family-member identity / age data, and Google Calendar event
content** (via a Zapier integration). When source code is added, the brief's
elevated-scrutiny criteria (health/financial/contact/location data) **will
apply** and should drive:

- Encryption at rest and in transit for all uploaded files and persisted state.
- Authentication on every route that touches user data; authorization checks
  per-resource (not per-route) so one user cannot read another's records.
- Strict parameterization of any DB queries; never f-string SQL.
- All credentials (Zapier webhook secret, Google Calendar OAuth client ID/secret,
  any LLM provider keys) loaded from environment variables only — never
  committed, never logged. Verify with a secret-scan job (`gitleaks`,
  `trufflehog`, or GitHub native secret scanning) before merge.
- Honor the "data deletion on request" and "no retention past session"
  commitments in `privacy_policy.md` §4 / §5 with concrete code paths and
  tests, not just policy text.
- A documented retention/erase path for any session metadata used for
  "troubleshooting" (§1.2) so it doesn't quietly turn into persistent logs.

Two cosmetic-but-real issues in the policy files themselves:

- `Privacy_policy` (the file without the `.md` extension) is a stale duplicate
  of `privacy_policy.md` with unfilled placeholders (`[Insert Date]`,
  `[Insert Contact Email or Phone]`). Two divergent privacy policies in a repo
  is a legal / compliance hazard — delete the stale one.
- `privacy_policy.md` §9 lists a personal Gmail address as the data-controller
  contact. For a system handling the data categories above, a dedicated
  privacy contact (and likely a postal address, per GDPR Art. 13 if EU users
  are in scope) is the safer pattern.

These are advisory — not fixed in this PR since they're outside the brief's
"applied fixes" scope and the duplicate-file deletion needs owner approval.

---

## 2. GitHub Actions audit & hardening

Reviewed all five workflow files. Two issues found; both fixed in this PR.

### 2.1 `pr-validation.yml` — already hardened (no change)

- Top-level `permissions: {}` ✔
- Per-job `permissions:` scoped to `pull-requests: read` ✔
- All `uses:` SHA-pinned (`step-security/harden-runner@91182ccc…`) ✔
- `harden-runner` step in every job with `egress-policy: audit` ✔
- User-controlled inputs (`github.event.pull_request.title`,
  `…body`) are passed through `env:` rather than direct `${{ … }}`
  expansion in `run:`, blocking shell-injection via crafted PR titles ✔

### 2.2 `repo-health.yml` — **FIXED**

**Before:** no `permissions:` block (job inherited the default
`GITHUB_TOKEN` permissions, which on this repo can be write-scoped depending
on org settings) and no `harden-runner` step.

**After:**

- Added top-level `permissions: {}` (deny-by-default).
- Added per-job `permissions: contents: read` (minimum needed; the job only
  runs `echo`, but explicit beats implicit).
- Added `step-security/harden-runner@a5ad31d6a139d249332a2605b85202e8c0b78450  # v2.19.1`
  with `egress-policy: audit`, matching the version already used in
  `reuse.yml`.

### 2.3 `reuse.yml` — **FIXED** (Docker image was tag-pinned, not digest-pinned)

All GitHub Action `uses:` are SHA-pinned correctly (`harden-runner@a5ad31d…`,
`actions/checkout@de0fac2…`, `fsfe/reuse-action@676e2d5…`,
`actions/upload-artifact@043fb46…`). However, the **SBOM-generation step**
ran:

```yaml
docker run --rm --volume $(pwd):/data fsfe/reuse:latest spdx --output /data/reuse-spdx.json
```

`fsfe/reuse:latest` is a mutable tag. Pinning every `uses:` to a SHA and then
running an unpinned `:latest` Docker image to generate your SBOM defeats the
point — an attacker who compromises the upstream image (or a typo-squat at
that registry path) gets arbitrary code execution inside CI with read access
to the repo checkout.

**After:** pinned to the current `:latest` digest (which today resolves to
`fsfe/reuse:6.2.0`):

```yaml
docker run --rm --volume "$(pwd):/data" \
  fsfe/reuse@sha256:85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e \
  spdx --output /data/reuse-spdx.json
```

Also added defensive quoting around `$(pwd)` (avoids volume-mount breakage if
the workspace path ever contains whitespace). Renovate's `github-actions`
manager won't catch this digest because it lives inside a `run:` block; future
bumps need to be manual or covered by a `regex` Renovate manager.

### 2.4 `scorecard.yml` — already hardened (no change)

- Top-level `permissions: contents: read` ✔
- Per-job permissions scoped (`security-events: write`, `id-token: write`,
  `contents: read`, `actions: read`) — all required by the OpenSSF Scorecard
  reusable workflow ✔
- Reusable workflow SHA-pinned (`ByronWilliamsCPA/.github/…@d18c930…`) ✔
- `harden-runner` not added at this layer — the caller delegates entirely to
  the reusable workflow, which is expected to do its own hardening. Confirm
  that the `ByronWilliamsCPA/.github` reusable workflow includes
  `harden-runner` at its leaf jobs (out of scope for this repo).

### 2.5 `security-analysis.yml` — already hardened (no change)

- Top-level `permissions: {}` ✔
- Per-job permissions scoped; `pull-requests: write` is broad but is the
  documented requirement for SARIF-comment-style scanners ✔
- Reusable workflow SHA-pinned (`ByronWilliamsCPA/.github/…@c22009c…`) ✔
- Gate job runs `harden-runner` ✔
- **Caveat (already noted in §1):** every scanner is currently disabled via
  inputs. This is a configuration finding, not a hardening finding — re-enable
  them before merging Python code.

---

## 3. Other observations (not fixed in this PR)

| # | Item | Severity | Recommendation |
|---|---|---|---|
| O-1 | `Privacy_policy` (no extension) is a stale duplicate of `privacy_policy.md` with placeholder text | Low (legal/compliance) | Delete `Privacy_policy`; keep `privacy_policy.md` as canonical. |
| O-2 | Privacy contact is a personal Gmail address | Low | Use a role-based contact (e.g. `privacy@…`) before any production launch. |
| O-3 | `security-analysis.yml` disables every scanner | Medium (will be High once code lands) | Re-enable `run-safety`, `run-codeql`, `run-osv`, `run-bandit`, `run-dependency-review` once Python sources exist. |
| O-4 | No secret-scanning workflow (gitleaks/trufflehog) in the repo | Medium | Add a pre-commit / CI secret scan before the first source-code PR. GitHub native push-protection is also worth enabling at org level. |
| O-5 | Docker image versions inside `run:` blocks aren't tracked by Renovate's `github-actions` manager | Low | Add a Renovate `regexManagers` rule for `fsfe/reuse@sha256:…` so digest bumps are automated, or migrate the SPDX step to invoke `fsfe/reuse-action` directly with `args: spdx`. |
| O-6 | `repo-health.yml` runs on every `push` / `pull_request` and does nothing but `echo` | Informational | Either give it a real check or drop it — empty status checks blur the signal when a real one fails. |

---

## 4. Files changed in this PR

- `.github/workflows/repo-health.yml` — added `permissions: {}`, per-job
  `contents: read`, and a `harden-runner` step.
- `.github/workflows/reuse.yml` — pinned the `fsfe/reuse` Docker image to a
  `sha256:` digest and quoted `$(pwd)`.
- `SECURITY-FINDINGS.md` — this report.
