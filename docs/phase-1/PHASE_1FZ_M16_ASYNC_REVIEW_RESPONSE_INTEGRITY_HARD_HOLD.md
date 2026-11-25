# Phase 1FZ — M16 asynchronous ticket review integrity (HARD HOLD)

24 November 2026 IST. Development branch only.

## Defects and controls

Out-of-order ticket detail, list, history and fingerprint requests could previously overwrite newer selection or loading state. Even a fingerprint of an earlier version of the same ticket could remain visible. The new read gate issues unique in-memory tokens by lane (list/detail/history/fingerprint). Refresh invalidates the selected detail and all dependent review tokens, and supersedes older ticket list requests. Selecting or re-opening a ticket clears previous detail, history, fingerprint and transition form; detail is accepted only if its ID matches the requested ticket and held-only state/version/history shape is valid. All four read lanes guard success, error and finally updates. Unmount invalidates pending read tokens. Existing customer request epoch is preserved.

Older history is applied only to matching ticket ID/version; displayed fingerprint must match both ticket ID and version. Status and create handlers use a synchronous in-flight ref to reject duplicate writes while pending, and disable ticket switching/refresh controls during writes; successful mutations refresh and reopen the affected ticket. These are UI concurrency protections, not server-side permission checks, cancellation of server work, or independently authenticated evidence. The existing server OWNER, CSRF, optimistic-version and audit guards remain authoritative.

## Verification

Deferred-promise unit regression exercises older response completing after a new selection, stale loading/error suppression, invalidated history and fingerprint, same-lane replacement and unmount invalidation. Source-contract tests check integration of all four lanes, ticket identity/version checks, fingerprint display pinning and write-in-flight guard. Full baseline/build and disposable MySQL/browser regression workflows must pass at exact latest HEAD before integrated verification.

No schema change, new permissions, external dispatch, production operation or evidence rewrite. Actual network/browser race behavior beyond these tests and independent staging remain unverified. M16 SERVER_INTERNAL_HELD, all M01–M30 independent external acceptance OPEN; production HARD HOLD. Keep main unchanged, PR #1 Draft/unmerged and Issue #2 open.
