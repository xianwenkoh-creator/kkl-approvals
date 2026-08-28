# KKL Approvals

Internal approval system for Koh Kock Leong Enterprise — replaces Teams
Approvals for supplier/subcon awards and supplier invoices.

- Single-file frontend (`index.html`), Supabase backend (own project, SG region)
- Staged approval chains (ALL / ANY / QUORUM) computed from an authority matrix
- Decisions bound to document SHA-256 hashes; changed docs reopen approvals
- Sealed PDF on final approval: signature block, per-page footer, certificate
  of completion, QR verification (public `#/verify` page)
- Append-only, hash-chained audit trail; approval status is trigger-computed —
  no client can ever set it
- NOT a notarised e-signature service — internal approvals only (see design brief)

Setup: `SETUP.md`. Schema + RLS: `supabase/setup.sql`. Edge functions:
`supabase/functions/{seal,verify,team}`.
