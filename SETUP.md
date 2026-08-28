# KKL Approvals — setup (one-time, ~20 minutes)

Internal approvals for KKLE: supplier/subcon awards + supplier invoices,
staged approval chains from an authority matrix, sealed PDFs with a
certificate of completion, append-only hash-chained audit trail.

**Deliberately a separate Supabase project from KKL CMS** — approvals are
server-authoritative (no offline writes), and pricing data gets its own key
and blast radius.

## 1 · Create the Supabase project
1. https://supabase.com/dashboard → New project → region **Southeast Asia (Singapore)**.
   Free tier is fine for the pilot (see the caveat at the bottom).
2. SQL Editor → paste the whole of `supabase/setup.sql` → Run.
   Creates tables, triggers, RLS, the three private buckets and seed settings.

## 2 · Deploy the three edge functions
Dashboard → Edge Functions → Create function, one per folder under
`supabase/functions/` (paste each `index.ts`):

| Function | Enforce JWT | Purpose |
|---|---|---|
| `seal`   | **ON**  | stamps + certificates the PDF on final approval |
| `verify` | **OFF** | public verification endpoint (QR / file-drop) |
| `team`   | **OFF** | admin-only invites & role changes (checks the caller itself) |

No secrets to set — they use the built-in `SUPABASE_SERVICE_ROLE_KEY`.

## 3 · Auth settings
Dashboard → Authentication:
- **Providers → Email**: leave enabled.
- **Sign-ups: DISABLE public sign-up** *after* step 5 (first sign-up becomes admin).
- **URL Configuration → Site URL**: the app URL (GitHub Pages URL once live).

## 4 · Configure the app
In `index.html`, fill in near the top:
```js
const DEFAULT_SB = { url: "https://<ref>.supabase.co", anon: "<anon key>" };
```
(Project Settings → API.) The anon key is public by design — every rule that
matters is enforced in Postgres RLS, not the browser.

Host: push this repo to GitHub, enable Pages (main / root). Or run locally:
`python -m http.server 8779` → http://127.0.0.1:8779/

## 5 · First user = admin
Temporarily leave sign-ups enabled, open the app, **sign up yourself first**
(first account is auto-admin), then disable public sign-ups. Invite everyone
else from **Admin → Invite**.

## 6 · Make it real
- **Admin → Authority matrix**: replace the placeholder emails/bands with the
  real chains. Approvers must be invited (active accounts) before routing.
- **Admin → App URL**: set it — it goes into QR codes and invite redirects.
- **Profile → Signature**: every approver draws theirs once.

## Microsoft 365 SSO (when IT is ready)
Dashboard → Authentication → Providers → **Azure** → follow the wizard
(needs an Entra app registration — ~15 min for an Entra admin; redirect URL
`https://<ref>.supabase.co/auth/v1/callback`). Existing accounts link by
email; no data migration. Until then: email + password.

## Free-tier caveat (agreed 28 Aug 2026)
No point-in-time recovery on free tier. Compensating control:
**Admin → Export archive (JSON)** regularly (weekly at least) into
OneDrive. Upgrade to the paid tier before the team stops double-entering
into Teams — at that point this becomes the system of record.

## Invite emails
Built-in mailer ≈ 2/hour on free tier. For real volume set custom SMTP:
Project Settings → Authentication → SMTP (an admin pastes the app password
there — it must not pass through Claude or the repo).
