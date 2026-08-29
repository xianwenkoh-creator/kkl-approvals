-- ============================================================
-- KKL Approvals — Supabase setup (run once, whole file, SQL Editor)
-- Server-authoritative approvals: requests / steps / decisions.
-- The client can NEVER set request status — a trigger computes it
-- from decision rows. Audit log is append-only with a hash chain.
-- ============================================================
create extension if not exists pgcrypto;

-- ---------------- tables ----------------
create table if not exists public.profiles (
  id             uuid primary key references auth.users(id) on delete cascade,
  email          text unique,
  display_name   text,
  title          text,                      -- e.g. "Project Manager"
  role           text not null default 'staff'
                 check (role in ('staff','finance','admin')),
  signature_path text,                      -- sigs bucket object, set by the app
  active         boolean not null default true,
  created_at     timestamptz not null default now()
);

create table if not exists public.settings (
  key        text primary key,
  value      jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid
);

create table if not exists public.requests (
  id            uuid primary key default gen_random_uuid(),
  ref           text unique,                -- AWD-2026-0001 / INV-2026-0001, set on submit
  type          text not null check (type in ('award','invoice')),
  entity        text not null default 'KKLE',
  title         text not null,
  project       text,
  supplier      text,
  amount        numeric(14,2) not null default 0,
  currency      text not null default 'SGD',
  form          jsonb not null default '{}'::jsonb,   -- typed fields per request type
  award_id      uuid references public.requests(id),  -- invoice -> the award that authorised it
  requester     uuid not null references public.profiles(id),
  status        text not null default 'DRAFT'
                check (status in ('DRAFT','PENDING','RETURNED','APPROVED','REJECTED','WITHDRAWN')),
  current_stage int  not null default 0,
  doc_manifest  text,                       -- sha256 over the ordered doc hashes
  sealed_path   text,                       -- sealed bucket object
  sealed_hash   text,                       -- sha256 of the sealed pdf
  verify_token  text,                       -- QR verification token
  created_at    timestamptz not null default now(),
  submitted_at  timestamptz,
  decided_at    timestamptz
);
create index if not exists requests_requester_idx on public.requests (requester, status);
create index if not exists requests_award_idx     on public.requests (award_id);

create table if not exists public.request_steps (
  id         uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.requests(id) on delete cascade,
  stage      int  not null,
  actor      uuid not null references public.profiles(id),
  step_type  text not null default 'DECIDE'
             check (step_type in ('DECIDE','REVIEW','ACK','WATCH')),
  rule       text not null default 'ALL' check (rule in ('ALL','ANY','QUORUM')),
  quorum     int,
  status     text not null default 'PENDING'
             check (status in ('PENDING','APPROVED','REJECTED','RETURNED','COMMENTED','ACKED','VOID')),
  acted_at   timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists steps_actor_idx   on public.request_steps (actor, status);
create index if not exists steps_request_idx on public.request_steps (request_id, stage);

-- Immutable. One row per act; never updated, never deleted.
create table if not exists public.decisions (
  id           uuid primary key default gen_random_uuid(),
  step_id      uuid not null references public.request_steps(id),
  request_id   uuid not null references public.requests(id),
  actor        uuid not null references public.profiles(id),
  action       text not null check (action in ('APPROVE','REJECT','RETURN','COMMENT','ACK')),
  comment      text,
  doc_manifest text,     -- server-stamped: what documents this decision was made against
  auth_level   text,     -- aal1 / aal2 from the JWT, server-stamped
  created_at   timestamptz not null default now()
);
create index if not exists decisions_request_idx on public.decisions (request_id);

create table if not exists public.documents (
  id           uuid primary key default gen_random_uuid(),
  request_id   uuid not null references public.requests(id) on delete cascade,
  name         text not null,
  mime         text,
  size         bigint,
  sha256       text not null,
  storage_path text not null,
  uploaded_by  uuid not null references public.profiles(id),
  superseded   boolean not null default false,
  created_at   timestamptz not null default now()
);
create index if not exists documents_request_idx on public.documents (request_id);
create index if not exists documents_hash_idx    on public.documents (sha256);

-- Append-only, hash-chained. at_key is the canonical timestamp string
-- that goes into the hash, so the chain can be re-verified from any client.
create table if not exists public.audit_events (
  seq        bigserial primary key,
  at         timestamptz not null default now(),
  at_key     text,
  actor      uuid,
  request_id uuid,
  event      text not null,
  detail     jsonb not null default '{}'::jsonb,
  prev_hash  text,
  hash       text
);

create table if not exists public.ref_counters (
  year int not null, type text not null, n int not null default 0,
  primary key (year, type)
);

-- ---------------- helpers ----------------
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as
$$ select role from public.profiles where id = auth.uid() $$;

-- service-role or in-trigger internal context?
create or replace function public.is_internal() returns boolean
language sql stable as $$
  select coalesce(current_setting('app.internal', true), '') = '1'
      or coalesce((current_setting('request.jwt.claims', true))::jsonb->>'role','') = 'service_role'
$$;

create or replace function public.can_see(p_request uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.requests r where r.id = p_request
                   and (r.requester = auth.uid()
                        or public.my_role() in ('finance','admin')))
      or exists (select 1 from public.request_steps s
                  where s.request_id = p_request and s.actor = auth.uid())
$$;

create or replace function public.next_ref(p_type text) returns text
language plpgsql security definer set search_path = public as $$
declare v_year int := extract(year from now())::int; v_n int;
begin
  insert into public.ref_counters(year, type, n) values (v_year, p_type, 1)
  on conflict (year, type) do update set n = public.ref_counters.n + 1
  returning n into v_n;
  return case p_type when 'award' then 'AWD' else 'INV' end
         || '-' || v_year || '-' || lpad(v_n::text, 4, '0');
end $$;

-- ---------------- audit: append-only + hash chain ----------------
create or replace function public.log_event(
  p_request uuid, p_event text, p_detail jsonb default '{}'::jsonb
) returns void language plpgsql security definer set search_path = public as $$
begin
  perform set_config('app.internal', '1', true);
  insert into public.audit_events (actor, request_id, event, detail)
  values (auth.uid(), p_request, p_event, coalesce(p_detail, '{}'::jsonb));
end $$;

create or replace function public.audit_chain() returns trigger
language plpgsql set search_path = public, extensions as $$
declare v_prev text;
begin
  select hash into v_prev from public.audit_events
   order by seq desc limit 1;
  new.at       := now();
  new.at_key   := to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  new.prev_hash := coalesce(v_prev, 'GENESIS');
  new.hash := encode(digest(
      new.prev_hash || '|' || new.at_key || '|' || coalesce(new.actor::text,'') || '|'
      || coalesce(new.request_id::text,'') || '|' || new.event || '|' || new.detail::text,
      'sha256'), 'hex');
  return new;
end $$;
drop trigger if exists audit_chain_t on public.audit_events;
create trigger audit_chain_t before insert on public.audit_events
  for each row execute function public.audit_chain();

create or replace function public.audit_freeze() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_events is append-only';
end $$;
drop trigger if exists audit_freeze_t on public.audit_events;
create trigger audit_freeze_t before update or delete on public.audit_events
  for each row execute function public.audit_freeze();
revoke update, delete on public.audit_events from anon, authenticated;

-- ---------------- first user becomes admin ----------------
create or replace function public.handle_new_user() returns trigger
security definer set search_path = public language plpgsql as $$
declare v_role text;
begin
  select case when exists(select 1 from public.profiles) then 'staff' else 'admin' end
    into v_role;
  insert into public.profiles (id, email, role,
      display_name)
  values (new.id, new.email, v_role,
      coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------- column guards ----------------
-- Clients may edit a request's content only in DRAFT / RETURNED, and may
-- never touch the protected state columns. All state moves happen inside
-- security-definer functions that set app.internal.
create or replace function public.requests_guard() returns trigger
language plpgsql as $$
begin
  if public.is_internal() then return new; end if;
  if old.status not in ('DRAFT','RETURNED') then
    raise exception 'request is % — content is locked', old.status;
  end if;
  if new.status       is distinct from old.status
     or new.current_stage is distinct from old.current_stage
     or new.doc_manifest  is distinct from old.doc_manifest
     or new.sealed_path   is distinct from old.sealed_path
     or new.sealed_hash   is distinct from old.sealed_hash
     or new.verify_token  is distinct from old.verify_token
     or new.ref           is distinct from old.ref
     or new.requester     is distinct from old.requester
     or new.submitted_at  is distinct from old.submitted_at
     or new.decided_at    is distinct from old.decided_at then
    raise exception 'protected columns are server-managed';
  end if;
  return new;
end $$;
drop trigger if exists requests_guard_t on public.requests;
create trigger requests_guard_t before update on public.requests
  for each row execute function public.requests_guard();

create or replace function public.profiles_guard() returns trigger
language plpgsql as $$
begin
  if public.is_internal() or public.my_role() = 'admin' then return new; end if;
  if new.role is distinct from old.role or new.active is distinct from old.active
     or new.email is distinct from old.email then
    raise exception 'role / active / email are admin-managed';
  end if;
  return new;
end $$;
drop trigger if exists profiles_guard_t on public.profiles;
create trigger profiles_guard_t before update on public.profiles
  for each row execute function public.profiles_guard();

-- decisions are immutable
create or replace function public.decisions_freeze() returns trigger
language plpgsql as $$
begin raise exception 'decisions are immutable'; end $$;
drop trigger if exists decisions_freeze_t on public.decisions;
create trigger decisions_freeze_t before update or delete on public.decisions
  for each row execute function public.decisions_freeze();
revoke update, delete on public.decisions from anon, authenticated;

-- ---------------- decision intake ----------------
-- Server stamps actor, the doc manifest and the auth level; the client's
-- values for those fields are ignored. Action must match the step type.
create or replace function public.decisions_before() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_step public.request_steps; v_req public.requests;
begin
  select * into v_step from public.request_steps where id = new.step_id;
  select * into v_req  from public.requests where id = v_step.request_id;
  new.actor        := auth.uid();
  new.request_id   := v_step.request_id;
  new.doc_manifest := v_req.doc_manifest;
  new.auth_level   := coalesce((current_setting('request.jwt.claims', true))::jsonb->>'aal', 'aal1');
  new.created_at   := now();
  if v_step.step_type = 'DECIDE' and new.action not in ('APPROVE','REJECT','RETURN') then
    raise exception 'a DECIDE step takes APPROVE / REJECT / RETURN';
  elsif v_step.step_type = 'REVIEW' and new.action <> 'COMMENT' then
    raise exception 'a REVIEW step takes COMMENT';
  elsif v_step.step_type = 'ACK' and new.action <> 'ACK' then
    raise exception 'an ACK step takes ACK';
  elsif v_step.step_type = 'WATCH' then
    raise exception 'a WATCH step takes no action';
  end if;
  if new.action = 'COMMENT' and coalesce(trim(new.comment),'') = '' then
    raise exception 'a review must include a comment';
  end if;
  return new;
end $$;
drop trigger if exists decisions_before_t on public.decisions;
create trigger decisions_before_t before insert on public.decisions
  for each row execute function public.decisions_before();

-- ---------------- the state machine ----------------
-- Approval is a CONSEQUENCE of decision rows. Nothing else sets status.
create or replace function public.apply_decision() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_step  public.request_steps;
  v_req   public.requests;
  v_total int; v_ok int; v_rule text; v_quorum int;
  v_reviews_open int; v_next int;
begin
  perform set_config('app.internal', '1', true);
  select * into v_step from public.request_steps where id = new.step_id;
  select * into v_req  from public.requests where id = new.request_id;

  update public.request_steps
     set status = case new.action
                    when 'APPROVE' then 'APPROVED'
                    when 'REJECT'  then 'REJECTED'
                    when 'RETURN'  then 'RETURNED'
                    when 'COMMENT' then 'COMMENTED'
                    when 'ACK'     then 'ACKED' end,
         acted_at = now()
   where id = new.step_id;

  perform public.log_event(new.request_id, 'DECISION',
    jsonb_build_object('step', v_step.id, 'stage', v_step.stage,
                       'action', new.action, 'auth', new.auth_level,
                       'manifest', new.doc_manifest));

  if new.action = 'REJECT' then
    update public.requests set status = 'REJECTED', decided_at = now()
     where id = new.request_id;
    update public.request_steps set status = 'VOID'
     where request_id = new.request_id and status = 'PENDING';
    perform public.log_event(new.request_id, 'REJECTED', '{}'::jsonb);
    return new;
  end if;

  if new.action = 'RETURN' then
    update public.requests set status = 'RETURNED'
     where id = new.request_id;
    update public.request_steps set status = 'VOID'
     where request_id = new.request_id and status = 'PENDING';
    perform public.log_event(new.request_id, 'RETURNED', '{}'::jsonb);
    return new;
  end if;

  -- Stage completion: DECIDE steps by the stage rule; REVIEW steps must
  -- have commented; ACK / WATCH never block.
  select count(*) filter (where step_type = 'DECIDE'),
         count(*) filter (where step_type = 'DECIDE' and status = 'APPROVED'),
         max(rule) filter (where step_type = 'DECIDE'),
         max(quorum) filter (where step_type = 'DECIDE'),
         count(*) filter (where step_type = 'REVIEW' and status = 'PENDING')
    into v_total, v_ok, v_rule, v_quorum, v_reviews_open
    from public.request_steps
   where request_id = new.request_id and stage = v_step.stage and status <> 'VOID';

  if v_reviews_open > 0 then return new; end if;
  if v_total > 0 then
    if (v_rule = 'ANY'    and v_ok < 1)
    or (v_rule = 'QUORUM' and v_ok < coalesce(v_quorum, v_total))
    or (v_rule = 'ALL'    and v_ok < v_total) then
      return new;                                   -- stage still open
    end if;
  end if;

  -- stage satisfied: void the no-longer-needed pending steps in it
  update public.request_steps set status = 'VOID'
   where request_id = new.request_id and stage = v_step.stage
     and status = 'PENDING' and step_type in ('DECIDE','REVIEW');

  select min(stage) into v_next from public.request_steps
   where request_id = new.request_id and stage > v_step.stage
     and status = 'PENDING';

  if v_next is not null then
    update public.requests set current_stage = v_next where id = new.request_id;
    perform public.log_event(new.request_id, 'STAGE_ADVANCED',
      jsonb_build_object('to', v_next));
  else
    update public.requests set status = 'APPROVED', decided_at = now()
     where id = new.request_id;
    update public.request_steps set status = 'VOID'
     where request_id = new.request_id and status = 'PENDING'
       and step_type in ('DECIDE','REVIEW');
    perform public.log_event(new.request_id, 'APPROVED', '{}'::jsonb);
  end if;
  return new;
end $$;
drop trigger if exists apply_decision_t on public.decisions;
create trigger apply_decision_t after insert on public.decisions
  for each row execute function public.apply_decision();

-- ---------------- documents bind decisions to content ----------------
-- Adding a document to a PENDING request changes the manifest, which
-- VOIDS completed approvals up to the current stage and reopens them.
create or replace function public.documents_after() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare v_req public.requests; v_manifest text; v_first int;
begin
  perform set_config('app.internal', '1', true);
  select * into v_req from public.requests where id = new.request_id;

  select encode(digest(string_agg(sha256, '|' order by sha256), 'sha256'), 'hex')
    into v_manifest
    from public.documents
   where request_id = new.request_id and not superseded;

  update public.requests set doc_manifest = v_manifest where id = new.request_id;
  perform public.log_event(new.request_id, 'DOCUMENT_ADDED',
    jsonb_build_object('doc', new.id, 'name', new.name, 'sha256', new.sha256,
                       'manifest', v_manifest));

  if v_req.status = 'PENDING' then
    update public.request_steps
       set status = 'PENDING', acted_at = null
     where request_id = new.request_id
       and stage <= v_req.current_stage
       and step_type in ('DECIDE','REVIEW')
       and status in ('APPROVED','COMMENTED','VOID');
    select min(stage) into v_first from public.request_steps
     where request_id = new.request_id and status = 'PENDING';
    update public.requests set current_stage = coalesce(v_first, v_req.current_stage)
     where id = new.request_id;
    perform public.log_event(new.request_id, 'REOPENED',
      jsonb_build_object('reason', 'documents changed after approval started'));
  end if;
  return new;
end $$;
drop trigger if exists documents_after_t on public.documents;
create trigger documents_after_t after insert on public.documents
  for each row execute function public.documents_after();

revoke update, delete on public.documents from anon, authenticated;

-- ---------------- submit / withdraw ----------------
-- Builds the approval chain from the authority matrix in settings.matrix:
-- { "award":   { "bands": [ { "max": 5000, "stages": [ { "rule":"ANY",
--   "steps":[ {"email":"pm@kkl.sg","type":"DECIDE"} ] } ] }, ... ] },
--   "invoice": { ... } }
-- Last band may omit "max" (open-ended). An award over its budget
-- allowance by more than settings.overbudget_pct bumps one band up.
create or replace function public.submit_request(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_req    public.requests;
  v_matrix jsonb; v_bands jsonb; v_band jsonb; v_stage jsonb; v_stepj jsonb;
  v_idx int := 0; v_pick int := -1; v_i int; v_stage_no int := 0;
  v_actor uuid; v_email text; v_missing text[] := '{}';
  v_manifest text; v_budget numeric; v_pct numeric;
begin
  perform set_config('app.internal', '1', true);
  select * into v_req from public.requests where id = p_id;
  if v_req.id is null or v_req.requester <> auth.uid() then
    raise exception 'not your request';
  end if;
  if v_req.status not in ('DRAFT','RETURNED') then
    raise exception 'only a draft or returned request can be submitted';
  end if;
  if v_req.amount <= 0 then raise exception 'amount must be positive'; end if;
  if not exists (select 1 from public.documents
                  where request_id = p_id and not superseded) then
    raise exception 'attach at least one document before submitting';
  end if;
  if v_req.type = 'invoice' then
    if v_req.award_id is null then
      raise exception 'an invoice must reference its approved award';
    end if;
    if not exists (select 1 from public.requests
                    where id = v_req.award_id and type = 'award' and status = 'APPROVED') then
      raise exception 'the referenced award is not approved';
    end if;
  end if;

  select value into v_matrix from public.settings where key = 'matrix';
  v_bands := v_matrix -> v_req.type -> 'bands';
  if v_bands is null then raise exception 'no authority matrix for type %', v_req.type; end if;

  for v_i in 0 .. jsonb_array_length(v_bands) - 1 loop
    v_band := v_bands -> v_i;
    if v_band ? 'max' then
      if v_req.amount <= (v_band->>'max')::numeric then v_pick := v_i; exit; end if;
    else
      v_pick := v_i; exit;
    end if;
  end loop;
  if v_pick < 0 then v_pick := jsonb_array_length(v_bands) - 1; end if;

  -- over-budget modifier: awards only
  if v_req.type = 'award' then
    v_budget := nullif(v_req.form->>'budget','')::numeric;
    select coalesce((value->>0)::numeric, 10) into v_pct
      from public.settings where key = 'overbudget_pct';
    if v_budget is not null and v_budget > 0
       and v_req.amount > v_budget * (1 + coalesce(v_pct,10)/100.0)
       and v_pick < jsonb_array_length(v_bands) - 1 then
      v_pick := v_pick + 1;
    end if;
  end if;

  -- fresh chain every submission; old steps become historical
  update public.request_steps set status = 'VOID'
   where request_id = p_id and status = 'PENDING';

  v_band := v_bands -> v_pick;
  for v_idx in 0 .. jsonb_array_length(v_band->'stages') - 1 loop
    v_stage := v_band->'stages'->v_idx;
    v_stage_no := v_idx + 1;
    for v_i in 0 .. jsonb_array_length(v_stage->'steps') - 1 loop
      v_stepj := v_stage->'steps'->v_i;
      v_email := lower(trim(v_stepj->>'email'));
      select id into v_actor from public.profiles
       where lower(email) = v_email and active;
      if v_actor is null then
        v_missing := array_append(v_missing, v_email);
      else
        insert into public.request_steps
          (request_id, stage, actor, step_type, rule, quorum)
        values (p_id, v_stage_no, v_actor,
                coalesce(upper(v_stepj->>'type'), 'DECIDE'),
                coalesce(upper(v_stage->>'rule'), 'ALL'),
                nullif(v_stage->>'quorum','')::int);
      end if;
    end loop;
  end loop;
  if array_length(v_missing, 1) > 0 then
    raise exception 'no active account for approver(s): % — invite them first',
      array_to_string(v_missing, ', ');
  end if;

  select encode(digest(string_agg(sha256, '|' order by sha256), 'sha256'), 'hex')
    into v_manifest from public.documents
   where request_id = p_id and not superseded;

  update public.requests
     set status = 'PENDING',
         current_stage = 1,
         submitted_at = now(),
         doc_manifest = v_manifest,
         ref = coalesce(ref, public.next_ref(v_req.type)),
         verify_token = coalesce(verify_token, encode(gen_random_bytes(12), 'hex'))
   where id = p_id;

  perform public.log_event(p_id, 'SUBMITTED',
    jsonb_build_object('band', v_pick, 'amount', v_req.amount, 'manifest', v_manifest));
  return jsonb_build_object('ok', true, 'band', v_pick);
end $$;

create or replace function public.withdraw_request(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  perform set_config('app.internal', '1', true);
  update public.requests set status = 'WITHDRAWN', decided_at = now()
   where id = p_id and requester = auth.uid() and status in ('PENDING','RETURNED');
  if not found then raise exception 'only your own pending request can be withdrawn'; end if;
  update public.request_steps set status = 'VOID'
   where request_id = p_id and status = 'PENDING';
  perform public.log_event(p_id, 'WITHDRAWN', '{}'::jsonb);
end $$;

-- ---------------- award exposure (the overrun control) ----------------
create or replace function public.award_exposure(p_award uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_award numeric; v_approved numeric; v_pending numeric;
begin
  if not public.can_see(p_award) then raise exception 'no access'; end if;
  select amount into v_award from public.requests
   where id = p_award and type = 'award';
  select coalesce(sum(amount) filter (where status = 'APPROVED'), 0),
         coalesce(sum(amount) filter (where status in ('PENDING','RETURNED')), 0)
    into v_approved, v_pending
    from public.requests where award_id = p_award and type = 'invoice';
  return jsonb_build_object('award', v_award, 'invoiced_approved', v_approved,
                            'invoiced_pending', v_pending);
end $$;

-- audit read for a request the caller can see (definer fn, not table grant)
create or replace function public.request_audit(p_request uuid)
returns setof public.audit_events
language sql stable security definer set search_path = public as $$
  select * from public.audit_events
   where request_id = p_request and public.can_see(p_request)
   order by seq
$$;

-- full-chain verification: recompute every hash, report first break
create or replace function public.verify_chain() returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare r record; v_prev text := 'GENESIS'; v_calc text; v_n int := 0;
begin
  if public.my_role() not in ('admin','finance') then raise exception 'admin/finance only'; end if;
  for r in select * from public.audit_events order by seq loop
    v_calc := encode(digest(
      v_prev || '|' || r.at_key || '|' || coalesce(r.actor::text,'') || '|'
      || coalesce(r.request_id::text,'') || '|' || r.event || '|' || r.detail::text,
      'sha256'), 'hex');
    if v_calc <> r.hash or r.prev_hash <> v_prev then
      return jsonb_build_object('ok', false, 'break_at_seq', r.seq, 'checked', v_n);
    end if;
    v_prev := r.hash; v_n := v_n + 1;
  end loop;
  return jsonb_build_object('ok', true, 'checked', v_n, 'head', v_prev);
end $$;

-- ---------------- row-level security ----------------
alter table public.profiles      enable row level security;
alter table public.settings      enable row level security;
alter table public.requests      enable row level security;
alter table public.request_steps enable row level security;
alter table public.decisions     enable row level security;
alter table public.documents     enable row level security;
alter table public.audit_events  enable row level security;
alter table public.ref_counters  enable row level security;

drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles
  for select using (auth.uid() is not null);   -- roster needed to show chains

drop policy if exists profiles_self_update on public.profiles;
create policy profiles_self_update on public.profiles
  for update using (id = auth.uid() or public.my_role() = 'admin')
  with check (id = auth.uid() or public.my_role() = 'admin');

drop policy if exists settings_read on public.settings;
create policy settings_read on public.settings
  for select using (auth.uid() is not null);

drop policy if exists settings_admin_write on public.settings;
create policy settings_admin_write on public.settings
  for all using (public.my_role() = 'admin')
  with check (public.my_role() = 'admin');

drop policy if exists requests_read on public.requests;
create policy requests_read on public.requests
  for select using (
    requester = auth.uid()
    or public.my_role() in ('finance','admin')
    or exists (select 1 from public.request_steps s
                where s.request_id = id and s.actor = auth.uid()));

drop policy if exists requests_insert on public.requests;
create policy requests_insert on public.requests
  for insert with check (requester = auth.uid() and status = 'DRAFT');

drop policy if exists requests_owner_update on public.requests;
create policy requests_owner_update on public.requests
  for update using (requester = auth.uid())
  with check (requester = auth.uid());
-- (content lock + protected columns enforced by requests_guard trigger)

drop policy if exists steps_read on public.request_steps;
create policy steps_read on public.request_steps
  for select using (public.can_see(request_id));
-- no client write policies: steps are built and moved by definer functions

-- THE core policy: a decision may only be inserted by the assigned actor,
-- on a step that is pending, in the stage the request is actually on.
drop policy if exists decisions_insert on public.decisions;
create policy decisions_insert on public.decisions
  for insert with check (
    exists (select 1
              from public.request_steps s
              join public.requests r on r.id = s.request_id
             where s.id = step_id
               and s.actor  = auth.uid()
               and s.status = 'PENDING'
               and s.stage  = r.current_stage
               and r.status = 'PENDING'));

drop policy if exists decisions_read on public.decisions;
create policy decisions_read on public.decisions
  for select using (public.can_see(request_id));

drop policy if exists documents_read on public.documents;
create policy documents_read on public.documents
  for select using (public.can_see(request_id));

drop policy if exists documents_insert on public.documents;
create policy documents_insert on public.documents
  for insert with check (
    uploaded_by = auth.uid()
    and exists (select 1 from public.requests r
                 where r.id = request_id and r.requester = auth.uid()
                   and r.status in ('DRAFT','RETURNED','PENDING')));

-- audit: no direct client access at all; read via request_audit()/verify_chain()
-- ref_counters: no client policies (definer functions only)

-- ---------------- storage ----------------
insert into storage.buckets (id, name, public) values
  ('docs','docs',false), ('sigs','sigs',false), ('sealed','sealed',false)
on conflict (id) do nothing;

drop policy if exists docs_ins on storage.objects;
create policy docs_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'docs');
drop policy if exists docs_read on storage.objects;
create policy docs_read on storage.objects for select to authenticated
  using (bucket_id in ('docs','sealed'));
-- (objects live under req/<uuid>/ — unguessable paths; listing is not granted)

drop policy if exists sigs_ins on storage.objects;
create policy sigs_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'sigs' and name = 'sig/' || auth.uid()::text || '.png');
drop policy if exists sigs_upd on storage.objects;
create policy sigs_upd on storage.objects for update to authenticated
  using (bucket_id = 'sigs' and name = 'sig/' || auth.uid()::text || '.png')
  with check (bucket_id = 'sigs' and name = 'sig/' || auth.uid()::text || '.png');
drop policy if exists sigs_read_own on storage.objects;
create policy sigs_read_own on storage.objects for select to authenticated
  using (bucket_id = 'sigs' and name = 'sig/' || auth.uid()::text || '.png');
-- signatures are otherwise only ever read server-side by the seal function

-- ---------------- seed settings ----------------
insert into public.settings (key, value) values
  ('overbudget_pct', '10'::jsonb),
  ('app_url', '""'::jsonb),
  ('matrix', '{
    "award": { "bands": [
      { "max": 5000,   "stages": [
        { "rule": "ANY", "steps": [ { "email": "pm@example.com", "type": "DECIDE" } ] } ] },
      { "max": 50000,  "stages": [
        { "rule": "ANY", "steps": [ { "email": "pm@example.com", "type": "DECIDE" } ] },
        { "rule": "ANY", "steps": [ { "email": "qs@example.com", "type": "DECIDE" } ] } ] },
      { "max": 250000, "stages": [
        { "rule": "ANY", "steps": [ { "email": "pm@example.com", "type": "DECIDE" } ] },
        { "rule": "ANY", "steps": [ { "email": "qs@example.com", "type": "DECIDE" } ] },
        { "rule": "ANY", "steps": [ { "email": "director@example.com", "type": "DECIDE" } ] } ] },
      { "stages": [
        { "rule": "ANY", "steps": [ { "email": "pm@example.com", "type": "DECIDE" } ] },
        { "rule": "ANY", "steps": [ { "email": "qs@example.com", "type": "DECIDE" } ] },
        { "rule": "ALL", "steps": [ { "email": "director@example.com", "type": "DECIDE" },
                                    { "email": "director2@example.com", "type": "DECIDE" } ] } ] }
    ] },
    "invoice": { "bands": [
      { "max": 50000, "stages": [
        { "rule": "ANY", "steps": [ { "email": "qs@example.com", "type": "DECIDE" } ] } ] },
      { "stages": [
        { "rule": "ANY", "steps": [ { "email": "qs@example.com", "type": "DECIDE" } ] },
        { "rule": "ANY", "steps": [ { "email": "director@example.com", "type": "DECIDE" } ] } ] }
    ] }
  }'::jsonb)
on conflict (key) do nothing;
