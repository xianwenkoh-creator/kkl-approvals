// KKL Approvals — verify
// Public verification endpoint (deploy with "Enforce JWT" OFF).
// Two modes:
//   { ref, token }  — from the QR code on a certificate page
//   { sha256 }      — hash of a file someone dropped on the verify page
// Returns the approval facts for a match, or found:false. Never returns
// document contents — only the record that a given hash was approved.
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
};
const j = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { ref, token, sha256 } = await req.json();
    const db = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    let r: Record<string, unknown> | null = null;
    let matched: string | null = null;

    if (ref && token) {
      const q = await db.from("requests").select("*").eq("ref", ref).eq("verify_token", token).maybeSingle();
      r = q.data; matched = r ? "qr" : null;
    } else if (sha256 && /^[0-9a-f]{64}$/.test(String(sha256).toLowerCase())) {
      const h = String(sha256).toLowerCase();
      const sealed = await db.from("requests").select("*").eq("sealed_hash", h).maybeSingle();
      if (sealed.data) { r = sealed.data; matched = "sealed_pdf"; }
      else {
        const doc = await db.from("documents").select("request_id").eq("sha256", h).limit(1).maybeSingle();
        if (doc.data) {
          const q = await db.from("requests").select("*").eq("id", doc.data.request_id).maybeSingle();
          r = q.data; matched = "source_document";
        }
      }
    } else {
      return j({ error: "send { ref, token } or { sha256 }" }, 400);
    }

    if (!r) return j({ found: false, note: "No approval record matches. If this file claims to be sealed, it has been altered or was never sealed here." });

    const { data: steps } = await db.from("request_steps").select("stage,actor,step_type,status,acted_at")
      .eq("request_id", r.id).neq("status", "VOID").order("stage");
    const { data: decisions } = await db.from("decisions").select("actor,action,created_at,auth_level")
      .eq("request_id", r.id).order("created_at");
    const ids = [...new Set([...(steps ?? []).map((s) => s.actor), ...(decisions ?? []).map((d) => d.actor)])];
    const { data: profiles } = await db.from("profiles").select("id,display_name,title").in("id", ids);
    const who = Object.fromEntries((profiles ?? []).map((p) => [p.id, p]));

    return j({
      found: true,
      matched,                     // qr | sealed_pdf | source_document
      ref: r.ref, title: r.title, type: r.type, entity: r.entity,
      amount: r.amount, currency: r.currency, status: r.status,
      submitted_at: r.submitted_at, decided_at: r.decided_at,
      sealed: !!r.sealed_hash, sealed_hash: r.sealed_hash,
      doc_manifest: r.doc_manifest,
      trail: (decisions ?? []).map((d) => ({
        who: who[d.actor]?.display_name ?? "—", title: who[d.actor]?.title ?? "",
        action: d.action, at: d.created_at, auth: d.auth_level,
      })),
    });
  } catch (e) {
    return j({ error: String((e as Error)?.message ?? e) }, 500);
  }
});
