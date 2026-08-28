// KKL Approvals — team
// Admin-only user invitation (deploy with "Enforce JWT" OFF; this function
// authenticates the caller itself and checks their role server-side).
// POST { email, display_name?, title?, role? }  → invites by email.
// POST { set_role: { id, role, active? } }      → change a user's role.
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
    const body = await req.json();
    const url = Deno.env.get("SUPABASE_URL")!;
    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    // authenticate caller and require admin
    const auth = req.headers.get("Authorization") ?? "";
    const { data: caller } = await createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: auth } },
    }).auth.getUser();
    if (!caller?.user) return j({ error: "sign in first" }, 401);
    const { data: me } = await admin.from("profiles").select("role").eq("id", caller.user.id).single();
    if (me?.role !== "admin") return j({ error: "admin only" }, 403);

    if (body.set_role) {
      const { id, role, active } = body.set_role;
      if (!id || !["staff", "finance", "admin"].includes(role)) return j({ error: "bad set_role" }, 400);
      const patch: Record<string, unknown> = { role };
      if (typeof active === "boolean") patch.active = active;
      const { error } = await admin.from("profiles").update(patch).eq("id", id);
      if (error) return j({ error: error.message }, 500);
      await admin.from("audit_events").insert({
        actor: caller.user.id, event: "ROLE_CHANGED", detail: { target: id, role, active },
      });
      return j({ ok: true });
    }

    const email = String(body.email ?? "").trim().toLowerCase();
    if (!email.includes("@")) return j({ error: "email required" }, 400);
    const { data: cfg } = await admin.from("settings").select("value").eq("key", "app_url").single();
    const appUrl = (typeof cfg?.value === "string" ? cfg.value : "") || undefined;

    const { data, error } = await admin.auth.admin.inviteUserByEmail(email, {
      data: { display_name: body.display_name ?? email.split("@")[0] },
      redirectTo: appUrl,
    });
    if (error) return j({ error: error.message }, 500);
    // profile row is created by the on_auth_user_created trigger; apply extras
    if (data.user) {
      await admin.from("profiles").update({
        title: body.title ?? null,
        role: ["staff", "finance", "admin"].includes(body.role) ? body.role : "staff",
      }).eq("id", data.user.id);
    }
    await admin.from("audit_events").insert({
      actor: caller.user.id, event: "USER_INVITED", detail: { email, role: body.role ?? "staff" },
    });
    return j({ ok: true, id: data.user?.id });
  } catch (e) {
    return j({ error: String((e as Error)?.message ?? e) }, 500);
  }
});
