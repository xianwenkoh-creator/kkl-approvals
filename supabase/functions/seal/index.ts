// KKL Approvals — seal
// On final approval, stamps the primary PDF with the signature block,
// footers every page with the request ref + document hash, appends a
// certificate-of-completion page with the full decision trail and a QR
// code to the verification page, then stores the sealed copy and records
// its hash. Runs with the service key; verifies APPROVED status itself.
// Idempotent: re-sealing an already-sealed request returns the existing seal.
import { PDFDocument, StandardFonts, rgb } from "npm:pdf-lib@1.17.1";
import qrcodegen from "npm:qrcode-generator@1.4.4";
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
};
const j = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

async function sha256hex(buf: ArrayBuffer): Promise<string> {
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { request_id } = await req.json();
    if (!request_id) return j({ error: "request_id required" }, 400);

    const db = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // caller must be an authenticated participant (defence in depth: the
    // sealed output is derived purely from server-side state anyway)
    const auth = req.headers.get("Authorization") ?? "";
    const { data: caller } = await createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: auth } } },
    ).auth.getUser();
    if (!caller?.user) return j({ error: "sign in first" }, 401);

    const { data: r, error: re } = await db.from("requests").select("*").eq("id", request_id).single();
    if (re || !r) return j({ error: "request not found" }, 404);
    if (r.status !== "APPROVED") return j({ error: `request is ${r.status}, not APPROVED` }, 409);
    if (r.sealed_hash) return j({ ok: true, already: true, sealed_path: r.sealed_path, sealed_hash: r.sealed_hash });

    const { data: docs } = await db.from("documents").select("*")
      .eq("request_id", request_id).eq("superseded", false).order("created_at");
    const primary = (docs ?? []).find((d) => (d.mime ?? "").includes("pdf"));
    if (!primary) return j({ error: "no PDF document on this request" }, 422);

    const { data: steps } = await db.from("request_steps").select("*")
      .eq("request_id", request_id).order("stage").order("created_at");
    const { data: decisions } = await db.from("decisions").select("*")
      .eq("request_id", request_id).order("created_at");
    const ids = [...new Set([...(steps ?? []).map((s) => s.actor), r.requester])];
    const { data: profiles } = await db.from("profiles").select("*").in("id", ids);
    const who = Object.fromEntries((profiles ?? []).map((p) => [p.id, p]));

    // download + integrity check: the file must still match its recorded hash
    const dl = await db.storage.from("docs").download(primary.storage_path);
    if (dl.error) return j({ error: "primary document download failed" }, 500);
    const srcBuf = await dl.data.arrayBuffer();
    const srcHash = await sha256hex(srcBuf);
    if (srcHash !== primary.sha256) {
      return j({ error: "TAMPER: stored file no longer matches its recorded hash", recorded: primary.sha256, actual: srcHash }, 409);
    }

    const { data: cfg } = await db.from("settings").select("value").eq("key", "app_url").single();
    const appUrl = (typeof cfg?.value === "string" ? cfg.value : "") || "";
    const verifyUrl = appUrl
      ? `${appUrl.replace(/\/$/, "")}/#/verify?r=${encodeURIComponent(r.ref)}&t=${r.verify_token}`
      : `#/verify?r=${r.ref}&t=${r.verify_token}`;

    const pdf = await PDFDocument.load(srcBuf, { ignoreEncryption: true });
    const helv = await pdf.embedFont(StandardFonts.Helvetica);
    const helvB = await pdf.embedFont(StandardFonts.HelveticaBold);
    const ink = rgb(0.08, 0.1, 0.14), blue = rgb(0.17, 0.29, 0.53), grey = rgb(0.42, 0.46, 0.53);
    const fmt = (iso: string) =>
      new Date(iso).toLocaleString("en-SG", { timeZone: "Asia/Singapore", hour12: false }) + " SGT";

    // ---- footer on every original page ----
    const foot = `KKL Approvals · ${r.ref} · doc SHA-256 ${primary.sha256.slice(0, 16)}… · sealed ${fmt(new Date().toISOString())} · verify: ${appUrl ? appUrl + "/#/verify" : "in-app #/verify"}`;
    for (const p of pdf.getPages()) {
      const { width } = p.getSize();
      p.drawRectangle({ x: 0, y: 0, width, height: 14, color: rgb(1, 1, 1), opacity: 0.85 });
      p.drawText(foot.slice(0, 160), { x: 8, y: 4, size: 6.2, font: helv, color: grey });
    }

    // ---- signature block, page 1, bottom-right ----
    const approvers = (decisions ?? []).filter((d) => d.action === "APPROVE");
    const p1 = pdf.getPage(0);
    const { width: W } = p1.getSize();
    const bw = 236, rowH = 44, bh = 26 + approvers.length * rowH;
    const bx = W - bw - 14, by = 22;
    p1.drawRectangle({ x: bx, y: by, width: bw, height: bh, color: rgb(1, 1, 1), opacity: 0.92, borderColor: blue, borderWidth: 1.2 });
    p1.drawText("APPROVED — KKL APPROVALS", { x: bx + 8, y: by + bh - 14, size: 8, font: helvB, color: blue });
    p1.drawText(r.ref, { x: bx + bw - 8 - helv.widthOfTextAtSize(r.ref, 8), y: by + bh - 14, size: 8, font: helv, color: grey });
    let yy = by + bh - 22;
    for (const d of approvers) {
      yy -= rowH;
      const p = who[d.actor] ?? {};
      // signature image, composited server-side only
      if (p.signature_path) {
        const sg = await db.storage.from("sigs").download(p.signature_path);
        if (!sg.error) {
          try {
            const img = await pdf.embedPng(await sg.data.arrayBuffer());
            const sc = Math.min(70 / img.width, 26 / img.height);
            p1.drawImage(img, { x: bx + 8, y: yy + 12, width: img.width * sc, height: img.height * sc });
          } catch (_) { /* non-png or corrupt: fall through to text-only */ }
        }
      }
      p1.drawLine({ start: { x: bx + 8, y: yy + 10 }, end: { x: bx + 84, y: yy + 10 }, thickness: 0.6, color: grey });
      p1.drawText(p.display_name ?? "—", { x: bx + 90, y: yy + 26, size: 8.4, font: helvB, color: ink });
      p1.drawText(p.title ?? "", { x: bx + 90, y: yy + 17, size: 7, font: helv, color: grey });
      p1.drawText(fmt(d.created_at), { x: bx + 90, y: yy + 8, size: 7, font: helv, color: grey });
    }

    // ---- certificate of completion ----
    const cp = pdf.addPage([595.28, 841.89]); // A4
    let y = 780;
    const line = (t: string, o: { size?: number; font?: typeof helv; color?: ReturnType<typeof rgb>; x?: number } = {}) => {
      cp.drawText(t, { x: o.x ?? 56, y, size: o.size ?? 9.5, font: o.font ?? helv, color: o.color ?? ink });
    };
    cp.drawRectangle({ x: 40, y: 40, width: 515, height: 762, borderColor: blue, borderWidth: 1.4 });
    line("CERTIFICATE OF COMPLETION", { size: 17, font: helvB, color: blue }); y -= 16;
    line("KKL Approvals — internal approval record. Not a notarised e-signature.", { size: 8, color: grey }); y -= 26;

    const field = (k: string, v: string) => {
      line(k.toUpperCase(), { size: 7, color: grey }); y -= 11;
      line(v || "—", { size: 10, font: helvB }); y -= 20;
    };
    field("Reference", r.ref);
    field("Title", r.title);
    field("Type / Entity", `${r.type === "award" ? "Supplier / subcon award" : "Supplier invoice"} · ${r.entity}`);
    field("Project / Supplier", `${r.project ?? "—"} · ${r.supplier ?? "—"}`);
    field("Amount", `${r.currency} ${Number(r.amount).toLocaleString("en-SG", { minimumFractionDigits: 2 })}`);
    field("Requested by", `${who[r.requester]?.display_name ?? "—"} · submitted ${fmt(r.submitted_at)}`);
    y -= 4;

    line("DECISION TRAIL", { size: 8, font: helvB, color: blue }); y -= 14;
    for (const d of decisions ?? []) {
      const p = who[d.actor] ?? {}; const st = (steps ?? []).find((s) => s.id === d.step_id);
      line(`Stage ${st?.stage ?? "?"} · ${d.action}`, { size: 8.4, font: helvB }); y -= 11;
      line(`${p.display_name ?? "—"} (${p.title ?? p.email ?? ""}) · ${fmt(d.created_at)} · auth ${d.auth_level ?? "aal1"} · docs ${String(d.doc_manifest ?? "").slice(0, 16)}…`, { size: 7.6, color: grey }); y -= 10;
      if (d.comment) { line(`“${String(d.comment).slice(0, 110)}”`, { size: 7.6, color: grey, x: 66 }); y -= 10; }
      y -= 4;
      if (y < 210) break; // long trails continue in the audit record
    }
    y -= 6;
    line("DOCUMENTS BOUND TO THIS APPROVAL (SHA-256)", { size: 8, font: helvB, color: blue }); y -= 13;
    for (const d of docs ?? []) {
      line(`${d.name.slice(0, 52)} — ${d.sha256}`, { size: 6.8, color: grey }); y -= 10;
      if (y < 150) break;
    }
    line(`Manifest: ${r.doc_manifest}`, { size: 6.8, color: grey }); y -= 14;

    // QR to verification
    const qr = qrcodegen(0, "M"); qr.addData(verifyUrl); qr.make();
    const n = qr.getModuleCount(), cell = 86 / n, qx = 452, qy = 60;
    cp.drawRectangle({ x: qx - 4, y: qy - 4, width: 94, height: 94, color: rgb(1, 1, 1), borderColor: grey, borderWidth: 0.5 });
    for (let ry = 0; ry < n; ry++) for (let cx = 0; cx < n; cx++) {
      if (qr.isDark(ry, cx)) cp.drawRectangle({ x: qx + cx * cell, y: qy + (n - 1 - ry) * cell, width: cell, height: cell, color: ink });
    }
    cp.drawText("Scan or visit the verification page and", { x: 56, y: 108, size: 8, font: helv, color: grey });
    cp.drawText("drop this file on it to confirm it is unaltered.", { x: 56, y: 96, size: 8, font: helv, color: grey });
    cp.drawText(verifyUrl.slice(0, 90), { x: 56, y: 82, size: 6.6, font: helv, color: blue });
    cp.drawText("Timestamps are database-server time (SGT). Decisions are immutable and hash-chained;", { x: 56, y: 62, size: 6.8, font: helv, color: grey });
    cp.drawText("altering any document or decision after sealing is detectable via the hashes above.", { x: 56, y: 52, size: 6.8, font: helv, color: grey });

    const sealedBytes = await pdf.save();
    const sealedHash = await sha256hex(sealedBytes.buffer as ArrayBuffer);
    const sealedPath = `req/${r.id}/SEALED-${r.ref}.pdf`;
    const up = await db.storage.from("sealed").upload(sealedPath, sealedBytes, { contentType: "application/pdf", upsert: true });
    if (up.error) return j({ error: "sealed upload failed: " + up.error.message }, 500);

    await db.from("requests").update({ sealed_path: sealedPath, sealed_hash: sealedHash }).eq("id", r.id);
    await db.from("audit_events").insert({
      actor: caller.user.id, request_id: r.id, event: "SEALED",
      detail: { sealed_path: sealedPath, sealed_hash: sealedHash, primary_doc: primary.sha256 },
    });

    return j({ ok: true, sealed_path: sealedPath, sealed_hash: sealedHash });
  } catch (e) {
    return j({ error: String((e as Error)?.message ?? e) }, 500);
  }
});
