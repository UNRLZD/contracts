// Regenerates oneclick_quotes.json: the EXACT bytes 1Click signed for each recorded live quote
// (spikes/intents/out), built exactly as spikes/intents/verify-sig.mjs (= SDK 0.1.26
// verifyQuoteSignature). Only quotes whose signature verifies are kept.
// usage: node oneclick_vectors.mjs ../../../../spikes/intents/out ../../../../audit/b2-intents/results/live > oneclick_quotes.json
// (2nd dir, optional: audit B2 recorded withdraw quotes `wd-*.json` = {signed_quote, signature}).
import { readFileSync, readdirSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";
const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58d = (s) => { let n = 0n; for (const c of s) n = n * 58n + BigInt(A.indexOf(c)); const h = n.toString(16); const b = Buffer.from(h.length % 2 ? "0" + h : h, "hex"); const z = s.match(/^1*/)[0].length; return Buffer.concat([Buffer.alloc(z), b]); };
const b58e = (buf) => { let n = BigInt("0x" + Buffer.from(buf).toString("hex")); let s = ""; while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; } for (const x of buf) { if (x) break; s = "1" + s; } return s; };
const stable = (v) => Array.isArray(v) ? "[" + v.map(stable).join(",") + "]" : v && typeof v === "object" ? "{" + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ":" + stable(v[k])).join(",") + "}" : JSON.stringify(v);
const MANAGER = "reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";
const pk = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), b58d(MANAGER)]), format: "der", type: "spki" });
const dir = process.argv[2];
const out = [];
for (const f of readdirSync(dir).filter((f) => /^quote-(live|v)-.*\.json$/.test(f)).sort()) {
  const r = JSON.parse(readFileSync(`${dir}/${f}`)).response;
  if (!r || !r.signature || !r.quote) continue;
  const q = r.quoteRequest, o = r.quote, u = (x) => x || undefined;
  const req = { dry: q.dry, swapType: q.swapType, slippageTolerance: q.slippageTolerance, originAsset: q.originAsset, depositType: q.depositType, destinationAsset: q.destinationAsset, amount: q.amount, refundTo: q.refundTo, refundType: q.refundType, recipient: q.recipient, recipientType: q.recipientType, deadline: q.deadline, quoteWaitingTimeMs: u(q.quoteWaitingTimeMs), referral: u(q.referral), customRecipientMsg: u(q.customRecipientMsg) };
  const base = { amountIn: o.amountIn, amountInFormatted: o.amountInFormatted, amountInUsd: o.amountInUsd, minAmountIn: o.minAmountIn, amountOut: o.amountOut, amountOutFormatted: o.amountOutFormatted, amountOutUsd: o.amountOutUsd, minAmountOut: o.minAmountOut };
  const quote = q.dry ? base : { ...base, depositAddress: u(o.depositAddress), depositMemo: u(o.depositMemo), deadline: u(o.deadline), timeWhenInactive: u(o.timeWhenInactive), timeEstimate: u(o.timeEstimate), refundFee: u(o.refundFee), withdrawFee: u(o.withdrawFee) };
  const signed_quote = stable({ ...req, ...quote, timestamp: r.timestamp });
  const message = b58e(createHash("sha256").update(signed_quote).digest());
  if (!verify(null, Buffer.from(message), pk, b58d(r.signature.replace("ed25519:", "")))) continue;
  out.push({ name: f.replace(/\.json$/, ""), signed_quote, signature: r.signature, message });
}
const dir2 = process.argv[3];
if (dir2) {
  for (const f of readdirSync(dir2).filter((f) => /^wd-.*\.json$/.test(f)).sort()) {
    const { signed_quote, signature } = JSON.parse(readFileSync(`${dir2}/${f}`));
    const message = b58e(createHash("sha256").update(signed_quote).digest());
    if (!verify(null, Buffer.from(message), pk, b58d(signature.replace("ed25519:", "")))) continue;
    out.push({ name: "b2-" + f.replace(/\.json$/, ""), signed_quote, signature, message });
  }
}
console.log(JSON.stringify(out, null, 1));
