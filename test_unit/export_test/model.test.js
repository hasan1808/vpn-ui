// Node test for web/assets/js/model/inbound.js: the client MODEL invariants that
// the panel's shared, id-keyed client plumbing depends on.
//
// Why this exists as a host-side test: the incus E2E drives the panel's HTTP API and
// posts client JSON directly (with an explicit "id"), so it never runs this file at
// all. A model bug here is therefore invisible to a fully green E2E and only shows up
// in the browser. That is not hypothetical: mtproto and wg-c both identify accounts
// by EMAIL and synthesize id=email in toJson(), but fromJson() rebuilds them through
// a constructor that takes no id: so the LIVE object had no .id while its serialized
// form did. Every id-keyed path then broke: the client modal's oldClientId became
// undefined, edits POSTed to /updateClient/undefined and the panel answered "empty
// client ID", and the client table's :row-key went undefined for every row.
"use strict";
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..", "..");
const failures = [];
function ok(cond, msg) {
  if (cond) console.log("  ok   " + msg);
  else { console.log("  FAIL " + msg); failures.push(msg); }
}

// ---- load the REAL panel model under Node -------------------------------
// inbound.js is a browser script (no module exports), so evaluate it with the few
// globals it touches and lift the classes out. Loading the real file is the point:
// a hand-copied model would not catch a regression in the shipped one.
// window.crypto: RandomUtil mints the default random email/secret through it, so the
// "add a client" path touches it during construction.
global.window = {
  location: { hostname: "example.com" },
  crypto: require("crypto").webcrypto,
};
global.document = { addEventListener() {} };
const src =
  fs.readFileSync(path.join(REPO, "web/assets/js/util/index.js"), "utf8") + "\n" +
  fs.readFileSync(path.join(REPO, "web/assets/js/model/inbound.js"), "utf8") +
  "\nglobalThis.__Inbound = Inbound; globalThis.__Protocols = Protocols;";
(0, eval)(src);
const Inbound = globalThis.__Inbound;

console.log("model: email-identity clients expose .id");

// Both protocols whose identity is the email rather than a username/password.
const CASES = [
  { name: "MtprotoUser", cls: Inbound.MtprotoSettings.MtprotoUser,
    stored: { email: "alice@t", id: "alice@t", secret: "a".repeat(32), enable: true,
              modeClassic: true, modeSecure: false, modeTls: false,
              tlsDomain: "www.google.com", userLimit: 0, externalProxy: [] } },
  { name: "WgUser", cls: Inbound.WgcSettings.WgUser,
    stored: { email: "bob@t", id: "bob@t", enable: true,
              privKey: "k", pubKey: "p", psk: "" } },
  // AmneziaWG mirrors wg-c exactly: an email-identity client that synthesizes id=email
  // in toJson() and must re-expose it through fromJson() (same id-keyed invariants).
  { name: "AwgUser", cls: Inbound.AwgSettings.AwgUser,
    stored: { email: "carol@t", id: "carol@t", enable: true,
              privKey: "k", pubKey: "p", psk: "" } },
];

for (const { name, cls, stored } of CASES) {
  // fromJson is the path the client table uses (dbInbound.toInbound()), and the one
  // that used to drop id on the floor.
  const live = cls.fromJson([stored])[0];
  ok(live.id === stored.email,
     `${name}: live object rehydrated by fromJson exposes id (got ${JSON.stringify(live.id)})`);
  ok(live.toJson().id === live.id,
     `${name}: serialized id matches the live object's id`);

  // A getter, not a copied field: the identity must follow a rename rather than go
  // stale, since the panel matches the posted client by this value.
  live.email = "renamed@t";
  ok(live.id === "renamed@t",
     `${name}: id follows an email rename (cannot go stale)`);

  // A freshly constructed client (the "add" path) must be id-keyed too.
  const fresh = new cls();
  ok(typeof fresh.id === "string" && fresh.id.length > 0 && fresh.id === fresh.email,
     `${name}: newly constructed client has id === email`);
}

// ---- naive: the username is a SEPARATE field from the email --------------
// naive is not email-identity, so it is not in the loop above, but it has the same
// class of trap. Its username sits between `password` and the inherited ClientBase
// arguments in the constructor, so a fromJson that is not updated in lockstep shifts
// every later argument by one and the account's EMAIL silently lands in `username`.
// Nothing throws; the client table looks right; the link authenticates as the wrong
// name. An empty username is meaningful and must survive: it means "use the email",
// which is what every account created before the field relies on.
console.log("");
console.log("model: naive username round-trips and never eats the email");

const NAIVE_CASES = [
  { label: "username set", stored: { email: "alice@t", username: "alice-login", password: "pw", enable: true }, wantUser: "alice-login" },
  { label: "username absent", stored: { email: "bob@t", password: "pw", enable: true }, wantUser: "" },
  { label: "username empty", stored: { email: "carol@t", username: "", password: "pw", enable: true }, wantUser: "" },
];

for (const { label, stored, wantUser } of NAIVE_CASES) {
  const live = Inbound.NaiveSettings.Naive.fromJson(stored);
  ok(live.email === stored.email,
     `naive (${label}): email survives fromJson (got ${JSON.stringify(live.email)})`);
  ok(live.username === wantUser,
     `naive (${label}): username is ${JSON.stringify(wantUser)} (got ${JSON.stringify(live.username)})`);
  ok(live.password === stored.password,
     `naive (${label}): password survives fromJson`);
  const round = Inbound.NaiveSettings.Naive.fromJson(live.toJson());
  ok(round.email === stored.email && round.username === wantUser,
     `naive (${label}): survives a toJson/fromJson round trip`);
}

// A freshly added client has no username, so it authenticates as its email exactly as
// it did before the field existed.
ok(new Inbound.NaiveSettings.Naive().username === "",
   "naive: a newly constructed client defaults to no username");

// ---- verdict ------------------------------------------------------------
console.log("");
if (failures.length) {
  console.log("FAIL: " + failures.length + " assertion(s) failed:");
  failures.forEach((f) => console.log("  - " + f));
  process.exit(1);
}
console.log("PASS: inbound.js model invariants all good");
