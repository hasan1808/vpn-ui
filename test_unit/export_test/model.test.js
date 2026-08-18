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
  // The secret, the ad tag and the external-proxy list are all an mtproto account
  // owns: the modes, the FakeTLS domain and the device cap are the inbound's.
  { name: "MtprotoUser", cls: Inbound.MtprotoSettings.MtprotoUser,
    stored: { email: "alice@t", id: "alice@t", secret: "a".repeat(32), enable: true,
              adtagEnable: false, adtag: "", externalProxy: [] } },
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

// An MTProto inbound stored before the modes, the FakeTLS domain and the device cap
// moved off its clients carries none of them at the root. This form POSTS BACK what it
// read, so resolving them to the fresh-inbound defaults here would widen an operator's
// narrower set to all three modes and no device cap the first time anyone opened the
// inbound and pressed Save, with nothing left to recover it from.
//
// The resolution must be the backend's, byte for byte: deriveMtprotoPolicy in
// web/service/mtproto.go, which the panel-side lift and the subscription links also go
// through. These cases are the same ones pinned in web/service/mtproto_compat_test.go.
console.log("");
console.log("model: mtproto legacy per-client settings resolve onto the inbound");

const MTPROTO_LEGACY_CASES = [
  {
    label: "union, first FakeTLS domain, largest cap",
    stored: { clients: [
      { email: "alice", secret: "a".repeat(32), modeClassic: true, modeSecure: true, userLimit: 4 },
      { email: "bob", secret: "b".repeat(32), modeTls: true, tlsDomain: "www.cloudflare.com", userLimit: 2 },
    ] },
    want: { modeClassic: true, modeSecure: true, modeTls: true, tlsDomain: "www.cloudflare.com", userLimit: 4 },
  },
  {
    // One account predates the move, one was added after it and carries nothing. An
    // absent per-client cap means ONE device, so the explicit 3 still wins.
    label: "mixed old and new clients",
    stored: { clients: [
      { email: "alice", secret: "a".repeat(32), modeSecure: true, userLimit: 3 },
      { email: "bob", secret: "b".repeat(32) },
    ] },
    want: { modeClassic: false, modeSecure: true, modeTls: false, tlsDomain: "www.google.com", userLimit: 3 },
  },
  {
    // Nothing to preserve: fall back to the fresh-inbound values rather than to a
    // modeless inbound, which telemt reads as "no restriction".
    label: "no accounts at all",
    stored: { clients: [] },
    want: { modeClassic: true, modeSecure: true, modeTls: true, tlsDomain: "www.google.com", userLimit: 10 },
  },
  {
    // Already migrated: read straight off the root, an explicit false included.
    label: "current shape is read verbatim",
    stored: { modeClassic: false, modeSecure: true, modeTls: false, tlsDomain: "a.example", userLimit: 2,
              clients: [{ email: "alice", secret: "a".repeat(32) }] },
    want: { modeClassic: false, modeSecure: true, modeTls: false, tlsDomain: "a.example", userLimit: 2 },
  },
];

for (const { label, stored, want } of MTPROTO_LEGACY_CASES) {
  const live = Inbound.MtprotoSettings.fromJson(stored);
  for (const key of Object.keys(want)) {
    ok(live[key] === want[key],
       `mtproto (${label}): ${key} is ${JSON.stringify(want[key])} (got ${JSON.stringify(live[key])})`);
  }
  // What the form would send back. It must be the resolved shape, not the legacy one:
  // that save is what makes the resolution permanent.
  const posted = live.toJson();
  ok(posted.modeClassic === want.modeClassic && posted.modeSecure === want.modeSecure &&
     posted.modeTls === want.modeTls && posted.tlsDomain === want.tlsDomain &&
     posted.userLimit === want.userLimit,
     `mtproto (${label}): a save posts the resolved values, not the legacy ones`);
}

// A vless inbound stored before `flow` moved off its clients carries it only on them.
// This form POSTS BACK what it read, so failing to lift it would show the picker as None
// and then mirror that None over every client the first time anyone opened the inbound
// and pressed Save. That is vision switched off on a working REALITY inbound, and it
// presents as customers who connect and then stall, with nothing in any log naming it.
//
// The mirror in the other direction is not made redundant by the core's own fallback
// (xray-core applies settings.flow to any client that carries none). All four share-link
// generators read the PER-CLIENT field: genLink in inbound.js, sub/subService.go,
// sub/subJsonService.go and sub/subClashService.go. An inbound-only value would therefore
// drop flow= from every link while the tunnel itself kept working.
console.log("");
console.log("model: vless flow resolves onto the inbound and mirrors back onto the clients");

const VLESS_FLOW_CASES = [
  {
    // Saved by an earlier build: nothing at the root, the value on the clients. The
    // second client carries no flow of its own and must still come back mirrored.
    label: "legacy per-client flow is lifted",
    stored: { clients: [
      { id: "u1", email: "alice", flow: "xtls-rprx-vision" },
      { id: "u2", email: "bob" },
    ] },
    want: "xtls-rprx-vision",
  },
  {
    // xray-core accepts exactly "" and "xtls-rprx-vision". At settings level a value it
    // refuses takes the WHOLE config down rather than one client, so the legacy spelling
    // must not survive the lift. Pinned against the bundled fork, whose rule is at
    // third_party/Xray-core/infra/conf/vless.go.
    label: "udp443 folds down to plain vision",
    stored: { clients: [{ id: "u1", email: "alice", flow: "xtls-rprx-vision-udp443" }] },
    want: "xtls-rprx-vision",
  },
  {
    // Already migrated: read straight off the root.
    label: "current shape is read verbatim",
    stored: { flow: "xtls-rprx-vision", clients: [{ id: "u1", email: "alice" }] },
    want: "xtls-rprx-vision",
  },
  {
    label: "no flow anywhere",
    stored: { clients: [{ id: "u1", email: "alice" }] },
    want: "",
  },
];

for (const { label, stored, want } of VLESS_FLOW_CASES) {
  const live = Inbound.VLESSSettings.fromJson(stored);
  ok(live.flow === want,
     `vless flow (${label}): flow is ${JSON.stringify(want)} (got ${JSON.stringify(live.flow)})`);
  const posted = live.toJson();
  ok(posted.clients.every((c) => c.flow === want),
     `vless flow (${label}): every client entry is mirrored`);
  ok((posted.flow || "") === want,
     `vless flow (${label}): a save posts the resolved value, not the legacy one`);
}

// Clearing the picker has to reach the clients too. Mirroring only non-empty values would
// leave every client holding the vision it was last saved with, which presents as a
// picker that does nothing.
{
  const live = Inbound.VLESSSettings.fromJson({
    flow: "xtls-rprx-vision",
    clients: [{ id: "u1", email: "alice", flow: "xtls-rprx-vision" }],
  });
  live.flow = "";
  const posted = live.toJson();
  ok(!("flow" in posted), "vless flow (cleared): settings.flow is omitted");
  ok(posted.clients.every((c) => c.flow === ""),
     "vless flow (cleared): the clear reaches every client");
  // testseed is gated on the inbound flow now, not on "some client has one".
  ok(!("testseed" in posted), "vless flow (cleared): testseed stops being emitted");
}

// The lift must not WIDEN a broken inbound.
//
// VLESSSettings.fromJson sees only the settings blob, so it cannot ask whether the
// transport supports flow. On a legacy vless inbound over ws or grpc, a stray flow on
// one client would otherwise be promoted to the inbound and then mirrored onto EVERY
// client on the next save: one broken account becomes all of them, and the operator
// cannot undo it, because the picker is hidden while canEnableTlsFlow() is false and
// the wipe handlers only fire on a security or network CHANGE. Inbound.fromJson is
// where the stream finally exists, so that is where it is cleared.
{
  const overTcpReality = Inbound.fromJson({
    protocol: "vless",
    settings: { clients: [{ id: "u1", email: "alice", flow: "xtls-rprx-vision" }] },
    streamSettings: { network: "tcp", security: "reality" },
  });
  ok(overTcpReality.canEnableTlsFlow(), "vless flow (transport): reality+tcp can carry flow");
  ok(overTcpReality.settings.flow === "xtls-rprx-vision",
     "vless flow (transport): a legacy flow still lifts on a transport that supports it");

  for (const stream of [
    { network: "ws", security: "tls" },
    { network: "grpc", security: "tls" },
    { network: "tcp", security: "none" },
  ]) {
    const bad = Inbound.fromJson({
      protocol: "vless",
      settings: { clients: [{ id: "u1", email: "alice", flow: "xtls-rprx-vision" }] },
      streamSettings: stream,
    });
    const where = `${stream.network}/${stream.security}`;
    ok(!bad.canEnableTlsFlow(), `vless flow (transport): ${where} cannot carry flow`);
    ok(bad.settings.flow === "",
       `vless flow (transport): a stray flow is cleared on ${where}, not promoted`);
    ok(bad.toJson().settings.clients.every((c) => !c.flow),
       `vless flow (transport): ${where} does not mirror a flow onto its clients`);
  }
}

// ---- verdict ------------------------------------------------------------
console.log("");
if (failures.length) {
  console.log("FAIL: " + failures.length + " assertion(s) failed:");
  failures.forEach((f) => console.log("  - " + f));
  process.exit(1);
}
console.log("PASS: inbound.js model invariants all good");
