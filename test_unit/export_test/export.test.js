// Node test for web/assets/js/util/export.js — the client-side TXT/PDF account
// export. The panel UI is browserless in this harness, so instead of driving a
// real browser we load the REAL export.js (and the REAL vendored jsPDF) under
// Node with small stubs for the browser-only bits (QRious canvas, FileManager
// download, SizeFormatter/IntlUtil formatters), then assert:
//   - TXT: a boxed credential card per account, with the fields, and the xray
//     account's share-link present.
//   - PDF: output is a real %PDF; a QR image is embedded ONLY for accounts that
//     have a real share-link URI (xray), never for VPN accounts.
//   - buildCards: link is populated for xray inbounds and empty for VPN.
"use strict";
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..", "..");
const EXPORT_JS = path.join(REPO, "web/assets/js/util/export.js");
const JSPDF = path.join(REPO, "web/assets/jspdf/jspdf.umd.min.js");

// ---- real jsPDF (UMD -> CommonJS export in Node) ------------------------
const { jsPDF } = require(JSPDF);

// ---- capture hooks ------------------------------------------------------
let qrCount = 0;      // # of QR images embedded into the PDF
let saved = [];       // captured PDF saves {fn, bytes}
let txtCapture = null;

const origAddImage = jsPDF.API.addImage;
jsPDF.API.addImage = function (...args) { qrCount++; return origAddImage.apply(this, args); };
jsPDF.API.save = function (fn) { saved.push({ fn, bytes: this.output("arraybuffer") }); return this; };

// Real jsPDF has a strict PNG decoder, so the QRious stub must return a genuinely
// valid PNG. Build a tiny RGB PNG with Node's zlib (browser QRious builds one via
// canvas.toDataURL — same net effect: a real PNG data URL).
const zlib = require("zlib");
function makePng(size) {
  const crcTable = (() => {
    const t = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
    const t = Buffer.from(type, "latin1");
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
    return Buffer.concat([len, t, data, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0; // 8-bit RGB
  const raw = Buffer.alloc(size * (1 + size * 3)); // filter byte + RGB per row (black)
  const idat = zlib.deflateSync(raw);
  const png = Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0)),
  ]);
  return "data:image/png;base64," + png.toString("base64");
}
const ONE_PX_PNG = makePng(8);

// ---- browser-global stubs ----------------------------------------------
global.window = { jspdf: { jsPDF } };
global.location = { hostname: "vpn.example" };
global.alert = () => {};
global.QRious = function (opts) { this.toDataURL = () => ONE_PX_PNG; };
global.FileManager = {
  downloadTextFile: (content, filename, mime) => { txtCapture = { content, filename, mime }; },
};
global.SizeFormatter = {
  sizeFormat: (b) => (b >= 1048576 ? (b / 1048576).toFixed(1) + " MB" : b + " B"),
};
global.IntlUtil = { formatDate: (ms) => new Date(ms).toISOString().slice(0, 10) };
// Backend fetch stub for the server-rendered-config protocols (wg-c/awg/ssh, via
// _fetchConfigs) and the ikev2 blank-serverAddr Remote ID resolver (_fetchRemoteId).
// Keyed on the URL path only, like the real endpoints (no request body to distinguish).
global.HttpUtil = {
  get: async (url) => {
    if (url.indexOf('/ikev2-remote-id') >= 0) {
      return { success: true, obj: { remoteId: 'fetched.example' } };
    }
    // A two-device account, each device with its OWN preshared key, as the real payload
    // has since WgcClientConfig grew a psk field. Keyed on the inbound id in the path so
    // the single-device response below stays exactly as it was.
    if (url.indexOf('/130/wgc-configs') >= 0) {
      return { success: true, obj: [
        { deviceIndex: 0, ip: '10.7.8.8/32', remark: 'Device 1', publicKey: 'PUB1',
          config: '[Interface]\nPrivateKey = D1\n', psk: 'DevPsk-1',
          host: 'relay.example', port: 51821 },
        { deviceIndex: 1, ip: '10.7.8.9/32', remark: 'Device 2', publicKey: 'PUB2',
          config: '[Interface]\nPrivateKey = D2\n', psk: 'DevPsk-2',
          host: 'relay.example', port: 51821 },
      ] };
    }
    // No psk field at all: both a single-device account and a payload from a panel that
    // predates the field, which must still fall back to the account-level key.
    if (url.indexOf('/wgc-configs') >= 0) {
      return { success: true, obj: [{ deviceIndex: 0, ip: '10.7.8.8/32', remark: '',
        publicKey: 'PUBKEY', config: '[Interface]\nPrivateKey = X\n',
        host: 'relay.example', port: 51821 }] };
    }
    return { success: false, obj: null };
  },
};
// export.js compares the inbound protocol against the Protocols enum (a browser global
// defined in model/inbound.js). buildCards runs in this Node context, so stub it here
// alongside the other browser globals, or every account is skipped with
// "Protocols is not defined". Values mirror model.Protocol (lowercase wire strings).
//
// EVERY key export.js reads has to be here, including the ones no fixture below uses
// yet. A missing key is undefined, and `'awg' === undefined` is simply false, so the
// branch it guards is quietly dead in this harness: the test would pass while the real
// panel took a path never exercised here. Keep this in step with model/inbound.js.
global.Protocols = {
  VMESS: 'vmess', VLESS: 'vless', TROJAN: 'trojan', SHADOWSOCKS: 'shadowsocks',
  WIREGUARD: 'wireguard', ANYTLS: 'anytls', TUIC: 'tuic', NAIVE: 'naive',
  L2TP: 'l2tp', PPTP: 'pptp', OPENVPN: 'openvpn', OPENCONNECT: 'openconnect',
  SSTP: 'sstp', IKEV2: 'ikev2', WGC: 'wg-c', AWG: 'awg', GRE: 'gre',
  MTPROTO: 'mtproto', SSH: 'ssh',
};

// ---- load the real export.js and expose AccountExport ------------------
const src = fs.readFileSync(EXPORT_JS, "utf8");
(0, eval)(src + "\n;globalThis.__AccountExport = AccountExport;");
const AE = globalThis.__AccountExport;

// ---- assertion helpers --------------------------------------------------
let failures = [];
function ok(cond, msg) { if (cond) console.log("  ✓ " + msg); else { failures.push(msg); console.log("  ✗ " + msg); } }

// ---- fixtures -----------------------------------------------------------
// One xray-style card (has a real share link -> gets a QR) and one VPN card
// (no link -> no QR).
const cards = [
  {
    remark: "xray-inbound", protocol: "VLESS", network: "tcp/TLS",
    server: "1.2.3.4", port: "443", email: "alice@t", username: "alice@t", password: "",
    uuid: "11111111-2222-3333-4444-555555555555", psk: "",
    expiry: "2026-08-01", used: "20.0 MB", total: "∞", enable: true,
    link: "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp#alice",
    qr: "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp#alice",
  },
  {
    remark: "l2tp-inbound", protocol: "L2TP", network: "IPsec/PSK",
    server: "1.2.3.4", port: "1701", email: "bob@t", username: "bob@t", password: "s3cret",
    uuid: "", psk: "TestPSK-9182",
    expiry: "∞", used: "5.0 MB", total: "1.0 GB", enable: false,
    link: "",
    qr: "",
  },
  // A third, ikev2 card carrying a Remote ID: the only protocol that ever sets one (see
  // the [remoteId] section below for where the value itself is computed).
  {
    remark: "ikev2-inbound", protocol: "IKEv2", network: "",
    server: "1.2.3.4", port: "500", email: "carol@t", username: "carol@t", password: "pw",
    uuid: "", psk: "", remoteId: "ikev2.relay.example",
    expiry: "∞", used: "1.0 MB", total: "∞", enable: true,
    link: "",
    qr: "",
  },
];

// ========================= TXT =========================
console.log("[txt]");
AE.txt(cards, "accounts");
ok(txtCapture !== null, "downloadTextFile was invoked");
ok(txtCapture && txtCapture.filename === "accounts.txt", "filename is accounts.txt");
const txt = (txtCapture && txtCapture.content) || "";
ok(txt.includes("alice@t") && txt.includes("bob@t"), "both accounts present");
ok(txt.includes("Password") && txt.includes("s3cret"), "password field rendered");
ok(txt.includes("PSK") && txt.includes("TestPSK-9182"), "PSK field rendered (l2tp)");
ok(txt.includes("═"), "boxed card style (box-drawing chars)");
ok(txt.includes("vless://11111111"), "xray share-link present in TXT");
ok(txt.includes("Remote ID") && txt.includes("ikev2.relay.example"), "Remote ID rendered (ikev2)");
{
  const remoteIdCount = (txt.match(/Remote ID/g) || []).length;
  ok(remoteIdCount === 1, "Remote ID row appears only on the ikev2 card, got " + remoteIdCount + " occurrence(s)");
}

// ========================= PDF =========================
console.log("[pdf]");
qrCount = 0; saved = [];
AE.pdf(cards, "accounts");
ok(saved.length === 1, "one PDF saved");
ok(saved.length === 1 && saved[0].fn === "accounts.pdf", "filename is accounts.pdf");
const head = saved.length ? Buffer.from(saved[0].bytes.slice(0, 5)).toString("latin1") : "";
ok(head.startsWith("%PDF"), "output is a real PDF (starts with %PDF), got " + JSON.stringify(head));
ok(qrCount === 1, "QR embedded ONLY for the xray card (1 image), got " + qrCount);

// ================== buildCards (link logic) ==================
// buildCards is async (WireGuard-C / SSH fetch their config from the backend); the
// xray + l2tp fixtures below never hit that fetch path, but we still await the result.
(async () => {
console.log("[buildCards]");
// Minimal fake of the inbounds Vue app: an xray inbound whose genAllLinks yields
// a link, and a VPN inbound whose genAllLinks yields '' (as Inbound.genLink does).
function fakeApp() {
  const xrayInbound = {
    listen: "", settings: {}, stream: { network: "tcp", isTls: true },
    genAllLinks: () => [{ link: "vless://uuid@1.2.3.4:443#x" }],
  };
  const vpnInbound = {
    listen: "", settings: { ipsecEnable: true, ipsecPsk: "P" },
    genAllLinks: () => [{ link: "" }],  // VPN protocols return '' from genLink
  };
  const rows = {
    // address mirrors DBInbound.prototype.address (buildCards reads it directly now):
    // both fixtures' inbounds have listen:"", so the real getter would fall back to
    // location.hostname, stubbed above as "vpn.example".
    10: { id: 10, remark: "xray", protocol: "vless", isOpenvpn: false, isL2tp: false, isPptp: false,
          address: "vpn.example", toInbound: () => xrayInbound },
    20: { id: 20, remark: "l2tp", protocol: "l2tp", isOpenvpn: false, isL2tp: true, isPptp: false,
          address: "vpn.example", toInbound: () => vpnInbound },
  };
  return {
    remarkModel: "-ieo",
    dbInbounds: [rows[10], rows[20]],
    getInboundClients: (db) => db.id === 10
      ? [{ email: "x@t", password: "", id: "uuid", totalGB: 0, expiryTime: 0 }]
      : [{ email: "v@t", password: "pw", id: "vuser", totalGB: 1073741824, expiryTime: 0 }],
    getSumStats: () => 12345,
  };
}
const built = await AE.buildCards(fakeApp(), [
  { inboundId: 10, email: "x@t" },
  { inboundId: 20, email: "v@t" },
]);
ok(built.length === 2, "buildCards returned a card per target");
const xc = built.find((c) => c.email === "x@t");
const vc = built.find((c) => c.email === "v@t");
ok(xc && xc.link && xc.link.startsWith("vless://"), "xray card has a share link (QR source)");
ok(xc && xc.qr && xc.qr.startsWith("vless://"), "xray card QR payload is the share link");
ok(vc && vc.link === "", "VPN card has no link (no QR)");
ok(vc && !vc.qr, "VPN card has no QR payload");
ok(vc && vc.psk === "P", "VPN (l2tp/ipsec) card carries the PSK");
ok(vc && vc.protocol === "L2TP/IPsec", "l2tp label is 'L2TP/IPsec' when ipsec on, got " + (vc && vc.protocol));
ok(vc && vc.network === "", "VPN protocol has no '/ tcp' network suffix");
ok(xc && xc.remoteId === "", "non-ikev2 (xray) card has no Remote ID, got " + JSON.stringify(xc && xc.remoteId));
ok(vc && vc.remoteId === "", "non-ikev2 (l2tp) card has no Remote ID, got " + JSON.stringify(vc && vc.remoteId));

// ================== new-protocol export domain + IKEv2 Remote ID ==================
// Covers: OpenVPN's externalProxy allowlist gap, IKEv2 Remote ID (configured, blank/
// fetched, and fan-out survival), IKEv2 psk-mode's missing PSK, and the wg-c "Server"
// row going stale next to its own (correct) attached .conf. One fakeApp with one
// inbound per concern, kept separate from the fixture above so a failure here can't be
// confused with the pre-existing xray/l2tp coverage.
console.log("[export domain + remote id]");
function fakeApp2() {
  const openvpnInbound = {
    listen: "", port: 1194,
    settings: { tcpEnable: true, udpEnable: true,
      externalProxy: [{ dest: "ovpn-relay.example", port: 443, remark: "Relay1" }] },
    genAllLinks: () => [{ link: "" }],
  };
  // psk auth mode + two external-proxy endpoints: exercises the PSK branch and proves
  // remoteId (inbound-wide, cert-bound) is untouched by the per-endpoint Object.assign
  // that overwrites server/port/remark for each endpoint.
  const ikev2PskInbound = {
    listen: "", port: 500,
    settings: { authMode: "psk", psk: "SharedSecret1", serverAddr: "ikev2.example.com",
      externalProxy: [
        { dest: "relay1.example", port: 4500, remark: "R1" },
        { dest: "relay2.example", port: 0, remark: "R2" },
      ] },
    genAllLinks: () => [{ link: "" }],
  };
  // authMode defaults to eap-mschapv2 and serverAddr is blank: the only case that must
  // hit _fetchRemoteId (stubbed above to answer "fetched.example").
  const ikev2BlankInbound = {
    listen: "", port: 500,
    settings: { authMode: "eap-mschapv2", serverAddr: "" },
    genAllLinks: () => [{ link: "" }],
  };
  const wgcInbound = {
    listen: "", port: 51820, settings: {},
    genAllLinks: () => [{ link: "" }],
  };
  const rows = {
    30: { id: 30, remark: "openvpn", protocol: "openvpn", isOpenvpn: true, isL2tp: false, isPptp: false,
          address: "vpn.example", toInbound: () => openvpnInbound },
    40: { id: 40, remark: "ikev2-psk", protocol: "ikev2", isOpenvpn: false, isL2tp: false, isPptp: false,
          address: "vpn.example", toInbound: () => ikev2PskInbound },
    50: { id: 50, remark: "ikev2-blank", protocol: "ikev2", isOpenvpn: false, isL2tp: false, isPptp: false,
          address: "vpn.example", toInbound: () => ikev2BlankInbound },
    70: { id: 70, remark: "wgc", protocol: "wg-c", isOpenvpn: false, isL2tp: false, isPptp: false,
          address: "vpn.example", toInbound: () => wgcInbound },
  };
  const clients = {
    30: [{ email: "ovpn@t", password: "pw", id: "ovpnuser", totalGB: 0, expiryTime: 0 }],
    // Non-empty id/password on purpose (as a real generated Ikev2User would have): the
    // hideUserPass tests below need real values on the card to prove they are kept but
    // not rendered, rather than "empty" hiding them for an unrelated reason.
    40: [{ email: "ikpsk@t", password: "GenPass123", id: "genuser1", totalGB: 0, expiryTime: 0 }],
    50: [{ email: "ikblank@t", password: "pw", id: "ikuser", totalGB: 0, expiryTime: 0 }],
    70: [{ email: "wgc@t", password: "", id: "", totalGB: 0, expiryTime: 0 }],
  };
  return {
    remarkModel: "-ieo",
    dbInbounds: [rows[30], rows[40], rows[50], rows[70]],
    getInboundClients: (db) => clients[db.id],
    getSumStats: () => 0,
  };
}
const built2 = await AE.buildCards(fakeApp2(), [
  { inboundId: 30, email: "ovpn@t" },
  { inboundId: 40, email: "ikpsk@t" },
  { inboundId: 50, email: "ikblank@t" },
  { inboundId: 70, email: "wgc@t" },
]);
// openvpn (1 externalProxy entry) + ikev2 psk (2 entries, fanned out) + ikev2 blank (1,
// no proxy) + wg-c (1 device from the HttpUtil stub) = 1 + 2 + 1 + 1.
ok(built2.length === 5, "buildCards fan-out totals as expected, got " + built2.length);

const ovc = built2.find((c) => c.email === "ovpn@t");
ok(ovc && ovc.server === "ovpn-relay.example", "openvpn externalProxy relay is the Server, got " + (ovc && ovc.server));
ok(ovc && ovc.port === "443", "openvpn externalProxy port used, got " + (ovc && ovc.port));

const ikpskCards = built2.filter((c) => c.email === "ikpsk@t");
ok(ikpskCards.length === 2, "ikev2 psk account fans out one card per externalProxy endpoint");
ok(ikpskCards.every((c) => c.psk === "SharedSecret1"), "ikev2 psk-mode PSK present on every endpoint card");
ok(ikpskCards.every((c) => c.remoteId === "ikev2.example.com"),
  "Remote ID survives the external-proxy fan-out unchanged, got " + JSON.stringify(ikpskCards.map((c) => c.remoteId)));
ok(ikpskCards.some((c) => c.server === "relay1.example" && c.port === "4500"), "first ikev2 endpoint card");
ok(ikpskCards.some((c) => c.server === "relay2.example" && c.port === "500"),
  "second ikev2 endpoint card (port 0 falls back to the inbound port)");

const ikBlank = built2.find((c) => c.email === "ikblank@t");
ok(ikBlank && ikBlank.remoteId === "fetched.example",
  "blank serverAddr resolves Remote ID via the server, got " + JSON.stringify(ikBlank && ikBlank.remoteId));
ok(ikBlank && ikBlank.psk === "", "eap-mschapv2 ikev2 card has no PSK row");

const wgcCard = built2.find((c) => c.email === "wgc@t");
ok(wgcCard && wgcCard.server === "relay.example",
  "wg-c 'Server' row matches its own config's Endpoint host, got " + (wgcCard && wgcCard.server));
ok(wgcCard && wgcCard.port === "51821",
  "wg-c 'Server' row matches its own config's Endpoint port, got " + (wgcCard && wgcCard.port));

// ============ the OTHER protocols with a PSK: shadowsocks-2022, xray wireguard, per-device wg-c ============
// Three separate ways a PSK went missing from a card. Shadowsocks-2022 authenticates with
// TWO secrets joined by ':' (the inbound's server key + the account's password) and only
// the account half was ever printed, so a card could not be reconstructed by hand at all.
// Xray-native `wireguard` keeps its preshared key on the peer and had no branch. wg-c/awg
// mint a DIFFERENT key per device, but every device card printed the account-level (device
// 1) value, which matters now that multi-device accounts are the norm.
console.log("[psk domain]");
function fakeApp3() {
  // isSS2022 is a getter on the real Inbound (derived from settings.method); the fixtures
  // state it directly, which is what the getter would answer for these two methods.
  const ss2022Inbound = {
    listen: "", port: 8388, isSS2022: true,
    settings: { method: "2022-blake3-aes-128-gcm", password: "ServerPSK-AAAA" },
    stream: { network: "tcp" },
    genAllLinks: () => [{ link: "ss://b64@1.2.3.4:8388#ss" }],
  };
  // Pre-2022 method: settings.password is not a server key the client ever sends, so the
  // card must NOT grow a PSK row out of it.
  const ssLegacyInbound = {
    listen: "", port: 8389, isSS2022: false,
    settings: { method: "chacha20-ietf-poly1305", password: "NotAServerKey" },
    stream: { network: "tcp" },
    genAllLinks: () => [{ link: "ss://b64@1.2.3.4:8389#ss" }],
  };
  // Xray-native wireguard: no inbound-wide pskEnable flag, the peer either has a key or not.
  const wgInbound = {
    listen: "", port: 51820, settings: {},
    genAllLinks: () => [{ link: "" }],
  };
  // wg-c, preshared keys on, two devices (see the /130/wgc-configs stub above).
  const wgcMultiInbound = {
    listen: "", port: 51820, settings: { pskEnable: true },
    genAllLinks: () => [{ link: "" }],
  };
  // wg-c, preshared keys on, a device payload with no psk field: the fallback case.
  const wgcLegacyInbound = {
    listen: "", port: 51820, settings: { pskEnable: true },
    genAllLinks: () => [{ link: "" }],
  };
  const rows = {
    100: { id: 100, remark: "ss2022", protocol: "shadowsocks", isOpenvpn: false, isL2tp: false, isPptp: false,
           address: "vpn.example", toInbound: () => ss2022Inbound },
    110: { id: 110, remark: "ss-legacy", protocol: "shadowsocks", isOpenvpn: false, isL2tp: false, isPptp: false,
           address: "vpn.example", toInbound: () => ssLegacyInbound },
    120: { id: 120, remark: "wg-native", protocol: "wireguard", isOpenvpn: false, isL2tp: false, isPptp: false,
           address: "vpn.example", toInbound: () => wgInbound },
    130: { id: 130, remark: "wgc-multi", protocol: "wg-c", isOpenvpn: false, isL2tp: false, isPptp: false,
           address: "vpn.example", toInbound: () => wgcMultiInbound },
    140: { id: 140, remark: "wgc-legacy", protocol: "wg-c", isOpenvpn: false, isL2tp: false, isPptp: false,
           address: "vpn.example", toInbound: () => wgcLegacyInbound },
  };
  const clients = {
    100: [{ email: "ss2022@t", password: "AcctPass-BBBB", totalGB: 0, expiryTime: 0 }],
    110: [{ email: "sslegacy@t", password: "AcctPass-CCCC", totalGB: 0, expiryTime: 0 }],
    120: [{ email: "wgpeer@t", psk: "PeerPSK-DDDD", totalGB: 0, expiryTime: 0 }],
    // The account-level psk is device 1's legacy value; each device's own key wins over it.
    130: [{ email: "wgcmulti@t", psk: "AccountPsk-OLD", totalGB: 0, expiryTime: 0 }],
    140: [{ email: "wgclegacy@t", psk: "AccountPsk-KEEP", totalGB: 0, expiryTime: 0 }],
  };
  return {
    remarkModel: "-ieo",
    dbInbounds: [rows[100], rows[110], rows[120], rows[130], rows[140]],
    getInboundClients: (db) => clients[db.id],
    getSumStats: () => 0,
  };
}
const built3 = await AE.buildCards(fakeApp3(), [
  { inboundId: 100, email: "ss2022@t" },
  { inboundId: 110, email: "sslegacy@t" },
  { inboundId: 120, email: "wgpeer@t" },
  { inboundId: 130, email: "wgcmulti@t" },
  { inboundId: 140, email: "wgclegacy@t" },
]);
ok(built3.length === 6, "one card each except the two-device wg-c account, got " + built3.length);

const ssCard = built3.find((c) => c.email === "ss2022@t");
ok(ssCard && ssCard.psk === "ServerPSK-AAAA",
  "shadowsocks-2022 card carries the inbound's server PSK, got " + JSON.stringify(ssCard && ssCard.psk));
ok(ssCard && ssCard.password === "AcctPass-BBBB", "shadowsocks-2022 card still carries the account password");
ok(ssCard && ssCard.pskLabel === "Server PSK",
  "shadowsocks-2022 PSK row is labelled 'Server PSK', got " + JSON.stringify(ssCard && ssCard.pskLabel));

const ssLegacyCard = built3.find((c) => c.email === "sslegacy@t");
ok(ssLegacyCard && ssLegacyCard.psk === "",
  "a pre-2022 shadowsocks inbound exports NO PSK row, got " + JSON.stringify(ssLegacyCard && ssLegacyCard.psk));
ok(ssLegacyCard && ssLegacyCard.pskLabel === "PSK", "a non-2022 card keeps the plain 'PSK' label");

const wgNativeCard = built3.find((c) => c.email === "wgpeer@t");
ok(wgNativeCard && wgNativeCard.psk === "PeerPSK-DDDD",
  "xray-native wireguard card carries the peer's own psk, got " + JSON.stringify(wgNativeCard && wgNativeCard.psk));

const wgcDevCards = built3.filter((c) => c.email === "wgcmulti@t");
ok(wgcDevCards.length === 2, "the two-device wg-c account fans out one card per device, got " + wgcDevCards.length);
ok(wgcDevCards.some((c) => c.psk === "DevPsk-1") && wgcDevCards.some((c) => c.psk === "DevPsk-2"),
  "each wg-c device card carries its OWN psk, got " + JSON.stringify(wgcDevCards.map((c) => c.psk)));
ok(new Set(wgcDevCards.map((c) => c.psk)).size === 2,
  "two devices with different psks do NOT collapse onto the account-level value");

const wgcLegacyCard = built3.find((c) => c.email === "wgclegacy@t");
ok(wgcLegacyCard && wgcLegacyCard.psk === "AccountPsk-KEEP",
  "a device payload with no psk field falls back to the account-level key, got " + JSON.stringify(wgcLegacyCard && wgcLegacyCard.psk));

// Round trip through the renderer: the row has to REACH the file, under its own label,
// carrying a DIFFERENT secret from the Password row right above it. That last clause is
// the assertion that catches the whole gap: before this, the server half was nowhere in
// the export except base64'd inside the ss:// link.
const rowOf = (txt, label) => {
  const l = txt.split("\n").find((s) => s.trim().indexOf(label + " :") === 0);
  return l ? l.split(":").slice(1).join(":").trim() : "";
};
AE.txt([ssCard], "ss2022");
const ssTxt = txtCapture.content;
ok(rowOf(ssTxt, "Server PSK") === "ServerPSK-AAAA",
  "TXT renders the shadowsocks-2022 server PSK row, got " + JSON.stringify(rowOf(ssTxt, "Server PSK")));
ok(rowOf(ssTxt, "Password") === "AcctPass-BBBB",
  "TXT still renders the account Password row, got " + JSON.stringify(rowOf(ssTxt, "Password")));
ok(rowOf(ssTxt, "Server PSK") !== "" && rowOf(ssTxt, "Server PSK") !== rowOf(ssTxt, "Password"),
  "the two shadowsocks-2022 secrets are BOTH present and are different values");
AE.txt([ssLegacyCard], "sslegacy");
ok(txtCapture.content.indexOf("PSK") < 0, "a pre-2022 shadowsocks card renders no PSK row at all");

AE.txt(wgcDevCards, "wgcmulti");
const devTxt = txtCapture.content;
ok(devTxt.includes("DevPsk-1") && devTxt.includes("DevPsk-2") && !devTxt.includes("AccountPsk-OLD"),
  "TXT prints each wg-c device's own PSK, never the account-level one");

// ================== _psk() unit coverage (ikev2 auth-mode branch) ==================
console.log("[psk]");
ok(AE._psk({ protocol: "ikev2" }, { settings: { authMode: "psk", psk: "SharedSecret1" } }, {}) === "SharedSecret1",
  "ikev2 psk-mode _psk() returns the shared secret");
ok(AE._psk({ protocol: "ikev2" }, { settings: { authMode: "eap-mschapv2", psk: "SharedSecret1" } }, {}) === "",
  "ikev2 non-psk mode _psk() returns '' even if a stale psk value is present");
ok(AE._psk({ protocol: "shadowsocks" },
  { isSS2022: true, settings: { password: "ServerPSK-AAAA" } }, { password: "AcctPass-BBBB" }) === "ServerPSK-AAAA",
  "shadowsocks-2022 _psk() returns the INBOUND's server key, not the account password");
ok(AE._psk({ protocol: "shadowsocks" },
  { isSS2022: false, settings: { password: "NotAServerKey" } }, { password: "AcctPass-CCCC" }) === "",
  "pre-2022 shadowsocks _psk() returns '' (settings.password is not a server key there)");
ok(AE._psk({ protocol: "wireguard" }, { settings: {} }, { psk: "PeerPSK-DDDD" }) === "PeerPSK-DDDD",
  "xray-native wireguard _psk() returns the peer's psk");
ok(AE._psk({ protocol: "wireguard" }, { settings: {} }, {}) === "",
  "a wireguard peer with no psk gets no PSK row");
ok(AE._pskLabel({ protocol: "shadowsocks" }, { isSS2022: true }) === "Server PSK"
  && AE._pskLabel({ protocol: "shadowsocks" }, { isSS2022: false }) === "PSK"
  && AE._pskLabel({ protocol: "l2tp" }, {}) === "PSK",
  "_pskLabel names only the shadowsocks-2022 row, everything else stays 'PSK'");

// ============ _hideUserPass() + rendering (ikev2 psk/eap-tls Username/Password) ============
// psk and eap-tls never check the per-account id/password (psk = one shared secret;
// eap-tls = a client cert against the CA, identity wildcarded), so their Username/
// Password rows must disappear from the rendered output while the VALUES stay on the
// card for any other reader.
console.log("[hideUserPass]");
ok(AE._hideUserPass({ protocol: "ikev2" }, { settings: { authMode: "psk" } } ) === true, "ikev2 psk hides user/pass");
ok(AE._hideUserPass({ protocol: "ikev2" }, { settings: { authMode: "eap-tls" } } ) === true, "ikev2 eap-tls hides user/pass");
ok(AE._hideUserPass({ protocol: "ikev2" }, { settings: { authMode: "eap-mschapv2" } } ) === false,
  "ikev2 eap-mschapv2 (RADIUS) keeps user/pass");
ok(AE._hideUserPass({ protocol: "l2tp" }, { settings: { authMode: "psk" } } ) === false,
  "non-ikev2 protocol is never hidden, even given an authMode-shaped settings object");

// buildCards: the psk cards from fakeApp2 (ikpskCards, ikBlank) built above.
ok(ikpskCards.every((c) => c.hideUserPass === true), "ikev2 psk cards carry hideUserPass");
ok(ikpskCards.every((c) => c.username === "genuser1" && c.password === "GenPass123"),
  "ikev2 psk cards keep their real username/password VALUES; only rendering is suppressed");
ok(ikBlank && ikBlank.hideUserPass === false, "ikev2 eap-mschapv2 card does not set hideUserPass");

// Rendering: a psk card shows PSK but no Username/Password row; an eap-mschapv2 card
// shows Username/Password as normal.
AE.txt([ikpskCards[0]], "x");
const pskTxt = txtCapture.content;
ok(!pskTxt.includes("Username") && !pskTxt.includes("Password"),
  "ikev2 psk card renders no Username/Password row in TXT");
ok(pskTxt.includes("PSK") && pskTxt.includes("SharedSecret1"), "ikev2 psk card still renders its PSK row");

AE.txt([ikBlank], "x");
const mschapTxt = txtCapture.content;
ok(mschapTxt.includes("Username") && mschapTxt.includes("ikuser"), "ikev2 eap-mschapv2 card renders its Username row");
ok(mschapTxt.includes("Password") && mschapTxt.includes("pw"), "ikev2 eap-mschapv2 card renders its Password row");

// ================== download filename sanitizing ==================
// The Clients page names a per-account export after the account's EMAIL, which is
// free text that goes straight onto a filesystem. _safeName is a DENYLIST: it drops
// only what a filesystem rejects, so the file really is named after the address. The
// first case is the whole point of the feature; the last few are the ones that would
// otherwise ship a file with no name at all.
console.log("[filename]");
const sn = (n) => AE._safeName(n, "account");
ok(sn("bob@example.com") === "bob@example.com",
  "an email survives INTACT, @ included, got " + sn("bob@example.com"));
ok(sn("bob+vpn@example.com") === "bob+vpn@example.com",
  "a plus-addressed email keeps its tag, so it cannot collide with the untagged one, got " + sn("bob+vpn@example.com"));
ok(sn("کاربر@ایران") === "کاربر@ایران",
  "a non-ASCII email is a legal filename and is kept, not flattened to the stem, got " + sn("کاربر@ایران"));
ok(sn("a/b\\c:d*e?f\"g<h>i|j k") === "abcdefghij k",
  "path separators, ':' and the Windows-reserved set are dropped; an interior space is legal and stays, got " + JSON.stringify(sn("a/b\\c:d*e?f\"g<h>i|j k")));
ok(sn("a\u0000b\u001fc\u007f") === "abc",
  "control characters are dropped, got " + JSON.stringify(sn("a\u0000b\u001fc\u007f")));
ok(sn("a@b/c") === "a@bc", "the @ is kept while a path separator next to it is not, got " + sn("a@b/c"));
ok(sn(".hidden.") === "hidden", "leading and trailing dots stripped, got " + sn(".hidden."));
ok(sn("  spaced  ") === "spaced", "leading and trailing spaces stripped (Windows strips them silently), got " + JSON.stringify(sn("  spaced  ")));
ok(sn("x".repeat(200)).length === 64, "capped at 64 chars, got " + sn("x".repeat(200)).length);
ok(sn("x".repeat(63) + "..") === "x".repeat(63), "the cap does not leave a trailing dot behind, got " + JSON.stringify(sn("x".repeat(63) + "..")));
// Empty-after-sanitize: rarer under a denylist, but a name of nothing but stripped
// characters still has to fall back rather than be offered as a bare ".txt".
ok(sn("///") === "account" && sn("...") === "account" && sn(" . ") === "account",
  "a name of nothing but dropped characters falls back to the stem");
ok(sn("") === "account" && sn(undefined) === "account" && sn(null) === "account",
  "empty/undefined/null fall back to the stem");
ok(AE._safeName("...", "") === "accounts", "no stem either -> 'accounts', never a bare extension");
// End to end through the two renderers, since they are what names the download.
AE.txt([cards[0]], "bob@example.com");
ok(txtCapture.filename === "bob@example.com.txt", "txt() names the file after the email, got " + txtCapture.filename);
saved = [];
AE.pdf([cards[1]], "bob@example.com");
ok(saved.length === 1 && saved[0].fn === "bob@example.com.pdf",
  "pdf() names the file after the email, got " + (saved[0] && saved[0].fn));

// ================== protocol labels (TXT + PDF display) ==================
console.log("[labels]");
const lbl = (proto, settings) => AE._protocolLabel({ protocol: proto }, { settings: settings || {} });
ok(lbl("wg-c") === "WireGuard (C)", "wg-c -> 'WireGuard (C)', got " + lbl("wg-c"));
ok(lbl("ikev2") === "IKEv2", "ikev2 -> 'IKEv2', got " + lbl("ikev2"));
ok(lbl("pptp") === "PPTP", "pptp -> 'PPTP'");
ok(lbl("openconnect") === "OpenConnect", "openconnect -> 'OpenConnect', got " + lbl("openconnect"));
ok(lbl("sstp") === "SSTP", "sstp -> 'SSTP'");
ok(lbl("ssh") === "SSH", "ssh -> 'SSH'");
ok(lbl("openvpn", { tcpEnable: true, udpEnable: true }) === "OpenVPN - TCP/UDP",
  "openvpn both -> 'OpenVPN - TCP/UDP', got " + lbl("openvpn", { tcpEnable: true, udpEnable: true }));
ok(lbl("openvpn", { udpEnable: true }) === "OpenVPN - UDP", "openvpn udp-only -> 'OpenVPN - UDP'");
ok(lbl("l2tp", { ipsecEnable: false }) === "L2TP/RAW", "l2tp ipsec off -> 'L2TP/RAW'");
ok(lbl("l2tp", { ipsecEnable: true }) === "L2TP/IPsec", "l2tp ipsec on -> 'L2TP/IPsec'");
// networks: VPN protocols carry no transport suffix, xray still does
ok(AE._network({ protocol: "wg-c" }, {}) === "", "wg-c network suffix is empty");
ok(AE._network({ protocol: "vless" }, { stream: { network: "tcp", isTls: true } }) === "tcp/TLS",
  "xray keeps its transport suffix");

// ---- verdict ------------------------------------------------------------
console.log("");
if (failures.length) {
  console.log("FAIL: " + failures.length + " assertion(s) failed:");
  failures.forEach((f) => console.log("  - " + f));
  process.exit(1);
}
console.log("PASS: export.js TXT/PDF/buildCards all good");
})();
