/* ==========================================================================
   fixture.js, the inbound add/edit surface, as measured.

   Every field below is a real one, read out of web/html/form/** (protocol
   partials, stream partials, tls/reality/sniffing) and web/html/form/inbound.html.
   The five schemes in schemes.html all render from THIS data, so they are drawn
   over the same inventory and can be compared like for like.

   Field shape:
     l  label as the panel writes it
     t  control: text | num | switch | select | radio | area | ro | seed | repeat
     v  current value in the fixture
     h  hint / help text shown under or beside the control
     req  the save gate depends on it (modalFormValid)
     bad  currently failing, with the reason (drives the validation ledger)
     adv  advanced: off the default path

   Section shape:
     id, title, note, fields[], adv (whole section is advanced), count override

   `n` on a section is the field count the panel can actually render there when
   every toggle and repeater inside it is expanded. Where that is larger than
   fields.length, the sheet is showing a representative slice and says so.
   ========================================================================== */

const F = (l, t, v, extra) => Object.assign({ l, t, v }, extra || {});

/* ---- blocks repeated across protocols -------------------------------------
   These are the reason a redesign is tractable: 9 of the 24 protocols carry the
   same network handout, 8 carry the same device cap, 11 the same reachability
   row, and all 24 carry the same commerce block. Today each is re-declared in
   its own partial and rendered as an undifferentiated run of rows. */

const QUOTA = () => ({
  id: 'quota', title: 'Quota and billing', n: 10,
  note: 'Identical on all 24 protocols. Stored on the DB row, not in protocol settings.',
  fields: [
    F('Total Flow (GB)', 'num', '0', { h: '0 means no limit' }),
    F('Traffic Multiplier', 'switch', true),
    F('Apply After (GB)', 'num', '50', { sub: true }),
    F('Multiplier', 'num', '1.5', { sub: true }),
    F('Speed Limit', 'switch', false),
    F('Separate Up/Down', 'switch', false, { sub: true, off: true }),
    F('Speed (Mbps)', 'num', '0', { sub: true, off: true }),
    F('Apply After (GB)', 'num', '0', { sub: true, off: true }),
    F('Periodic Traffic Reset', 'select', 'Monthly'),
    F('Expire Date', 'text', '2027-02-01 00:00:00', { h: 'blank never expires' }),
  ],
});

const EXTPROXY = () => ({
  id: 'reach', title: 'Reachability', n: 1,
  note: 'External Proxy. 11 protocols carry this same row.',
  fields: [F('External Proxy', 'switch', false, { h: 'advertise a different host:port to clients' })],
});

const SNIFF = () => ({
  id: 'sniff', title: 'Sniffing', n: 4, adv: true,
  fields: [
    F('Enabled', 'switch', false),
    F('Metadata Only', 'switch', false),
    F('Domains Excluded', 'text', ''),
    F('Route Only', 'switch', false),
  ],
});

const MESH = () => ([
  F('Client to Client', 'switch', false, { h: 'let connected clients reach each other' }),
  F('Cross Inbound', 'switch', false, { h: 'and clients of other inbounds; both sides must enable it' }),
]);

const HANDOUT = (range) => ([
  F('IP Range', 'ro', range, { h: 'assigned automatically on save' }),
  F('DNS 1', 'text', '8.8.8.8'),
  F('DNS 2', 'text', '8.8.4.4'),
  F('MTU', 'num', '1400'),
]);

/* ---- the five fixtures -------------------------------------------------- */

const PROTOCOLS = {

  /* The worst case the modal can reach. 195 fields in a 520px column. */
  vless: {
    label: 'VLESS', tagline: 'XHTTP + REALITY',
    family: 'Xray-native', port: '443', total: 195,
    why: 'The maximum. Transport, sockopt, final mask, REALITY and sniffing all stack on top of the protocol form.',
    sections: [
      {
        id: 'identity', title: 'Identity', n: 5,
        fields: [
          F('Enable', 'switch', true),
          F('Remark', 'text', 'reality-443', { req: true }),
          F('Protocol', 'select', 'VLESS', { lock: 'edit', h: 'cannot change after creation' }),
          F('Listen IP', 'text', '', { h: 'blank listens on every address' }),
          F('Port', 'num', '443', { req: true }),
        ],
      },
      {
        id: 'proto', title: 'VLESS', n: 12,
        fields: [
          F('Authentication', 'select', 'x25519 (post-quantum)'),
          F('decryption', 'ro', 'none'),
          F('encryption', 'ro', 'none'),
          F('Flow', 'select', 'xtls-rprx-vision'),
          F('Vision Seed', 'seed', '900, 500, 900, 256'),
          F('Fallbacks', 'repeat', '1 fallback: SNI, ALPN, Path, Dest, xVer'),
        ],
      },
      {
        id: 'transport', title: 'Transport', n: 33,
        note: 'XHTTP is the largest transport form: 32 fields. TCP is 9, gRPC 3.',
        fields: [
          F('Transmission', 'select', 'XHTTP'),
          F('Host', 'text', 'cdn.example.com'),
          F('Path', 'text', '/'),
          F('Mode', 'select', 'auto'),
          F('Padding Bytes', 'text', '100-1000'),
          F('Padding Placement', 'select', 'header', { bad: 'not allowed in this mode, so the core refuses the whole config' }),
          F('Uplink HTTP Method', 'select', 'POST'),
          F('xmux Max Concurrency', 'text', '16-32'),
          F('xmux Max Connections', 'text', '0', { bad: 'both xmux strategies set at once' }),
          F('... 24 more', 'more', 'session, sequence, uplink data, SSE, gRPC header, scMinPostsInterval, serverMaxHeaderBytes, 6 more xmux'),
        ],
      },
      {
        id: 'sockopt', title: 'Socket options', n: 18, adv: true,
        note: 'Rendered for every stream protocol, gated behind one switch.',
        fields: [
          F('Sockopt', 'switch', false),
          F('... 17 more', 'more', 'Route Mark, 5 TCP tunables, Proxy Protocol, TCP Fast Open, Multipath TCP, Penetrate, V6 Only, Domain Strategy, TCP Congestion, TProxy, Dialer Proxy, Interface Name, Trusted X-Forwarded-For'),
        ],
      },
      {
        id: 'mask', title: 'Final mask', n: 64, adv: true,
        note: 'Repeaters. Each TCP mask adds ~6 fields; 64 is the reachable total.',
        fields: [
          F('TCP Masks', 'repeat', 'none added'),
          F('UDP Masks', 'repeat', 'mKCP only'),
        ],
      },
      {
        id: 'security', title: 'Security (REALITY)', n: 16,
        fields: [
          F('Security', 'radio', 'REALITY'),
          F('Target', 'text', 'www.cloudflare.com:443'),
          F('SNI', 'text', 'www.cloudflare.com'),
          F('Public Key', 'ro', 'kPqR...9wA'),
          F('Private Key', 'ro', 'yBv2...Xk4'),
          F('Short IDs', 'text', '6ba85179e30d4fc2'),
          F('... 10 more', 'more', 'Show, Xver, uTLS, Max Time Diff, Min/Max Client Ver, SpiderX, mldsa65 Seed, mldsa65 Verify'),
        ],
      },
      {
        id: 'access', title: 'Access limits', n: 2,
        fields: [
          F('IP Limit', 'num', '2', { h: 'per account; a client override wins' }),
          F('IP Limit Strategy', 'radio', 'Reject'),
        ],
      },
      QUOTA(), SNIFF(),
    ],
  },

  /* Five PEM blobs, two ports, a cipher matrix, and a save gate that says nothing. */
  openvpn: {
    label: 'OpenVPN', tagline: 'TCP + UDP, generated certs',
    family: 'PPP / user-password', port: '1195', total: 48,
    why: 'The largest non-Xray form. Its certificate block alone gates the save, silently.',
    sections: [
      {
        id: 'identity', title: 'Identity', n: 8,
        note: 'The only protocol with two port rows plus a switch that splits them.',
        fields: [
          F('Enable', 'switch', true),
          F('Remark', 'text', 'ovpn-main', { req: true }),
          F('Protocol', 'select', 'OpenVPN', { lock: 'edit' }),
          F('Listen IP', 'text', ''),
          F('Separate Ports', 'switch', true, { h: 'off: TCP and UDP share one number' }),
          F('TCP Port', 'num', '1194', { req: true }),
          F('UDP Port', 'num', '1195', { req: true }),
          F('Friendly Name', 'text', 'My VPN', { h: 'shown in OpenVPN Connect' }),
        ],
      },
      {
        id: 'security', title: 'Certificates', n: 11,
        note: 'Four of the seven cert-bearing protocols repeat this Content / File / Managed switch.',
        fields: [
          F('Certificate Source', 'radio', 'Content'),
          F('CA Certificate', 'area', '-----BEGIN CERTIFICATE-----...', { req: true }),
          F('CA Key', 'area', '-----BEGIN PRIVATE KEY-----...'),
          F('Server Certificate', 'area', '', { req: true, bad: 'empty, and this is why Add is greyed out' }),
          F('Server Key', 'area', ''),
          F('TLS-Crypt', 'switch', true),
          F('TLS-Crypt Key', 'area', '', { req: true, bad: 'required while TLS-Crypt is on' }),
          F('Generate certificates', 'btn', 'one click fills all five'),
        ],
      },
      {
        id: 'ciphers', title: 'Ciphers', n: 4, adv: true,
        fields: [
          F('Mode', 'radio', 'AEAD only'),
          F('AEAD', 'check', 'AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305'),
          F('CBC', 'check', 'none selected'),
        ],
      },
      {
        id: 'network', title: 'Network handout', n: 4,
        note: 'The same four rows appear on 9 protocols.',
        fields: HANDOUT('10.2.0.0/24'),
      },
      {
        id: 'access', title: 'Access limits', n: 4,
        fields: [
          F('User Limit', 'num', '10', { h: 'devices per account; each gets its own IP' }),
          F('User Limit Strategy', 'radio', 'Accept'),
          ...MESH(),
        ],
      },
      EXTPROXY(), QUOTA(),
      {
        id: 'export', title: 'Client config', n: 2, editOnly: true,
        note: 'Edit only, it needs a saved inbound id.',
        fields: [
          F('Download .ovpn (UDP)', 'btn', 'saves the form first'),
          F('Download .ovpn (TCP)', 'btn', 'saves the form first'),
        ],
      },
    ],
  },

  /* Two ports that are not a range, an auth mode that rewrites the form, and an
     async warning from the server about the cert. */
  ikev2: {
    label: 'IKEv2', tagline: 'PSK mode',
    family: 'PPP / user-password', port: '500', total: 42,
    why: 'Its auth mode changes which half of the form is even relevant, and the cert warning arrives from the server after you type.',
    sections: [
      {
        id: 'identity', title: 'Identity', n: 7,
        fields: [
          F('Enable', 'switch', true),
          F('Remark', 'text', 'ikev2-psk', { req: true }),
          F('Protocol', 'select', 'IKEv2', { lock: 'edit' }),
          F('Listen IP', 'text', ''),
          F('Port', 'num', '500', { req: true, h: 'IKE, UDP' }),
          F('NAT-T Port', 'num', '4500', { h: 'used once a NAT is detected' }),
          F('Server Address (SAN)', 'text', 'vpn.example.com', { h: 'must match what clients dial' }),
        ],
      },
      {
        id: 'auth', title: 'Authentication', n: 3,
        note: 'Picking PSK makes the whole certificate section below inert.',
        fields: [
          F('Authentication Mode', 'radio', 'PSK (shared secret)'),
          F('Pre-Shared Key', 'text', 'A7f...k92', { req: true, h: 'auto-filled the first time PSK is picked' }),
        ],
      },
      {
        id: 'security', title: 'Certificates', n: 8,
        note: 'Inert in PSK mode, and nothing on screen says so today.',
        warn: 'A non-RSA server certificate is silently rejected by iOS. The panel checks this after the fact.',
        fields: [
          F('Certificate Source', 'radio', 'Content'),
          F('Server Certificate', 'area', ''),
          F('Server Key', 'area', ''),
          F('Generate CA + server cert', 'btn', 'warns about device trust first'),
        ],
      },
      { id: 'network', title: 'Network handout', n: 4, fields: HANDOUT('10.6.0.0/24') },
      {
        id: 'access', title: 'Access limits', n: 4,
        fields: [F('User Limit', 'num', '4'), F('User Limit Strategy', 'radio', 'Accept'), ...MESH()],
      },
      EXTPROXY(), QUOTA(),
    ],
  },

  /* The floor. If a redesign makes THIS heavier, it has failed. */
  ssh: {
    label: 'SSH', tagline: 'relay',
    family: 'Relay', port: '2222', total: 25,
    why: 'The smallest protocol in the panel. Two thirds of its 25 fields are the commerce block every protocol carries.',
    sections: [
      {
        id: 'identity', title: 'Identity', n: 5,
        fields: [
          F('Enable', 'switch', true),
          F('Remark', 'text', 'ssh-relay', { req: true }),
          F('Protocol', 'select', 'SSH', { lock: 'edit' }),
          F('Listen IP', 'text', ''),
          F('Port', 'num', '2222', { req: true, h: 'not 22, the host sshd owns that' }),
        ],
      },
      {
        id: 'access', title: 'Access limits', n: 2,
        fields: [F('IP Limit', 'num', '0'), F('IP Limit Strategy', 'radio', 'Accept')],
      },
      EXTPROXY(), QUOTA(),
    ],
  },

  /* No port at all. Every layout that assumes a port row has to cope. */
  gre: {
    label: 'GRE', tagline: 'site-to-site',
    family: 'Tunnel / peer', port: null, total: 32,
    why: 'IP protocol 47: it has no port, so the row every other protocol pins its identity on is absent.',
    sections: [
      {
        id: 'identity', title: 'Identity', n: 4,
        note: 'No port row. The stored port exists only to build the inbound tag and the server assigns it.',
        fields: [
          F('Enable', 'switch', true),
          F('Remark', 'text', 'gre-branch', { req: true }),
          F('Protocol', 'select', 'GRE', { lock: 'edit' }),
          F('Listen IP', 'text', ''),
        ],
      },
      {
        id: 'network', title: 'Network handout', n: 3,
        fields: [
          F('IP Range', 'ro', '10.9.0.0/24', { h: 'assigned automatically on save' }),
          F('MTU', 'num', '1400', { h: '0 = kernel default' }),
          F('TTL', 'num', '64'),
        ],
      },
      {
        id: 'security', title: 'IPsec', n: 3,
        fields: [
          F('IPsec', 'switch', true),
          F('IPsec PSK', 'text', 'branch-psk-2026', { req: true }),
          F('Allow Unencrypted', 'switch', false, { h: 'accept peers that skip IPsec' }),
        ],
      },
      {
        id: 'transport', title: 'Encapsulation', n: 2, adv: true,
        fields: [
          F('FOU', 'switch', false, { h: 'UDP encapsulation, for paths that drop proto 47' }),
          F('FOU Port', 'num', '5555', { sub: true, off: true }),
        ],
      },
      {
        id: 'access', title: 'Access limits', n: 3,
        fields: [F('User Limit', 'num', '4', { h: 'peer routers' }), ...MESH()],
      },
      QUOTA(),
    ],
  },
};

/* Families, for the protocol picker in scheme A. Counts are the reachable field
   totals measured off the partials. */
const FAMILIES = [
  {
    name: 'Xray-native', note: 'transport, sockopt, final mask and TLS stack on top',
    items: [
      ['VLESS', 195], ['Trojan', 189], ['AnyTLS', 184], ['NaiveProxy', 172],
      ['Shadowsocks', 171], ['VMess', 167], ['Hysteria', 141], ['TUIC', 72],
    ],
  },
  {
    name: 'PPP / user-password', note: 'the customer types a username and a password',
    items: [['OpenVPN', 48], ['IKEv2', 42], ['OpenConnect', 38], ['SSTP', 38], ['L2TP', 34], ['PPTP', 31], ['SSH', 25]],
  },
  {
    name: 'Tunnel / peer', note: 'the client is a device or a router',
    items: [['WireGuard (Xray)', 34], ['WireGuard (C)', 33], ['AmneziaWG', 33], ['GRE', 32], ['TUN', 30]],
  },
  { name: 'Relay', note: 'no tunnel, just a forwarder', items: [['MTProto Proxy', 28], ['SSH', 25]] },
  { name: 'Utility', note: 'no accounts of its own', items: [['HTTP', 23], ['Mixed', 23], ['Tunnel', 23]] },
];

if (typeof module !== 'undefined') module.exports = { PROTOCOLS, FAMILIES };
