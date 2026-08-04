const Protocols = {
    Freedom: "freedom",
    Blackhole: "blackhole",
    DNS: "dns",
    VMess: "vmess",
    VLESS: "vless",
    Trojan: "trojan",
    Shadowsocks: "shadowsocks",
    Socks: "socks",
    HTTP: "http",
    Wireguard: "wireguard",
    Hysteria: "hysteria",
    // Native Xray protocols, same as everything above them: the core speaks all
    // three, so an outbound here is a real proxy handler and not a facade the
    // panel keeps alive. Nothing is spawned, nothing is managed, and there is no
    // /save endpoint behind them the way ssh and the tunnels have one.
    AnyTLS: "anytls",
    Tuic: "tuic",
    Naive: "naive",
    // Not an Xray protocol: Xray core ships no ssh outbound. The panel keeps the
    // SSH connection itself and fronts it with a local SOCKS5 proxy, so what
    // reaches the config is a `socks` outbound pointing at that proxy (see
    // Outbound.SshSettings and web/service/sshoutbound.go). Listed here so the
    // tunnel can be created from Add Outbound, where operators look for it.
    SSH: "ssh",
    // The nine client tunnels, one picker entry each. Also not Xray protocols:
    // every one of them serialises to the SAME freedom outbound pinned to a
    // netdev (see VPN_OUT_KINDS and web/service/vpnoutbound.go), so the kind is
    // the only thing that differs between them. They are listed LAST because the
    // picker renders this object in order and they belong after the protocols the
    // core itself speaks.
    //
    // This was ONE "vpn" entry with the kind picked inside the form, on the
    // argument that nine rows nearly double the picker and that the protocol
    // axis carries no information here. The operator overruled it: to whoever is
    // adding a tunnel, L2TP IS the protocol, and looking for it behind a generic
    // "vpn" row is the part nobody found. The picker is where protocols are
    // looked for, so that is where they go.
    //
    // Namespaced under "vpn:" because the bare names collide: "wireguard" above
    // is Xray's own native wireguard outbound and cannot mean two things. The
    // prefix is also what every check tests (isVpnProtocol below), so a tenth
    // tunnel is one entry here plus one in VPN_OUT_KINDS and no new branch.
    VpnWireguard: "vpn:wireguard",
    VpnAmneziaWG: "vpn:awg",
    VpnOpenVPN: "vpn:openvpn",
    VpnL2TP: "vpn:l2tp",
    VpnIKEv2: "vpn:ikev2",
    VpnSSTP: "vpn:sstp",
    VpnOpenConnect: "vpn:openconnect",
    VpnPPTP: "vpn:pptp",
    VpnGre: "vpn:gre"
};

// Helpers for the tunnel protocols above. Separate consts and functions rather
// than properties of Protocols on purpose: the Add Outbound picker walks that
// object to build its option list, so a function stored in it would be offered
// as a protocol.
const VPN_PROTOCOL_PREFIX = "vpn:";

function isVpnProtocol(protocol) {
    return typeof protocol === 'string' && protocol.startsWith(VPN_PROTOCOL_PREFIX);
}

// The VPN_OUT_KINDS key inside a tunnel protocol value, or '' for everything
// else. This is the discriminator: the kind decides which fields the form draws
// and which driver raises the tunnel.
function vpnKindOf(protocol) {
    return isVpnProtocol(protocol) ? protocol.slice(VPN_PROTOCOL_PREFIX.length) : '';
}

function vpnProtocolFor(kind) {
    return VPN_PROTOCOL_PREFIX + kind;
}

// Picker labels the Protocols KEY does not get right. One entry, and it is there
// to break a TIE rather than to decorate: Xray ships its own userspace wireguard
// outbound, the panel raises a kernel WireGuard tunnel, and unqualified they are
// two rows reading "Wireguard" and "WireGuard" one above the other. An operator
// who picks the wrong one gets a config that looks right and carries nothing.
//
// Both sides are qualified (see VPN_OUT_KINDS.wireguard) because a heading over
// the tunnels cannot fix this: it is gone the moment the dropdown closes, and
// what is left is one label standing alone with no neighbour to compare it to.
//
// The other three are here for capitalisation only. The Protocols KEY is what
// the picker falls back to, and "Tuic"/"Naive" are not how either project spells
// itself; an operator matching the row against the client they already run
// should not have to guess that they are the same thing.
const PROTOCOL_LABELS = {
    [Protocols.Wireguard]: 'WireGuard (Xray)',
    [Protocols.AnyTLS]: 'AnyTLS',
    [Protocols.Tuic]: 'TUIC',
    [Protocols.Naive]: 'NaiveProxy',
};

// What the Add Outbound picker shows for one protocol. The KEY of the Protocols
// entry reads well for VMess and not at all for a tunnel ("VpnOpenConnect"), so
// a tunnel takes the name its kind already carries in VPN_OUT_KINDS. Read at
// render time, which is why it can name a table defined further down this file.
function protocolLabel(value, key) {
    const kind = vpnKindOf(value);
    if (!kind) return PROTOCOL_LABELS[value] || key;
    return (VPN_OUT_KINDS[kind] || {}).label || key;
}

// Normalises the `servers` array of a server-shaped outbound (socks/http/ssh) to
// something always safe to index. A missing or empty `servers` is as common as a
// populated one here: the panel synthesises bare outbounds, and the JSON tab lets
// an operator hand-write a partial one. Callers still have to treat `users` as
// optional; see Outbound.SocksSettings.fromJson.
function firstServerOf(json) {
    const servers = json && json.servers;
    return Array.isArray(servers) && servers.length ? servers : [{}];
}

// A tuning number the operator left BLANK, dropped from the config entirely.
//
// The distinction matters because every one of these fields is a Go uint32 whose
// zero value means "use the core's default": an idleSessionTimeout of 0 is not a
// zero-second timeout, it is 30 seconds. Emitting 0 for a blank box would look
// like the operator asked for something and read as the default anyway, so the
// key is omitted instead and the two states stay distinguishable in the JSON tab.
function optionalNumber(value) {
    if (value === '' || value === null || value === undefined) return undefined;
    const n = Number(value);
    return Number.isFinite(n) ? n : undefined;
}

const SSMethods = {
    AES_256_GCM: 'aes-256-gcm',
    AES_128_GCM: 'aes-128-gcm',
    CHACHA20_POLY1305: 'chacha20-poly1305',
    CHACHA20_IETF_POLY1305: 'chacha20-ietf-poly1305',
    XCHACHA20_POLY1305: 'xchacha20-poly1305',
    XCHACHA20_IETF_POLY1305: 'xchacha20-ietf-poly1305',
    BLAKE3_AES_128_GCM: '2022-blake3-aes-128-gcm',
    BLAKE3_AES_256_GCM: '2022-blake3-aes-256-gcm',
    BLAKE3_CHACHA20_POLY1305: '2022-blake3-chacha20-poly1305',
};

const TLS_FLOW_CONTROL = {
    VISION: "xtls-rprx-vision",
    VISION_UDP443: "xtls-rprx-vision-udp443",
};

const UTLS_FINGERPRINT = {
    UTLS_CHROME: "chrome",
    UTLS_FIREFOX: "firefox",
    UTLS_SAFARI: "safari",
    UTLS_IOS: "ios",
    UTLS_android: "android",
    UTLS_EDGE: "edge",
    UTLS_360: "360",
    UTLS_QQ: "qq",
    UTLS_RANDOM: "random",
    UTLS_RANDOMIZED: "randomized",
    UTLS_RONDOMIZEDNOALPN: "randomizednoalpn",
    UTLS_UNSAFE: "unsafe",
};

const ALPN_OPTION = {
    H3: "h3",
    H2: "h2",
    HTTP1: "http/1.1",
};

const OutboundDomainStrategies = [
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv6v4",
    "UseIPv4v6",
    "ForceIP",
    "ForceIPv6v4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv4"
];

const WireguardDomainStrategy = [
    "ForceIP",
    "ForceIPv4",
    "ForceIPv4v6",
    "ForceIPv6",
    "ForceIPv6v4"
];

const USERS_SECURITY = {
    AES_128_GCM: "aes-128-gcm",
    CHACHA20_POLY1305: "chacha20-poly1305",
    AUTO: "auto",
    NONE: "none",
    ZERO: "zero",
};

const MODE_OPTION = {
    AUTO: "auto",
    PACKET_UP: "packet-up",
    STREAM_UP: "stream-up",
    STREAM_ONE: "stream-one",
};

const Address_Port_Strategy = {
    NONE: "none",
    SrvPortOnly: "srvportonly",
    SrvAddressOnly: "srvaddressonly",
    SrvPortAndAddress: "srvportandaddress",
    TxtPortOnly: "txtportonly",
    TxtAddressOnly: "txtaddressonly",
    TxtPortAndAddress: "txtportandaddress"
};

const DNSRuleActions = ['direct', 'drop', 'reject', 'hijack'];

function normalizeDNSRuleField(value) {
    if (value === null || value === undefined) {
        return '';
    }
    if (Array.isArray(value)) {
        return value.map(item => item.toString().trim()).filter(item => item.length > 0).join(',');
    }
    return value.toString().trim();
}

function normalizeDNSRuleAction(action) {
    action = ObjectUtil.isEmpty(action) ? 'direct' : action.toString().toLowerCase().trim();
    return DNSRuleActions.includes(action) ? action : 'direct';
}

function parseLegacyDNSBlockTypes(blockTypes) {
    if (blockTypes === null || blockTypes === undefined || blockTypes === '') {
        return [];
    }

    if (Array.isArray(blockTypes)) {
        return blockTypes
            .map(item => Number(item))
            .filter(item => Number.isInteger(item) && item >= 0 && item <= 65535);
    }

    if (typeof blockTypes === 'number') {
        return Number.isInteger(blockTypes) && blockTypes >= 0 && blockTypes <= 65535 ? [blockTypes] : [];
    }

    return blockTypes
        .toString()
        .split(',')
        .map(item => item.trim())
        .filter(item => /^\d+$/.test(item))
        .map(item => Number(item))
        .filter(item => item >= 0 && item <= 65535);
}

function buildLegacyDNSRules(nonIPQuery, blockTypes) {
    const mode = ['reject', 'drop', 'skip'].includes(nonIPQuery) ? nonIPQuery : 'reject';
    const rules = [];
    const parsedBlockTypes = parseLegacyDNSBlockTypes(blockTypes);

    if (parsedBlockTypes.length > 0) {
        rules.push(new Outbound.DNSRule(mode === 'reject' ? 'reject' : 'drop', parsedBlockTypes.join(',')));
    }

    rules.push(new Outbound.DNSRule('hijack', '1,28'));
    rules.push(new Outbound.DNSRule(mode === 'skip' ? 'direct' : mode));

    return rules;
}

function getDNSRulesFromJson(json = {}) {
    if (Array.isArray(json.rules) && json.rules.length > 0) {
        return json.rules.map(rule => Outbound.DNSRule.fromJson(rule));
    }

    if (json.nonIPQuery !== undefined || json.blockTypes !== undefined) {
        return buildLegacyDNSRules(json.nonIPQuery, json.blockTypes);
    }

    return [];
}

Object.freeze(Protocols);
Object.freeze(SSMethods);
Object.freeze(TLS_FLOW_CONTROL);
Object.freeze(UTLS_FINGERPRINT);
Object.freeze(ALPN_OPTION);
Object.freeze(OutboundDomainStrategies);
Object.freeze(WireguardDomainStrategy);
Object.freeze(USERS_SECURITY);
Object.freeze(MODE_OPTION);
Object.freeze(Address_Port_Strategy);
Object.freeze(DNSRuleActions);

class CommonClass {

    static toJsonArray(arr) {
        return arr.map(obj => obj.toJson());
    }

    static fromJson() {
        return new CommonClass();
    }

    toJson() {
        return this;
    }

    toString(format = true) {
        return format ? JSON.stringify(this.toJson(), null, 2) : JSON.stringify(this.toJson());
    }
}

class TcpStreamSettings extends CommonClass {
    constructor(type = 'none', host, path) {
        super();
        this.type = type;
        this.host = host;
        this.path = path;
    }

    static fromJson(json = {}) {
        let header = json.header;
        if (!header) return new TcpStreamSettings();
        if (header.type == 'http' && header.request) {
            return new TcpStreamSettings(
                header.type,
                header.request.headers.Host.join(','),
                header.request.path.join(','),
            );
        }
        return new TcpStreamSettings(header.type, '', '');
    }

    toJson() {
        return {
            header: {
                type: this.type,
                request: this.type === 'http' ? {
                    headers: {
                        Host: ObjectUtil.isEmpty(this.host) ? [] : this.host.split(',')
                    },
                    path: ObjectUtil.isEmpty(this.path) ? ["/"] : this.path.split(',')
                } : undefined,
            }
        };
    }
}

class KcpStreamSettings extends CommonClass {
    constructor(
        mtu = 1350,
        tti = 20,
        uplinkCapacity = 5,
        downlinkCapacity = 20,
        cwndMultiplier = 1,
        maxSendingWindow = 1350,
    ) {
        super();
        this.mtu = mtu;
        this.tti = tti;
        this.upCap = uplinkCapacity;
        this.downCap = downlinkCapacity;
        this.cwndMultiplier = cwndMultiplier;
        this.maxSendingWindow = maxSendingWindow;
    }

    static fromJson(json = {}) {
        return new KcpStreamSettings(
            json.mtu,
            json.tti,
            json.uplinkCapacity,
            json.downlinkCapacity,
            json.cwndMultiplier,
            json.maxSendingWindow,
        );
    }

    toJson() {
        return {
            mtu: this.mtu,
            tti: this.tti,
            uplinkCapacity: this.upCap,
            downlinkCapacity: this.downCap,
            cwndMultiplier: this.cwndMultiplier,
            maxSendingWindow: this.maxSendingWindow,
        };
    }
}

class WsStreamSettings extends CommonClass {
    constructor(
        path = '/',
        host = '',
        heartbeatPeriod = 0,

    ) {
        super();
        this.path = path;
        this.host = host;
        this.heartbeatPeriod = heartbeatPeriod;
    }

    static fromJson(json = {}) {
        return new WsStreamSettings(
            json.path,
            json.host,
            json.heartbeatPeriod,
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
            heartbeatPeriod: this.heartbeatPeriod
        };
    }
}

class GrpcStreamSettings extends CommonClass {
    constructor(
        serviceName = "",
        authority = "",
        multiMode = false
    ) {
        super();
        this.serviceName = serviceName;
        this.authority = authority;
        this.multiMode = multiMode;
    }

    static fromJson(json = {}) {
        return new GrpcStreamSettings(json.serviceName, json.authority, json.multiMode);
    }

    toJson() {
        return {
            serviceName: this.serviceName,
            authority: this.authority,
            multiMode: this.multiMode
        }
    }
}

class HttpUpgradeStreamSettings extends CommonClass {
    constructor(path = '/', host = '') {
        super();
        this.path = path;
        this.host = host;
    }

    static fromJson(json = {}) {
        return new HttpUpgradeStreamSettings(
            json.path,
            json.host,
        );
    }

    toJson() {
        return {
            path: this.path,
            host: this.host,
        };
    }
}

class xHTTPStreamSettings extends CommonClass {
    constructor(
        path = '/',
        host = '',
        mode = '',
        noGRPCHeader = false,
        scMinPostsIntervalMs = "30",
        xmux = {
            maxConcurrency: "16-32",
            maxConnections: 0,
            cMaxReuseTimes: 0,
            hMaxRequestTimes: "600-900",
            hMaxReusableSecs: "1800-3000",
            hKeepAlivePeriod: 0,
        },
        scMaxEachPostBytes = '',
        xPaddingBytes = '',
        downloadSettings = undefined,
        extra = {},
    ) {
        super();
        this.path = path;
        this.host = host;
        this.mode = mode;
        this.noGRPCHeader = noGRPCHeader;
        this.scMinPostsIntervalMs = scMinPostsIntervalMs;
        this.xmux = xmux;
        this.scMaxEachPostBytes = scMaxEachPostBytes;
        this.xPaddingBytes = xPaddingBytes;
        // downloadSettings is a full nested stream-settings object; stored
        // and round-tripped verbatim (we do not model its internals here).
        this.downloadSettings = downloadSettings;
        // Any xhttp key the form does not model structurally (headers,
        // noSSEHeader, scMaxBufferedPosts, xPadding* obfs, uplink*/session*/seq*,
        // future keys...) is preserved verbatim here so ANY xhttp object shape
        // round-trips losslessly. Kept out of the structured fields above.
        this.extra = extra && typeof extra === 'object' ? extra : {};
    }

    static fromJson(json = {}) {
        // Everything the structured fields don't own is kept verbatim in `extra`.
        const extra = {};
        Object.keys(json).forEach(k => {
            if (!xHTTPStreamSettings.STRUCTURED_KEYS.has(k)) extra[k] = json[k];
        });
        return new xHTTPStreamSettings(
            json.path,
            json.host,
            json.mode,
            json.noGRPCHeader,
            json.scMinPostsIntervalMs,
            json.xmux,
            json.scMaxEachPostBytes,
            json.xPaddingBytes,
            json.downloadSettings,
            extra
        );
    }

    toJson() {
        // Start from the preserved passthrough so unmodeled keys survive; the
        // structured fields below then overwrite their own keys. For a plain
        // xhttp link `extra` is empty, so output stays byte-identical.
        const o = Object.assign({}, this.extra);
        o.path = this.path;
        o.host = this.host;
        o.mode = this.mode;
        o.noGRPCHeader = this.noGRPCHeader;
        o.scMinPostsIntervalMs = this.scMinPostsIntervalMs;
        // Spread the live xmux so any extra sub-keys (e.g. cMaxLifetimeMs) ride
        // along instead of being flattened to the six the form knows about.
        o.xmux = Object.assign({}, this.xmux);
        // Only emit the extended xhttp fields when they carry a real value so
        // existing outputs stay byte-identical for plain xhttp links.
        if (this.scMaxEachPostBytes !== undefined && this.scMaxEachPostBytes !== '') o.scMaxEachPostBytes = this.scMaxEachPostBytes;
        if (this.xPaddingBytes !== undefined && this.xPaddingBytes !== '') o.xPaddingBytes = this.xPaddingBytes;
        if (this.downloadSettings !== undefined && this.downloadSettings !== null) o.downloadSettings = this.downloadSettings;
        return o;
    }
}
// Keys the structured constructor/toJson own; everything else is preserved
// verbatim in `extra` so any xhttp object shape round-trips losslessly.
xHTTPStreamSettings.STRUCTURED_KEYS = new Set([
    'path', 'host', 'mode', 'noGRPCHeader', 'scMinPostsIntervalMs',
    'xmux', 'scMaxEachPostBytes', 'xPaddingBytes', 'downloadSettings',
]);

class TlsStreamSettings extends CommonClass {
    constructor(
        serverName = '',
        alpn = [],
        fingerprint = '',
        echConfigList = '',
        verifyPeerCertByName = '',
        pinnedPeerCertSha256 = '',
    ) {
        super();
        this.serverName = serverName;
        this.alpn = alpn;
        this.fingerprint = fingerprint;
        this.echConfigList = echConfigList;
        this.verifyPeerCertByName = verifyPeerCertByName;
        this.pinnedPeerCertSha256 = pinnedPeerCertSha256;
    }

    static fromJson(json = {}) {
        return new TlsStreamSettings(
            json.serverName,
            json.alpn,
            json.fingerprint,
            json.echConfigList,
            json.verifyPeerCertByName,
            json.pinnedPeerCertSha256,
        );
    }

    toJson() {
        const o = { serverName: this.serverName };
        // Emit optional TLS fields only when they carry a value. Xray rejects a
        // blank/"none" fingerprint ("unknown fingerprint"), and empty optionals
        // just add noise, so omit them.
        if (Array.isArray(this.alpn) && this.alpn.length) o.alpn = this.alpn;
        if (this.fingerprint && this.fingerprint !== 'none') o.fingerprint = this.fingerprint;
        if (this.echConfigList) o.echConfigList = this.echConfigList;
        if (this.verifyPeerCertByName) o.verifyPeerCertByName = this.verifyPeerCertByName;
        if (this.pinnedPeerCertSha256 && !(Array.isArray(this.pinnedPeerCertSha256) && this.pinnedPeerCertSha256.length === 0)) {
            o.pinnedPeerCertSha256 = this.pinnedPeerCertSha256;
        }
        return o;
    }
}

class RealityStreamSettings extends CommonClass {
    constructor(
        publicKey = '',
        fingerprint = '',
        serverName = '',
        shortId = '',
        spiderX = '',
        mldsa65Verify = ''
    ) {
        super();
        this.publicKey = publicKey;
        this.fingerprint = fingerprint;
        this.serverName = serverName;
        this.shortId = shortId
        this.spiderX = spiderX;
        this.mldsa65Verify = mldsa65Verify;
    }
    static fromJson(json = {}) {
        return new RealityStreamSettings(
            json.publicKey,
            json.fingerprint,
            json.serverName,
            json.shortId,
            json.spiderX,
            json.mldsa65Verify
        );
    }
    toJson() {
        return {
            publicKey: this.publicKey,
            fingerprint: this.fingerprint,
            serverName: this.serverName,
            shortId: this.shortId,
            spiderX: this.spiderX,
            mldsa65Verify: this.mldsa65Verify
        };
    }
};

class HysteriaStreamSettings extends CommonClass {
    constructor(
        version = 2,
        auth = '',
        congestion = '',
        up = '0',
        down = '0',
        udphopPort = '',
        udphopIntervalMin = 30,
        udphopIntervalMax = 30,
        initStreamReceiveWindow = 8388608,
        maxStreamReceiveWindow = 8388608,
        initConnectionReceiveWindow = 20971520,
        maxConnectionReceiveWindow = 20971520,
        maxIdleTimeout = 30,
        keepAlivePeriod = 0,
        disablePathMTUDiscovery = false
    ) {
        super();
        this.version = version;
        this.auth = auth;
        this.congestion = congestion;
        this.up = up;
        this.down = down;
        this.udphopPort = udphopPort;
        this.udphopIntervalMin = udphopIntervalMin;
        this.udphopIntervalMax = udphopIntervalMax;
        this.initStreamReceiveWindow = initStreamReceiveWindow;
        this.maxStreamReceiveWindow = maxStreamReceiveWindow;
        this.initConnectionReceiveWindow = initConnectionReceiveWindow;
        this.maxConnectionReceiveWindow = maxConnectionReceiveWindow;
        this.maxIdleTimeout = maxIdleTimeout;
        this.keepAlivePeriod = keepAlivePeriod;
        this.disablePathMTUDiscovery = disablePathMTUDiscovery;
    }

    static fromJson(json = {}) {
        let udphopPort = '';
        let udphopIntervalMin = 30;
        let udphopIntervalMax = 30;
        if (json.udphop) {
            udphopPort = json.udphop.port || '';
            // Backward compatibility: if old 'interval' exists, use it for both min/max
            if (json.udphop.interval !== undefined) {
                udphopIntervalMin = json.udphop.interval;
                udphopIntervalMax = json.udphop.interval;
            } else {
                udphopIntervalMin = json.udphop.intervalMin || 30;
                udphopIntervalMax = json.udphop.intervalMax || 30;
            }
        }
        return new HysteriaStreamSettings(
            json.version,
            json.auth,
            json.congestion,
            json.up,
            json.down,
            udphopPort,
            udphopIntervalMin,
            udphopIntervalMax,
            json.initStreamReceiveWindow,
            json.maxStreamReceiveWindow,
            json.initConnectionReceiveWindow,
            json.maxConnectionReceiveWindow,
            json.maxIdleTimeout,
            json.keepAlivePeriod,
            json.disablePathMTUDiscovery
        );
    }

    toJson() {
        const result = {
            version: this.version,
            auth: this.auth,
            congestion: this.congestion,
            up: this.up,
            down: this.down,
            initStreamReceiveWindow: this.initStreamReceiveWindow,
            maxStreamReceiveWindow: this.maxStreamReceiveWindow,
            initConnectionReceiveWindow: this.initConnectionReceiveWindow,
            maxConnectionReceiveWindow: this.maxConnectionReceiveWindow,
            maxIdleTimeout: this.maxIdleTimeout,
            keepAlivePeriod: this.keepAlivePeriod,
            disablePathMTUDiscovery: this.disablePathMTUDiscovery
        };
        if (this.udphopPort) {
            result.udphop = {
                port: this.udphopPort,
                intervalMin: this.udphopIntervalMin,
                intervalMax: this.udphopIntervalMax
            };
        }
        return result;
    }
};
class SockoptStreamSettings extends CommonClass {
    constructor(
        dialerProxy = "",
        tcpFastOpen = false,
        tcpKeepAliveInterval = 0,
        tcpMptcp = false,
        penetrate = false,
        addressPortStrategy = Address_Port_Strategy.NONE,
        // Xray's JSON key is "interface", which is a reserved word and so cannot
        // name a binding inside a class body (always strict mode). Held under
        // interfaceName and translated back in toJson, as inbound.js does.
        interfaceName = "",
        mark = 0,
        trustedXForwardedFor = [],
    ) {
        super();
        this.dialerProxy = dialerProxy;
        this.tcpFastOpen = tcpFastOpen;
        this.tcpKeepAliveInterval = tcpKeepAliveInterval;
        this.tcpMptcp = tcpMptcp;
        this.penetrate = penetrate;
        this.addressPortStrategy = addressPortStrategy;
        this.interfaceName = interfaceName;
        this.mark = mark;
        this.trustedXForwardedFor = trustedXForwardedFor;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return undefined;
        return new SockoptStreamSettings(
            json.dialerProxy,
            json.tcpFastOpen,
            json.tcpKeepAliveInterval,
            json.tcpMptcp,
            json.penetrate,
            json.addressPortStrategy,
            json.interface,
            json.mark,
            json.trustedXForwardedFor || []
        );
    }

    toJson() {
        const result = {
            dialerProxy: this.dialerProxy,
            tcpFastOpen: this.tcpFastOpen,
            tcpKeepAliveInterval: this.tcpKeepAliveInterval,
            tcpMptcp: this.tcpMptcp,
            penetrate: this.penetrate,
            addressPortStrategy: this.addressPortStrategy
        };
        // Only emitted when set, so an outbound that never used them does not
        // gain SO_BINDTODEVICE/SO_MARK keys just by being opened and saved.
        if (this.interfaceName) {
            result.interface = this.interfaceName;
        }
        if (this.mark) {
            result.mark = this.mark;
        }
        if (this.trustedXForwardedFor && this.trustedXForwardedFor.length > 0) {
            result.trustedXForwardedFor = this.trustedXForwardedFor;
        }
        return result;
    }
}

class UdpMask extends CommonClass {
    constructor(type = 'salamander', settings = {}) {
        super();
        this.type = type;
        this.settings = this._getDefaultSettings(type, settings);
    }

    _getDefaultSettings(type, settings = {}) {
        switch (type) {
            case 'salamander':
            case 'mkcp-aes128gcm':
                return { password: settings.password || '' };
            case 'header-dns':
                return { domain: settings.domain || '' };
            case 'xdns':
                return { resolvers: Array.isArray(settings.resolvers) ? settings.resolvers : [] };
            case 'xicmp':
                return { ip: settings.ip || '', id: settings.id ?? 0 };
            case 'mkcp-original':
            case 'header-dtls':
            case 'header-srtp':
            case 'header-utp':
            case 'header-wechat':
            case 'header-wireguard':
                return {}; // No settings needed
            case 'header-custom':
                return {
                    client: Array.isArray(settings.client) ? settings.client : [],
                    server: Array.isArray(settings.server) ? settings.server : [],
                };
            case 'noise':
                return {
                    reset: settings.reset ?? 0,
                    noise: Array.isArray(settings.noise) ? settings.noise : [],
                };
            case 'sudoku':
                return {
                    ascii: settings.ascii || '',
                    customTable: settings.customTable || '',
                    customTables: Array.isArray(settings.customTables) ? settings.customTables : [],
                    paddingMin: settings.paddingMin ?? 0,
                    paddingMax: settings.paddingMax ?? 0
                };
            default:
                return settings;
        }
    }

    static fromJson(json = {}) {
        return new UdpMask(
            json.type || 'salamander',
            json.settings || {}
        );
    }

    toJson() {
        const cleanItem = item => {
            const out = { ...item };
            if (out.type === 'array') {
                delete out.packet;
            } else {
                delete out.rand;
                delete out.randRange;
            }
            return out;
        };

        let settings = this.settings;
        if (this.type === 'noise' && settings && Array.isArray(settings.noise)) {
            settings = { ...settings, noise: settings.noise.map(cleanItem) };
        } else if (this.type === 'header-custom' && settings) {
            settings = {
                ...settings,
                client: Array.isArray(settings.client) ? settings.client.map(cleanItem) : settings.client,
                server: Array.isArray(settings.server) ? settings.server.map(cleanItem) : settings.server,
            };
        }

        return {
            type: this.type,
            settings: (settings && Object.keys(settings).length > 0) ? settings : undefined
        };
    }
}

class TcpMask extends CommonClass {
    constructor(type = 'fragment', settings = {}) {
        super();
        this.type = type;
        this.settings = this._getDefaultSettings(type, settings);
    }

    _getDefaultSettings(type, settings = {}) {
        switch (type) {
            case 'fragment':
                return {
                    packets: settings.packets ?? 'tlshello',
                    length: settings.length ?? '',
                    delay: settings.delay ?? '',
                    maxSplit: settings.maxSplit ?? '',
                };
            case 'sudoku':
                return {
                    password: settings.password ?? '',
                    ascii: settings.ascii ?? '',
                    customTable: settings.customTable ?? '',
                    customTables: Array.isArray(settings.customTables) ? settings.customTables : [],
                    paddingMin: settings.paddingMin ?? 0,
                    paddingMax: settings.paddingMax ?? 0,
                };
            case 'header-custom':
                return {
                    clients: Array.isArray(settings.clients) ? settings.clients : [],
                    servers: Array.isArray(settings.servers) ? settings.servers : [],
                };
            default:
                return settings;
        }
    }

    static fromJson(json = {}) {
        return new TcpMask(
            json.type || 'fragment',
            json.settings || {}
        );
    }

    toJson() {
        const cleanItem = item => {
            const out = { ...item };
            if (out.type === 'array') {
                delete out.packet;
            } else {
                delete out.rand;
                delete out.randRange;
            }
            return out;
        };

        let settings = this.settings;
        if (this.type === 'header-custom' && settings) {
            const cleanGroup = group => Array.isArray(group) ? group.map(cleanItem) : group;
            settings = {
                ...settings,
                clients: Array.isArray(settings.clients) ? settings.clients.map(cleanGroup) : settings.clients,
                servers: Array.isArray(settings.servers) ? settings.servers.map(cleanGroup) : settings.servers,
            };
        }

        return {
            type: this.type,
            settings: (settings && Object.keys(settings).length > 0) ? settings : undefined
        };
    }
}

class QuicParams extends CommonClass {
    constructor(
        congestion = 'bbr',
        debug = false,
        brutalUp = '',
        brutalDown = '',
        udpHop = undefined,
    ) {
        super();
        this.congestion = congestion;
        this.debug = debug;
        this.brutalUp = brutalUp;
        this.brutalDown = brutalDown;
        this.udpHop = udpHop;
    }

    get hasUdpHop() {
        return this.udpHop != null;
    }

    set hasUdpHop(value) {
        this.udpHop = value ? (this.udpHop || { ports: '20000-50000', interval: '5-10' }) : undefined;
    }

    static fromJson(json = {}) {
        if (!json || Object.keys(json).length === 0) return undefined;
        return new QuicParams(
            json.congestion,
            json.debug,
            json.brutalUp,
            json.brutalDown,
            json.udpHop ? { ports: json.udpHop.ports, interval: json.udpHop.interval } : undefined,
        );
    }

    toJson() {
        const result = { congestion: this.congestion };
        if (this.debug) result.debug = this.debug;
        if (this.brutalUp) result.brutalUp = this.brutalUp;
        if (this.brutalDown) result.brutalDown = this.brutalDown;
        if (this.udpHop) result.udpHop = { ports: this.udpHop.ports, interval: this.udpHop.interval };
        return result;
    }
}

class FinalMaskStreamSettings extends CommonClass {
    constructor(tcp = [], udp = [], quicParams = undefined) {
        super();
        this.tcp = Array.isArray(tcp) ? tcp.map(t => t instanceof TcpMask ? t : new TcpMask(t.type, t.settings)) : [];
        this.udp = Array.isArray(udp) ? udp.map(u => new UdpMask(u.type, u.settings)) : [new UdpMask(udp.type, udp.settings)];
        this.quicParams = quicParams instanceof QuicParams ? quicParams : (quicParams ? QuicParams.fromJson(quicParams) : undefined);
    }

    get enableQuicParams() {
        return this.quicParams != null;
    }

    set enableQuicParams(value) {
        this.quicParams = value ? (this.quicParams || new QuicParams()) : undefined;
    }

    static fromJson(json = {}) {
        return new FinalMaskStreamSettings(
            json.tcp || [],
            json.udp || [],
            json.quicParams ? QuicParams.fromJson(json.quicParams) : undefined,
        );
    }

    toJson() {
        const result = {};
        if (this.tcp && this.tcp.length > 0) {
            result.tcp = this.tcp.map(t => t.toJson());
        }
        if (this.udp && this.udp.length > 0) {
            result.udp = this.udp.map(udp => udp.toJson());
        }
        if (this.quicParams) {
            result.quicParams = this.quicParams.toJson();
        }
        return result;
    }
}

class StreamSettings extends CommonClass {
    constructor(
        network = 'tcp',
        security = 'none',
        tlsSettings = new TlsStreamSettings(),
        realitySettings = new RealityStreamSettings(),
        tcpSettings = new TcpStreamSettings(),
        kcpSettings = new KcpStreamSettings(),
        wsSettings = new WsStreamSettings(),
        grpcSettings = new GrpcStreamSettings(),
        httpupgradeSettings = new HttpUpgradeStreamSettings(),
        xhttpSettings = new xHTTPStreamSettings(),
        hysteriaSettings = new HysteriaStreamSettings(),
        finalmask = new FinalMaskStreamSettings(),
        sockopt = undefined,
    ) {
        super();
        this.network = network;
        this.security = security;
        this.tls = tlsSettings;
        this.reality = realitySettings;
        this.tcp = tcpSettings;
        this.kcp = kcpSettings;
        this.ws = wsSettings;
        this.grpc = grpcSettings;
        this.httpupgrade = httpupgradeSettings;
        this.xhttp = xhttpSettings;
        this.hysteria = hysteriaSettings;
        this.finalmask = finalmask;
        this.sockopt = sockopt;
    }

    addTcpMask(type = 'fragment') {
        this.finalmask.tcp.push(new TcpMask(type));
    }

    delTcpMask(index) {
        if (this.finalmask.tcp) {
            this.finalmask.tcp.splice(index, 1);
        }
    }

    addUdpMask(type = 'salamander') {
        this.finalmask.udp.push(new UdpMask(type));
    }

    delUdpMask(index) {
        if (this.finalmask.udp) {
            this.finalmask.udp.splice(index, 1);
        }
    }

    get hasFinalMask() {
        const hasTcp = this.finalmask.tcp && this.finalmask.tcp.length > 0;
        const hasUdp = this.finalmask.udp && this.finalmask.udp.length > 0;
        const hasQuicParams = this.finalmask.quicParams != null;
        return hasTcp || hasUdp || hasQuicParams;
    }

    get isTls() {
        return this.security === 'tls';
    }

    get isReality() {
        return this.security === "reality";
    }

    get sockoptSwitch() {
        return this.sockopt != undefined;
    }

    set sockoptSwitch(value) {
        this.sockopt = value ? new SockoptStreamSettings() : undefined;
    }

    static fromJson(json = {}) {
        return new StreamSettings(
            json.network,
            json.security,
            TlsStreamSettings.fromJson(json.tlsSettings),
            RealityStreamSettings.fromJson(json.realitySettings),
            TcpStreamSettings.fromJson(json.tcpSettings),
            KcpStreamSettings.fromJson(json.kcpSettings),
            WsStreamSettings.fromJson(json.wsSettings),
            GrpcStreamSettings.fromJson(json.grpcSettings),
            HttpUpgradeStreamSettings.fromJson(json.httpupgradeSettings),
            xHTTPStreamSettings.fromJson(json.xhttpSettings),
            HysteriaStreamSettings.fromJson(json.hysteriaSettings),
            FinalMaskStreamSettings.fromJson(json.finalmask),
            SockoptStreamSettings.fromJson(json.sockopt),
        );
    }

    toJson() {
        const network = this.network;
        return {
            network: network,
            security: this.security,
            tlsSettings: this.security == 'tls' ? this.tls.toJson() : undefined,
            realitySettings: this.security == 'reality' ? this.reality.toJson() : undefined,
            tcpSettings: network === 'tcp' ? this.tcp.toJson() : undefined,
            kcpSettings: network === 'kcp' ? this.kcp.toJson() : undefined,
            wsSettings: network === 'ws' ? this.ws.toJson() : undefined,
            grpcSettings: network === 'grpc' ? this.grpc.toJson() : undefined,
            httpupgradeSettings: network === 'httpupgrade' ? this.httpupgrade.toJson() : undefined,
            xhttpSettings: network === 'xhttp' ? this.xhttp.toJson() : undefined,
            hysteriaSettings: network === 'hysteria' ? this.hysteria.toJson() : undefined,
            finalmask: this.hasFinalMask ? this.finalmask.toJson() : undefined,
            sockopt: this.sockopt != undefined ? this.sockopt.toJson() : undefined,
        };
    }
}

class Mux extends CommonClass {
    constructor(enabled = false, concurrency = 8, xudpConcurrency = 16, xudpProxyUDP443 = "reject") {
        super();
        this.enabled = enabled;
        this.concurrency = concurrency;
        this.xudpConcurrency = xudpConcurrency;
        this.xudpProxyUDP443 = xudpProxyUDP443;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return undefined;
        return new Mux(
            json.enabled,
            json.concurrency,
            json.xudpConcurrency,
            json.xudpProxyUDP443,
        );
    }

    toJson() {
        return {
            enabled: this.enabled,
            concurrency: this.concurrency,
            xudpConcurrency: this.xudpConcurrency,
            xudpProxyUDP443: this.xudpProxyUDP443,
        };
    }
}

class Outbound extends CommonClass {
    constructor(
        tag = '',
        protocol = Protocols.VLESS,
        settings = null,
        streamSettings = new StreamSettings(),
        sendThrough,
        mux = new Mux(),
    ) {
        super();
        this.tag = tag;
        this._protocol = protocol;
        this.settings = settings == null ? Outbound.Settings.getSettings(protocol) : settings;
        this.stream = streamSettings;
        this.sendThrough = sendThrough;
        this.mux = mux;
    }

    get protocol() {
        return this._protocol;
    }

    set protocol(protocol) {
        this._protocol = protocol;
        this.settings = Outbound.Settings.getSettings(protocol);
        this.stream = Outbound.defaultStreamFor(protocol);
    }

    // The stream a freshly picked protocol starts on. Everything gets the plain
    // tcp/none default it always got; the two below get something else because
    // for them the default is not a starting point, it is a broken outbound the
    // operator has to know to repair.
    //
    // TUIC: its dialer refuses any stream whose network is not "tuic", and reads
    // its TLS off streamSettings. Starting at tcp/none means the outbound cannot
    // work until BOTH are changed, and neither is guessable from the form. ALPN
    // is prefilled to h3 for the third reason in the same family: the server is
    // pinned to h3, an empty ALPN is what every other client defaults to, and the
    // mismatch surfaces as "tls: no application protocol" naming neither end.
    //
    // AnyTLS: TLS is the protocol. It runs over a normal Xray stream, so the
    // network stays tcp and the operator can move it, but security starting at
    // "none" would be a plaintext AnyTLS outbound, which is not a configuration
    // anyone wants and not one the far side would accept.
    // NAIVE: two stacks behind one protocol, and which one is dialled is decided
    // by settings.network while the stream it is dialled over is decided here.
    // They are set together by setNaiveNetwork below and start on the h2 pair.
    static defaultStreamFor(protocol) {
        if (protocol === Protocols.Tuic) {
            const stream = new StreamSettings('tuic', 'tls');
            stream.tls.alpn = ['h3'];
            return stream;
        }
        if (protocol === Protocols.AnyTLS) return new StreamSettings('tcp', 'tls');
        if (protocol === Protocols.Naive) {
            const stream = new StreamSettings('tcp', 'tls');
            stream.tls.alpn = ['h2'];
            stream.tls.fingerprint = UTLS_FINGERPRINT.UTLS_CHROME;
            return stream;
        }
        return new StreamSettings();
    }

    // Moves a naive outbound between its two stacks, both halves at once.
    //
    // The core reads ONE of them and the transport layer reads the other, so
    // setting either alone produces an outbound that dials the wrong stack:
    //
    //   tcp -> HTTP/2 CONNECT written straight onto an ordinary TLS stream, so
    //          streamSettings is the plain tcp one and ALPN must be h2. The
    //          client checks the negotiated ALPN itself and refuses anything
    //          else, which is the one failure here that names its own cause.
    //   udp -> HTTP/3, dialled through the "naive" transport. That dialer takes
    //          its TLS from streamSettings and REFUSES to run at all for anything
    //          other than a naive outbound, so the network name has to be
    //          "naive" and security has to be tls.
    //
    // The core now normalises a mismatched pair in both directions, so this is
    // belt and braces rather than the only thing standing between the operator
    // and a dead outbound. It stays because a config that only works because
    // something downstream rewrote it is not one the JSON tab should be showing.
    setNaiveNetwork(network) {
        this.settings.network = network === 'udp' ? 'udp' : 'tcp';
        this.stream.security = 'tls';
        if (this.settings.network === 'udp') {
            this.stream.network = 'naive';
            // An explicit h3 is honoured as-is (the dialer only substitutes when
            // h3 is absent), so this is exactly what goes on the wire.
            this.stream.tls.alpn = ['h3'];
            // The fingerprint is deliberately left ALONE here rather than
            // cleared. uTLS rewrites a TLS-over-TCP ClientHello and is never
            // consulted on a QUIC path, so it is inert on h3. But it is inert
            // on tuic and hysteria too and the panel does not clear it for them
            // either, and clearing it would throw away a deliberate choice the
            // moment someone toggled to UDP and back.
        } else {
            this.stream.network = 'tcp';
            this.stream.tls.alpn = ['h2'];
            // Only when nothing is set, so firefox or safari survives a toggle.
            //
            // The whole reason h2 stays on the ordinary TLS stream instead of
            // going through naive's own transport is to pick up Xray's uTLS. Left
            // empty, the ClientHello is Go's, which is the single most
            // recognisable thing naive exists to avoid: the outbound would work
            // perfectly and be trivially classifiable.
            if (!this.stream.tls.fingerprint) {
                this.stream.tls.fingerprint = UTLS_FINGERPRINT.UTLS_CHROME;
            }
        }
    }

    canEnableTls() {
        if (this.protocol === Protocols.Hysteria) return true;
        // TUIC is QUIC, so TLS is not a choice the operator makes, it is the only
        // way the protocol exists. The section is offered anyway because it is
        // where SNI and ALPN live, and ALPN in particular is not optional here:
        // the server is pinned to h3 and a client that negotiates anything else
        // fails the handshake with "tls: no application protocol", which names
        // neither side. See the ALPN field in the tuic block of form/outbound.
        if (this.protocol === Protocols.Tuic) return true;
        // naive for the same reason on the h3 side, where the stream network is
        // "naive" and would fall out of the transport list below. Its h2 side
        // needs the section just as much: the client reads the negotiated ALPN
        // and refuses anything that is not h2, so ALPN has to be settable.
        if (this.protocol === Protocols.Naive) return true;
        if (![Protocols.VMess, Protocols.VLESS, Protocols.Trojan, Protocols.Shadowsocks, Protocols.AnyTLS].includes(this.protocol)) return false;
        return ["tcp", "ws", "http", "grpc", "httpupgrade", "xhttp"].includes(this.stream.network);
    }

    //this is used for xtls-rprx-vision
    canEnableTlsFlow() {
        if ((this.stream.security != 'none') && (this.stream.network === "tcp")) {
            return this.protocol === Protocols.VLESS;
        }
        return false;
    }

    // Vision seed applies only when vision flow is selected
    canEnableVisionSeed() {
        if (!this.canEnableTlsFlow()) return false;
        const flow = this.settings?.flow;
        return flow === TLS_FLOW_CONTROL.VISION || flow === TLS_FLOW_CONTROL.VISION_UDP443;
    }

    canEnableReality() {
        // AnyTLS carries no transport of its own: it is a session-multiplexing
        // layer that runs over whatever stream Xray hands it, so REALITY works
        // for it on exactly the networks it works for VLESS and Trojan, and for
        // the same reason. TUIC is deliberately absent: it IS its transport.
        if (![Protocols.VLESS, Protocols.Trojan, Protocols.AnyTLS].includes(this.protocol)) return false;
        return ["tcp", "http", "grpc", "xhttp"].includes(this.stream.network);
    }

    // Whether this outbound gets a streamSettings object at all. Not cosmetic:
    // toJson() emits streamSettings only when this is true, so a protocol whose
    // core-side dialer READS streamSettings has to be listed here or it dials
    // with none.
    //
    // TUIC is listed for exactly that reason. Its dialer takes the TLS config off
    // streamSettings and rejects any stream whose network is not "tuic", the same
    // way the hysteria transport does, so both keys have to reach the config.
    //
    // NAIVE is listed for it too, and it is the one that is easy to get wrong.
    // naive looks self-contained (it speaks its own HTTP and does its own
    // padding), but it does NOT bring its own TLS: the h2 path writes CONNECT
    // onto whatever stream Xray dials, and the h3 path goes through the "naive"
    // transport, which reads TLS off streamSettings and refuses to run without
    // it. Leaving naive out here emits no streamSettings at all, and the outbound
    // then either speaks plaintext h2 or fails h3 outright. See setNaiveNetwork.
    canEnableStream() {
        return [
            Protocols.VMess,
            Protocols.VLESS,
            Protocols.Trojan,
            Protocols.Shadowsocks,
            Protocols.Hysteria,
            Protocols.AnyTLS,
            Protocols.Tuic,
            Protocols.Naive,
        ].includes(this.protocol);
    }

    canEnableMux() {
        // Disable Mux if flow is set
        if (this.settings.flow && this.settings.flow !== '') {
            this.mux.enabled = false;
            return false;
        }

        // Disable Mux if network is xhttp
        if (this.stream.network === 'xhttp') {
            this.mux.enabled = false;
            return false;
        }

        // Allow Mux only for these protocols
        //
        // anytls, tuic and naive are deliberately absent, and not because Mux
        // would merely be redundant on top of protocols that already multiplex.
        // Mux takes the outbound over BEFORE the protocol handler is reached and
        // dials the marker host v1.mux.cool:9527, which nothing resolves; the
        // dial error is logged at Info while the panel runs at warning, so the
        // config is valid, Xray boots, and 100% of that tag's traffic dead-ends
        // with no log line anywhere. Being absent here also strips a `mux` object
        // pasted into the JSON tab on serialise (see toJson), which is the only
        // other way one can get onto these.
        return [
            Protocols.VMess,
            Protocols.VLESS,
            Protocols.Trojan,
            Protocols.Shadowsocks,
            Protocols.HTTP,
            Protocols.Socks
        ].includes(this.protocol);
    }

    // Whether the settings object nests its address/port under a `servers` array.
    // anytls/tuic/naive do NOT: all three are flat, so they stay out of this list
    // and their address/port come from hasAddressPort below.
    hasServers() {
        return [Protocols.Trojan, Protocols.Shadowsocks, Protocols.Socks, Protocols.HTTP].includes(this.protocol);
    }

    hasAddressPort() {
        return [
            Protocols.DNS,
            Protocols.VMess,
            Protocols.VLESS,
            Protocols.Trojan,
            Protocols.Shadowsocks,
            Protocols.Socks,
            Protocols.HTTP,
            Protocols.Hysteria,
            Protocols.AnyTLS,
            Protocols.Tuic,
            Protocols.Naive
        ].includes(this.protocol);
    }

    hasUsername() {
        return [Protocols.Socks, Protocols.HTTP].includes(this.protocol);
    }

    static fromJson(json = {}) {
        const out = Outbound.fromJsonInner(json);
        // A naive outbound with NO streamSettings has to derive one, and it can
        // only be derived after the settings are parsed because it is
        // settings.network that decides it. There is no operator intent to
        // preserve in this branch, which is why it is safe to write here and
        // nowhere else: a config that DID carry a stream keeps exactly the one
        // it came with, even a mismatched one, so the JSON tab keeps showing
        // what is really on disk.
        if (out.protocol === Protocols.Naive && !json.streamSettings) {
            out.setNaiveNetwork(out.settings.network);
        }
        return out;
    }

    static fromJsonInner(json = {}) {
        return new Outbound(
            json.tag,
            json.protocol,
            Outbound.Settings.fromJson(json.protocol, json.settings),
            // An outbound with NO streamSettings at all gets the protocol's
            // default rather than a bare one. Identical for every protocol that
            // existed before (defaultStreamFor returns exactly `new
            // StreamSettings()` for all of them), and it is what stops a TUIC
            // outbound pasted into the JSON tab without a streamSettings block
            // from landing on network "tcp", which its dialer refuses outright.
            json.streamSettings
                ? StreamSettings.fromJson(json.streamSettings)
                : Outbound.defaultStreamFor(json.protocol),
            json.sendThrough,
            Mux.fromJson(json.mux),
        )
    }

    // What Xray is told this outbound is. ssh and vpn are panel-side tunnels, not
    // Xray protocols, so what the core gets is the outbound that fronts them: the
    // local socks proxy the panel serves for an SSH tunnel, and a freedom outbound
    // pinned to the netdev for a VPN one. Rewritten in the model rather than in
    // the caller so every path that serialises an outbound (Add Outbound, the JSON
    // tab, the config write) agrees.
    xrayProtocol() {
        if (this.protocol === Protocols.SSH) return Protocols.Socks;
        if (isVpnProtocol(this.protocol)) return Protocols.Freedom;
        return this.protocol;
    }

    // Moves a tunnel outbound to another kind. Not the protocol setter, which
    // would build a fresh settings object and with it a fresh storedKind: an
    // edit has to keep knowing which kind is STORED, because that is what warns
    // the operator their tunnel is being replaced rather than adjusted. The
    // stream settings survive too, so the sockopts stay put across the switch.
    setVpnKind(kind) {
        this._protocol = vpnProtocolFor(kind);
        this.settings.setKind(kind);
    }

    toJson() {
        var stream;
        if (this.canEnableStream()) {
            stream = this.stream.toJson();
        } else {
            if (this.stream?.sockopt)
                stream = { sockopt: this.stream.sockopt.toJson() };
        }
        let settingsOut = this.settings instanceof CommonClass ? this.settings.toJson() : this.settings;
        if (isVpnProtocol(this.protocol)) {
            // Emit what applyVpnOutboundsWith synthesises server-side, so the
            // JSON tab shows the outbound Xray will really get: a freedom one
            // carrying the operator's own sockopts plus the SO_BINDTODEVICE pin.
            //
            // The interface is the one sockopt the operator does not get to set.
            // The driver decides it when it raises the tunnel and
            // /vpnoutbound/save hands it back, which is why it is read off the
            // settings and overwrites whatever the sockopt form holds.
            //
            // Without an interface there is deliberately NO interface key at
            // all. A freedom outbound bound to "" is not an error to Xray, it is
            // an unbound socket: every byte would leave through the host's own
            // default route while the row still looked like a working tunnel.
            const sockopt = this.stream?.sockopt ? this.stream.sockopt.toJson() : {};
            delete sockopt.interface;
            if (this.settings?.iface) sockopt.interface = this.settings.iface;
            stream = Object.keys(sockopt).length ? { sockopt: sockopt } : undefined;
        }
        return {
            protocol: this.xrayProtocol(),
            settings: settingsOut,
            // Only include tag, streamSettings, sendThrough, mux if present and not empty
            ...(this.tag ? { tag: this.tag } : {}),
            ...(stream ? { streamSettings: stream } : {}),
            ...(this.sendThrough ? { sendThrough: this.sendThrough } : {}),
            // canEnableMux(), not just the flag: the flag can be true on an
            // outbound whose protocol has no Mux form to turn it off with. The
            // JSON tab accepts a pasted {"mux":{"enabled":true}} on any protocol,
            // and switching the picker to another protocol keeps whatever mux the
            // previous one had.
            //
            // On a tunnel that is not a cosmetic problem. Mux takes the outbound
            // over before freedom is ever reached and dials its marker host
            // v1.mux.cool:9527, which nothing resolves; the dial error is logged
            // at Info while the panel runs at warning, so the config is valid,
            // Xray boots, and 100% of that outbound's traffic dead-ends with no
            // log line anywhere. The SSH outbound was bitten by exactly this.
            ...(this.mux?.enabled && this.canEnableMux() ? { mux: this.mux } : {}),
        };
    }

    static fromLink(link) {
        const data = link.split('://');
        if (data.length != 2) return null;
        switch (data[0].toLowerCase()) {
            case Protocols.VMess:
                return this.fromVmessLink(JSON.parse(Base64.decode(data[1])));
            case Protocols.VLESS:
            case Protocols.Trojan:
            case 'ss':
                return this.fromParamLink(link);
            case 'hysteria2':
            case Protocols.Hysteria:
                return this.fromHysteriaLink(link);
            // anytls goes through the generic parser and not a parser of its own
            // because its link IS a trojan link with a different scheme: the panel
            // that emits it fills the query string from streamShareParams, so it
            // carries type=, security=, and everything ws / grpc / xhttp / REALITY
            // need. A hand-written parser reading only sni and alpn would import
            // one of those onto a plain tcp stream, which connects to nothing and
            // looks like a correct row.
            case Protocols.AnyTLS:
                return this.fromParamLink(link);
            case Protocols.Tuic:
                return this.fromTuicLink(link);
            // naive has no scheme of its own: naiveproxy's own --proxy flag takes
            // the transport's scheme directly (https:// for h2, quic:// for h3),
            // and the panels that do emit a link prefix that with "naive+". Both
            // are accepted, and a bare naive:// alongside them, because that is
            // what an operator types when they are copying the protocol name.
            case Protocols.Naive:
            case 'naive+https':
            case 'naive+quic':
                return this.fromNaiveLink(link);
            default:
                return null;
        }
    }

    // The userinfo of a share link, decoded.
    //
    // URL keeps username and password percent-ENCODED (unlike searchParams,
    // which decodes), so a password containing @ : / or #, all of which have to
    // be escaped to survive the authority, comes back escaped and authenticates
    // as the wrong string. Returns null for a link the URL parser rejects, which
    // is how each caller reports "Wrong Link!" instead of throwing out of the
    // import handler.
    static parseShareLink(link) {
        let url;
        try {
            url = new URL(link);
        } catch (_) {
            return null;
        }
        if (!url.hostname) return null;
        const decode = s => {
            try { return decodeURIComponent(s); } catch (_) { return s; }
        };
        // A non-special scheme keeps IPv6 brackets in hostname. They belong in a
        // URL and not in a config field, where the address is a bare host.
        const host = url.hostname.replace(/^\[(.*)\]$/, '$1');
        let remark = decode(url.hash || '');
        remark = remark.length > 1 ? remark.substring(1) : '';
        return {
            url: url,
            address: host,
            port: url.port ? Number(url.port) : 443,
            user: decode(url.username || ''),
            pass: decode(url.password || ''),
            params: url.searchParams,
            remark: remark,
        };
    }

    // tuic://uuid:password@host:port?congestion_control=&udp_relay_mode=&alpn=&sni=#remark
    //
    // Not routed through fromParamLink the way anytls is: a TUIC link carries no
    // type= or security= because there is nothing to choose, and its parameters
    // are named for TUIC rather than for Xray's transport layer.
    //
    // Both halves of the userinfo are required. TUIC v5 authenticates with a UUID
    // AND a password, and a link carrying only one of them is not a TUIC link.
    static fromTuicLink(link) {
        const p = Outbound.parseShareLink(link);
        if (!p) return null;
        if (!p.user || !p.pass) return null;
        const stream = new StreamSettings('tuic', 'tls');
        const alpn = p.params.get('alpn');
        stream.tls = new TlsStreamSettings(
            p.params.get('sni') || p.address,
            // h3 when the link does not say, because the server is pinned to it
            // and an empty ALPN is a failed handshake here rather than a default.
            alpn ? alpn.split(',').map(a => a.trim()).filter(a => a) : ['h3'],
            // Never defaulted to 'none': that is not a uTLS fingerprint and Xray
            // rejects the whole config with "unknown fingerprint".
            p.params.get('fp') || '',
        );
        const settings = new Outbound.TuicSettings(
            p.address,
            p.port,
            p.user,
            p.pass,
            p.params.get('congestion_control') || p.params.get('congestionControl') || 'cubic',
            p.params.get('udp_relay_mode') || p.params.get('udpRelayMode') || 'native',
            ['1', 'true'].includes(String(p.params.get('zero_rtt_handshake') || '').toLowerCase()),
        );
        return new Outbound(p.remark || ('out-tuic-' + p.port), Protocols.Tuic, settings, stream);
    }

    // naive://user:pass@host:port#remark, and the naive+https / naive+quic forms
    // that carry the transport in the scheme. https and a bare naive mean h2 over
    // TCP; quic means h3.
    static fromNaiveLink(link) {
        const p = Outbound.parseShareLink(link);
        if (!p) return null;
        if (!p.user) return null;
        const scheme = link.split('://')[0].toLowerCase();
        // The link's user half goes into EMAIL with the username left empty, and that is
        // not a guess about which of the two it was: a link carries the credential the
        // server matched, never both, so nothing here can tell them apart. Email is the
        // slot that reproduces it on the wire either way, because the core falls back to
        // the email when there is no username.
        const settings = new Outbound.NaiveSettings(p.address, p.port, p.user, '', p.pass);
        const out = new Outbound(
            p.remark || ('out-naive-' + p.port),
            Protocols.Naive,
            settings,
            Outbound.defaultStreamFor(Protocols.Naive),
        );
        // Through the setter, not by assigning settings.network: the stream has
        // to move with it or an imported quic link dials h3 over a tcp stream.
        out.setNaiveNetwork(scheme === 'naive+quic' ? 'udp' : 'tcp');
        out.stream.tls.serverName = p.params.get('sni') || p.address;
        return out;
    }

    // Merge a share link's `extra` object onto an xHTTPStreamSettings instance.
    // The keys the model owns structurally (mode, xmux, sc*, xPaddingBytes,
    // downloadSettings...) are routed to their fields; every OTHER key is kept
    // verbatim in xh.extra so any xhttp object shape round-trips losslessly.
    //
    // collectUnknown MUST be false when `extra` is actually the whole vmess/link
    // JSON (the fromVmessLink fallback) — otherwise link-level keys (add, port,
    // id, net, tls, sni...) would leak into the xhttp settings. Pass true only
    // when `extra` is a genuine xhttp `extra=` object.
    static applyXhttpExtra(xh, extra, collectUnknown = false) {
        if (!extra || typeof extra !== 'object') return;
        // Don't let a missing/empty extra.mode clobber a mode already set from
        // the top-level `mode=` query param.
        if (!xh.mode && typeof extra.mode === 'string' && extra.mode) xh.mode = extra.mode;
        if (!xh.path && typeof extra.path === 'string' && extra.path) xh.path = extra.path;
        if (!xh.host && typeof extra.host === 'string' && extra.host) xh.host = extra.host;
        if (typeof extra.noGRPCHeader === 'boolean') xh.noGRPCHeader = extra.noGRPCHeader;
        if (extra.scMaxEachPostBytes !== undefined && extra.scMaxEachPostBytes !== '') xh.scMaxEachPostBytes = extra.scMaxEachPostBytes;
        if (extra.scMinPostsIntervalMs !== undefined && extra.scMinPostsIntervalMs !== '') xh.scMinPostsIntervalMs = extra.scMinPostsIntervalMs;
        if (typeof extra.xPaddingBytes === 'string' && extra.xPaddingBytes) xh.xPaddingBytes = extra.xPaddingBytes;
        // Merge, don't replace, so the six default xmux keys the form binds to survive.
        if (extra.xmux && typeof extra.xmux === 'object') xh.xmux = Object.assign({}, xh.xmux, extra.xmux);
        // Nested full stream-settings object, passed through verbatim.
        if (extra.downloadSettings !== undefined && extra.downloadSettings !== null) xh.downloadSettings = extra.downloadSettings;
        if (!collectUnknown) return;
        // Preserve everything the fields above don't own (headers, noSSEHeader,
        // scMaxBufferedPosts, xPadding* obfs keys, uplink*/session*/seq*, future keys).
        if (!xh.extra || typeof xh.extra !== 'object') xh.extra = {};
        Object.keys(extra).forEach(k => {
            if (!xHTTPStreamSettings.STRUCTURED_KEYS.has(k)) xh.extra[k] = extra[k];
        });
    }

    static fromVmessLink(json = {}) {
        let stream = new StreamSettings(json.net, json.tls);

        let network = json.net;
        if (network === 'tcp') {
            stream.tcp = new TcpStreamSettings(
                json.type,
                json.host ?? '',
                json.path ?? '');
        } else if (network === 'kcp') {
            stream.kcp = new KcpStreamSettings();
            stream.type = json.type;
            stream.seed = json.path;
            const mtu = Number(json.mtu);
            if (Number.isFinite(mtu) && mtu > 0) stream.kcp.mtu = mtu;
            const tti = Number(json.tti);
            if (Number.isFinite(tti) && tti > 0) stream.kcp.tti = tti;
        } else if (network === 'ws') {
            stream.ws = new WsStreamSettings(json.path, json.host);
        } else if (network === 'grpc') {
            stream.grpc = new GrpcStreamSettings(json.path, json.authority, json.type == 'multi');
        } else if (network === 'httpupgrade') {
            stream.httpupgrade = new HttpUpgradeStreamSettings(json.path, json.host);
        } else if (network === 'xhttp') {
            // xHTTPStreamSettings positional args are (path, host, headers, ..., mode);
            // passing `json.mode` as the 3rd argument used to land in the `headers`
            // slot, dropping the mode on the floor. Build the object and set mode
            // explicitly to avoid that.
            const xh = new xHTTPStreamSettings(json.path, json.host);
            if (json.mode) xh.mode = json.mode;
            // The extra xhttp fields (scMaxEachPostBytes, xPaddingBytes and a
            // nested downloadSettings) may arrive either as an `extra` object or
            // directly on the vmess json. Merge whichever is present.
            let extra = json.extra;
            if (typeof extra === 'string') { try { extra = JSON.parse(extra); } catch (_) { extra = undefined; } }
            if (extra && typeof extra === 'object') {
                // Genuine xhttp `extra` object: preserve every key verbatim.
                Outbound.applyXhttpExtra(xh, extra, true);
            } else {
                // Fallback: fields sit directly on the vmess json. Route the
                // known ones only — do NOT collect unknowns (would pull in the
                // link-level keys add/port/id/net/tls...).
                Outbound.applyXhttpExtra(xh, json, false);
            }
            stream.xhttp = xh;
        }

        if (json.tls && json.tls == 'tls') {
            stream.tls = new TlsStreamSettings(
                json.sni,
                json.alpn ? json.alpn.split(',') : [],
                json.fp);
        }

        const port = json.port * 1;

        return new Outbound(json.ps, Protocols.VMess, new Outbound.VmessSettings(json.add, port, json.id, json.scy), stream);
    }

    static fromParamLink(link) {
        const url = new URL(link);
        let type = url.searchParams.get('type') ?? 'tcp';
        let security = url.searchParams.get('security') ?? 'none';
        let stream = new StreamSettings(type, security);

        let headerType = url.searchParams.get('headerType') ?? undefined;
        let host = url.searchParams.get('host') ?? undefined;
        let path = url.searchParams.get('path') ?? undefined;
        let seed = url.searchParams.get('seed') ?? path ?? undefined;
        let mode = url.searchParams.get('mode') ?? undefined;

        if (type === 'tcp' || type === 'none') {
            stream.tcp = new TcpStreamSettings(headerType ?? 'none', host, path);
        } else if (type === 'kcp') {
            stream.kcp = new KcpStreamSettings();
            stream.kcp.type = headerType ?? 'none';
            stream.kcp.seed = seed;
            const mtu = Number(url.searchParams.get('mtu'));
            if (Number.isFinite(mtu) && mtu > 0) stream.kcp.mtu = mtu;
            const tti = Number(url.searchParams.get('tti'));
            if (Number.isFinite(tti) && tti > 0) stream.kcp.tti = tti;
        } else if (type === 'ws') {
            stream.ws = new WsStreamSettings(path, host);
        } else if (type === 'grpc') {
            stream.grpc = new GrpcStreamSettings(
                url.searchParams.get('serviceName') ?? '',
                url.searchParams.get('authority') ?? '',
                url.searchParams.get('mode') == 'multi');
        } else if (type === 'httpupgrade') {
            stream.httpupgrade = new HttpUpgradeStreamSettings(path, host);
        } else if (type === 'xhttp') {
            // Same positional bug as in the VMess-JSON branch above:
            // passing `mode` as the 3rd positional arg put it into the
            // `headers` slot. Build explicitly instead.
            const xh = new xHTTPStreamSettings(path, host);
            if (mode) xh.mode = mode;
            const xpb = url.searchParams.get('x_padding_bytes');
            if (xpb) xh.xPaddingBytes = xpb;
            const extraRaw = url.searchParams.get('extra');
            if (extraRaw) {
                try {
                    Outbound.applyXhttpExtra(xh, JSON.parse(extraRaw), true);
                } catch (_) { /* ignore malformed extra */ }
            }
            stream.xhttp = xh;
        }

        if (security == 'tls') {
            // No default 'none' — 'none' is NOT a valid uTLS fingerprint and
            // Xray rejects it ("unknown fingerprint"). Empty = no uTLS.
            let fp = url.searchParams.get('fp') ?? '';
            let alpn = url.searchParams.get('alpn');
            let sni = url.searchParams.get('sni') ?? '';
            let ech = url.searchParams.get('ech') ?? '';
            stream.tls = new TlsStreamSettings(sni, alpn ? alpn.split(',') : [], fp, ech);
        }

        if (security == 'reality') {
            let pbk = url.searchParams.get('pbk');
            let fp = url.searchParams.get('fp');
            let sni = url.searchParams.get('sni') ?? '';
            let sid = url.searchParams.get('sid') ?? '';
            let spx = url.searchParams.get('spx') ?? '';
            let pqv = url.searchParams.get('pqv') ?? '';
            stream.reality = new RealityStreamSettings(pbk, fp, sni, sid, spx, pqv);
        }

        const regex = /([^@]+):\/\/([^@]+)@(.+):(\d+)(.*)$/;
        const match = link.match(regex);

        if (!match) return null;
        let [, protocol, userData, address, port,] = match;
        port *= 1;
        if (protocol == 'ss') {
            protocol = 'shadowsocks';
            userData = atob(userData).split(':');
        }
        var settings;
        switch (protocol) {
            case Protocols.VLESS:
                settings = new Outbound.VLESSSettings(address, port, userData, url.searchParams.get('flow') ?? '', url.searchParams.get('encryption') ?? 'none');
                break;
            case Protocols.Trojan:
                settings = new Outbound.TrojanSettings(address, port, userData);
                break;
            case Protocols.AnyTLS:
                // Decoded, unlike the two above. `userData` here is the raw
                // authority slice, and the generator that writes an anytls link
                // percent-encodes the password into it, so a password holding an
                // @ : / or # arrives as %40 %3A %2F %23 and would be stored, and
                // then sent, as those literal characters.
                settings = new Outbound.AnyTLSSettings(address, port, decodeURIComponent(userData));
                break;
            case Protocols.Shadowsocks:
                let method = userData.splice(0, 1)[0];
                settings = new Outbound.ShadowsocksSettings(address, port, userData.join(":"), method, true);
                break;
            default:
                return null;
        }
        let remark = decodeURIComponent(url.hash);
        // Remove '#' from url.hash
        remark = remark.length > 0 ? remark.substring(1) : 'out-' + protocol + '-' + port;
        return new Outbound(remark, protocol, settings, stream);
    }

    static fromHysteriaLink(link) {
        // Parse hysteria2://password@address:port[?param1=value1&param2=value2...][#remarks]
        const regex = /^hysteria2?:\/\/([^@]+)@([^:?#]+):(\d+)([^#]*)(#.*)?$/;
        const match = link.match(regex);

        if (!match) return null;

        let [, password, address, port, params, hash] = match;
        port = parseInt(port);

        // Parse URL parameters if present
        let urlParams = new URLSearchParams(params);

        // Create stream settings with hysteria network
        let stream = new StreamSettings('hysteria', 'none');

        // Set hysteria stream settings
        stream.hysteria.auth = password;
        stream.hysteria.congestion = urlParams.get('congestion') ?? '';
        stream.hysteria.up = urlParams.get('up') ?? '0';
        stream.hysteria.down = urlParams.get('down') ?? '0';
        stream.hysteria.udphopPort = urlParams.get('udphopPort') ?? '';
        // Support both old single interval and new min/max range
        if (urlParams.has('udphopInterval')) {
            const interval = parseInt(urlParams.get('udphopInterval'));
            stream.hysteria.udphopIntervalMin = interval;
            stream.hysteria.udphopIntervalMax = interval;
        } else {
            stream.hysteria.udphopIntervalMin = parseInt(urlParams.get('udphopIntervalMin') ?? '30');
            stream.hysteria.udphopIntervalMax = parseInt(urlParams.get('udphopIntervalMax') ?? '30');
        }

        // Optional QUIC parameters
        if (urlParams.has('initStreamReceiveWindow')) {
            stream.hysteria.initStreamReceiveWindow = parseInt(urlParams.get('initStreamReceiveWindow'));
        }
        if (urlParams.has('maxStreamReceiveWindow')) {
            stream.hysteria.maxStreamReceiveWindow = parseInt(urlParams.get('maxStreamReceiveWindow'));
        }
        if (urlParams.has('initConnectionReceiveWindow')) {
            stream.hysteria.initConnectionReceiveWindow = parseInt(urlParams.get('initConnectionReceiveWindow'));
        }
        if (urlParams.has('maxConnectionReceiveWindow')) {
            stream.hysteria.maxConnectionReceiveWindow = parseInt(urlParams.get('maxConnectionReceiveWindow'));
        }
        if (urlParams.has('maxIdleTimeout')) {
            stream.hysteria.maxIdleTimeout = parseInt(urlParams.get('maxIdleTimeout'));
        }
        if (urlParams.has('keepAlivePeriod')) {
            stream.hysteria.keepAlivePeriod = parseInt(urlParams.get('keepAlivePeriod'));
        }
        if (urlParams.has('disablePathMTUDiscovery')) {
            stream.hysteria.disablePathMTUDiscovery = urlParams.get('disablePathMTUDiscovery') === 'true';
        }

        // Create settings
        let settings = new Outbound.HysteriaSettings(address, port, 2);

        // Extract remark from hash
        let remark = hash ? decodeURIComponent(hash.substring(1)) : `out-hysteria-${port}`;

        return new Outbound(remark, Protocols.Hysteria, settings, stream);
    }
}

Outbound.Settings = class extends CommonClass {
    constructor(protocol) {
        super();
        this.protocol = protocol;
    }

    static getSettings(protocol) {
        // A tunnel carries its kind in the protocol value, so picking "L2TP" in
        // the outbound form is what builds the L2TP field set. Answered before
        // the switch because there are nine of these and the kind is the only
        // thing that differs between them.
        if (isVpnProtocol(protocol)) return new Outbound.VpnSettings(vpnKindOf(protocol));
        switch (protocol) {
            case Protocols.Freedom: return new Outbound.FreedomSettings();
            case Protocols.Blackhole: return new Outbound.BlackholeSettings();
            case Protocols.DNS: return new Outbound.DNSSettings();
            case Protocols.VMess: return new Outbound.VmessSettings();
            case Protocols.VLESS: return new Outbound.VLESSSettings();
            case Protocols.Trojan: return new Outbound.TrojanSettings();
            case Protocols.Shadowsocks: return new Outbound.ShadowsocksSettings();
            case Protocols.Socks: return new Outbound.SocksSettings();
            case Protocols.HTTP: return new Outbound.HttpSettings();
            case Protocols.Wireguard: return new Outbound.WireguardSettings();
            case Protocols.Hysteria: return new Outbound.HysteriaSettings();
            case Protocols.AnyTLS: return new Outbound.AnyTLSSettings();
            case Protocols.Tuic: return new Outbound.TuicSettings();
            case Protocols.Naive: return new Outbound.NaiveSettings();
            case Protocols.SSH: return new Outbound.SshSettings();
            // Reached only for a protocol nobody added a case for, and the null
            // is load-bearing downstream in the worst way: canEnableMux() reads
            // this.settings.flow unguarded, so a missing case does not render an
            // empty form, it throws inside the render and leaves the whole panel
            // blank behind v-cloak with nothing in the console pointing here.
            default: return null;
        }
    }

    static fromJson(protocol, json) {
        if (isVpnProtocol(protocol)) return Outbound.VpnSettings.fromJson(json, vpnKindOf(protocol));
        switch (protocol) {
            case Protocols.Freedom: return Outbound.FreedomSettings.fromJson(json);
            case Protocols.Blackhole: return Outbound.BlackholeSettings.fromJson(json);
            case Protocols.DNS: return Outbound.DNSSettings.fromJson(json);
            case Protocols.VMess: return Outbound.VmessSettings.fromJson(json);
            case Protocols.VLESS: return Outbound.VLESSSettings.fromJson(json);
            case Protocols.Trojan: return Outbound.TrojanSettings.fromJson(json);
            case Protocols.Shadowsocks: return Outbound.ShadowsocksSettings.fromJson(json);
            case Protocols.Socks: return Outbound.SocksSettings.fromJson(json);
            case Protocols.HTTP: return Outbound.HttpSettings.fromJson(json);
            case Protocols.Wireguard: return Outbound.WireguardSettings.fromJson(json);
            case Protocols.Hysteria: return Outbound.HysteriaSettings.fromJson(json);
            case Protocols.AnyTLS: return Outbound.AnyTLSSettings.fromJson(json);
            case Protocols.Tuic: return Outbound.TuicSettings.fromJson(json);
            case Protocols.Naive: return Outbound.NaiveSettings.fromJson(json);
            case Protocols.SSH: return Outbound.SshSettings.fromJson(json);
            // Same null, same consequence as in getSettings above: an outbound
            // read back from the config with no case here reaches the form with
            // settings === null and blanks the page on the first render.
            default: return null;
        }
    }

    toJson() {
        return {};
    }
};
Outbound.FreedomSettings = class extends CommonClass {
    constructor(
        domainStrategy = '',
        redirect = '',
        fragment = {},
        noises = [],
        ipsBlocked = [],
    ) {
        super();
        this.domainStrategy = domainStrategy;
        this.redirect = redirect;
        this.fragment = fragment || {};
        this.noises = Array.isArray(noises) ? noises : [];
        this.ipsBlocked = Array.isArray(ipsBlocked) ? ipsBlocked : [];
    }

    addNoise() {
        this.noises.push(new Outbound.FreedomSettings.Noise());
    }

    delNoise(index) {
        this.noises.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings(
            json.domainStrategy,
            json.redirect,
            json.fragment ? Outbound.FreedomSettings.Fragment.fromJson(json.fragment) : {},
            json.noises ? json.noises.map(noise => Outbound.FreedomSettings.Noise.fromJson(noise)) : [],
            json.ipsBlocked || [],
        );
    }

    toJson() {
        return {
            domainStrategy: ObjectUtil.isEmpty(this.domainStrategy) ? undefined : this.domainStrategy,
            redirect: ObjectUtil.isEmpty(this.redirect) ? undefined : this.redirect,
            fragment: Object.keys(this.fragment).length === 0 ? undefined : this.fragment,
            noises: this.noises.length === 0 ? undefined : Outbound.FreedomSettings.Noise.toJsonArray(this.noises),
            ipsBlocked: this.ipsBlocked.length === 0 ? undefined : this.ipsBlocked,
        };
    }
};

Outbound.FreedomSettings.Fragment = class extends CommonClass {
    constructor(
        packets = '1-3',
        length = '',
        interval = '',
        maxSplit = ''
    ) {
        super();
        this.packets = packets;
        this.length = length;
        this.interval = interval;
        this.maxSplit = maxSplit;
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings.Fragment(
            json.packets,
            json.length,
            json.interval,
            json.maxSplit
        );
    }
};

Outbound.FreedomSettings.Noise = class extends CommonClass {
    constructor(
        type = 'rand',
        packet = '10-20',
        delay = '10-16',
        applyTo = 'ip'
    ) {
        super();
        this.type = type;
        this.packet = packet;
        this.delay = delay;
        this.applyTo = applyTo;
    }

    static fromJson(json = {}) {
        return new Outbound.FreedomSettings.Noise(
            json.type,
            json.packet,
            json.delay,
            json.applyTo
        );
    }

    toJson() {
        return {
            type: this.type,
            packet: this.packet,
            delay: this.delay,
            applyTo: this.applyTo
        };
    }
};

Outbound.BlackholeSettings = class extends CommonClass {
    constructor(type) {
        super();
        this.type = type;
    }

    static fromJson(json = {}) {
        return new Outbound.BlackholeSettings(
            json.response ? json.response.type : undefined,
        );
    }

    toJson() {
        return {
            response: ObjectUtil.isEmpty(this.type) ? undefined : { type: this.type },
        };
    }
};

Outbound.DNSRule = class extends CommonClass {
    constructor(action = 'direct', qtype = '', domain = '') {
        super();
        this.action = action;
        this.qtype = qtype;
        this.domain = domain;
    }

    static fromJson(json = {}) {
        return new Outbound.DNSRule(
            json.action,
            normalizeDNSRuleField(json.qtype),
            normalizeDNSRuleField(json.domain),
        );
    }

    toJson() {
        const rule = {
            action: normalizeDNSRuleAction(this.action),
        };

        const qtype = normalizeDNSRuleField(this.qtype);
        if (!ObjectUtil.isEmpty(qtype)) {
            if (/^\d+$/.test(qtype)) {
                rule.qtype = Number(qtype);
            } else {
                rule.qtype = qtype;
            }
        }

        const domains = normalizeDNSRuleField(this.domain)
            .split(',')
            .map(d => d.trim())
            .filter(d => d.length > 0);
        if (domains.length > 0) {
            rule.domain = domains;
        }

        return rule;
    }
};

Outbound.DNSSettings = class extends CommonClass {
    constructor(
        network = 'udp',
        address = '',
        port = 53,
        rules = []
    ) {
        super();
        this.network = network;
        this.address = address;
        this.port = port;
        this.rules = Array.isArray(rules) ? rules.map(rule => rule instanceof Outbound.DNSRule ? rule : Outbound.DNSRule.fromJson(rule)) : [];
    }

    addRule(action = 'direct') {
        this.rules.push(new Outbound.DNSRule(action));
    }

    delRule(index) {
        this.rules.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Outbound.DNSSettings(
            json.network,
            json.address,
            json.port,
            getDNSRulesFromJson(json),
        );
    }

    toJson() {
        const json = {
            network: this.network,
            address: this.address,
            port: this.port,
        };

        if (this.rules.length > 0) {
            json.rules = Outbound.DNSRule.toJsonArray(this.rules);
        }

        return json;
    }
};
Outbound.VmessSettings = class extends CommonClass {
    constructor(address, port, id, security) {
        super();
        this.address = address;
        this.port = port;
        this.id = id;
        this.security = security;
    }

    static fromJson(json = {}) {
        if (!ObjectUtil.isArrEmpty(json.vnext)) {
            const v = json.vnext[0] || {};
            const u = ObjectUtil.isArrEmpty(v.users) ? {} : v.users[0];
            return new Outbound.VmessSettings(
                v.address,
                v.port,
                u.id,
                u.security,
            );
        }
    }

    toJson() {
        return {
            vnext: [{
                address: this.address,
                port: this.port,
                users: [{
                    id: this.id,
                    security: this.security
                }]
            }]
        };
    }
};
Outbound.VLESSSettings = class extends CommonClass {
    constructor(address, port, id, flow, encryption, testpre = 0, testseed = [900, 500, 900, 256]) {
        super();
        this.address = address;
        this.port = port;
        this.id = id;
        this.flow = flow;
        this.encryption = encryption;
        this.testpre = testpre;
        this.testseed = testseed;
    }

    static fromJson(json = {}) {
        if (ObjectUtil.isEmpty(json.address) || ObjectUtil.isEmpty(json.port)) return new Outbound.VLESSSettings();
        return new Outbound.VLESSSettings(
            json.address,
            json.port,
            json.id,
            json.flow,
            json.encryption,
            json.testpre || 0,
            json.testseed && json.testseed.length >= 4 ? json.testseed : [900, 500, 900, 256]
        );
    }

    toJson() {
        const result = {
            address: this.address,
            port: this.port,
            id: this.id,
            flow: this.flow,
            encryption: this.encryption,
        };
        // Only include Vision settings when flow is set
        if (this.flow && this.flow !== '') {
            if (this.testpre > 0) {
                result.testpre = this.testpre;
            }
            if (this.testseed && this.testseed.length >= 4) {
                result.testseed = this.testseed;
            }
        }
        return result;
    }
};
Outbound.TrojanSettings = class extends CommonClass {
    constructor(address, port, password) {
        super();
        this.address = address;
        this.port = port;
        this.password = password;
    }

    static fromJson(json = {}) {
        if (ObjectUtil.isArrEmpty(json.servers)) return new Outbound.TrojanSettings();
        return new Outbound.TrojanSettings(
            json.servers[0].address,
            json.servers[0].port,
            json.servers[0].password,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                password: this.password,
            }],
        };
    }
};

// AnyTLS, TUIC and NaiveProxy all take a FLAT settings object: address and port
// sit at the top level, not inside a `servers` array. That is what the core's
// client configs read, so it is what these emit.
//
// They still read a `servers` array back, through firstServerOf. Not for the
// panel's own output, which never produces one, but because the JSON tab accepts
// anything and TUIC in particular has a documented servers[] form in the upstream
// the port comes from, so an operator pasting one is a normal thing to happen.
// ObjectUtil.isArrEmpty is the wrong guard for that and always has been: it
// answers "is this an EMPTY array", so isArrEmpty(undefined) is FALSE and the
// guard reads straight through to servers[0] on the flat object that has no
// servers at all. The throw lands inside outModal.show() AFTER it has set
// visible, so Edit on such a row opens the dialog holding the PREVIOUSLY edited
// outbound with OK live, and confirming overwrites the real row.
Outbound.AnyTLSSettings = class extends CommonClass {
    constructor(
        address = '',
        port = 443,
        password = '',
        // Blank, not zero, and blank is what gets sent. See optionalNumber: the
        // core treats 0 as "use my default", so a prefilled 0 would claim the
        // operator chose something and behave as though they had not.
        idleSessionCheckInterval = null,
        idleSessionTimeout = null,
        minIdleSession = null,
        // Opens a fresh session per connection instead of reusing an idle one.
        // A boolean and not a blank-means-default number: false IS the default,
        // and there is nothing for the core to fill in.
        disableReuse = false,
    ) {
        super();
        this.address = address;
        this.port = port;
        this.password = password;
        this.idleSessionCheckInterval = idleSessionCheckInterval;
        this.idleSessionTimeout = idleSessionTimeout;
        this.minIdleSession = minIdleSession;
        this.disableReuse = disableReuse;
    }

    static fromJson(json = {}) {
        const server = firstServerOf(json)[0];
        return new Outbound.AnyTLSSettings(
            json.address ?? server.address ?? '',
            json.port ?? server.port ?? 443,
            json.password ?? server.password ?? '',
            json.idleSessionCheckInterval ?? null,
            json.idleSessionTimeout ?? null,
            json.minIdleSession ?? null,
            !!json.disableReuse,
        );
    }

    toJson() {
        return {
            address: this.address,
            port: this.port,
            password: this.password,
            idleSessionCheckInterval: optionalNumber(this.idleSessionCheckInterval),
            idleSessionTimeout: optionalNumber(this.idleSessionTimeout),
            minIdleSession: optionalNumber(this.minIdleSession),
            disableReuse: !!this.disableReuse,
        };
    }
};

Outbound.TuicSettings = class extends CommonClass {
    constructor(
        address = '',
        port = 443,
        id = '',
        password = '',
        congestionControl = 'cubic',
        // "native" sends each UDP packet as its own QUIC datagram, "quic" wraps
        // the UDP session in a reliable stream. Both ends must agree; native is
        // the default on every TUIC client and is what this starts on.
        udpRelayMode = 'native',
        zeroRttHandshake = false,
        heartbeat = null,
    ) {
        super();
        this.address = address;
        this.port = port;
        this.id = id;
        this.password = password;
        this.congestionControl = congestionControl;
        this.udpRelayMode = udpRelayMode;
        this.zeroRttHandshake = zeroRttHandshake;
        this.heartbeat = heartbeat;
    }

    // No `alpn` here on purpose. TUIC's ALPN is ordinary TLS ALPN and it is read
    // off streamSettings.tlsSettings.alpn by the dialer, the same place SNI and
    // the fingerprint come from, so a second copy in the settings object would be
    // two sources for one value with nothing deciding which wins. The form binds
    // its ALPN field straight to the stream's, prefilled with h3, so the operator
    // still meets it in the TUIC block rather than having to know to go looking
    // for it under TLS. See Outbound.defaultStreamFor.
    static fromJson(json = {}) {
        const server = firstServerOf(json)[0];
        return new Outbound.TuicSettings(
            json.address ?? server.address ?? '',
            json.port ?? server.port ?? 443,
            json.id ?? server.id ?? '',
            json.password ?? server.password ?? '',
            json.congestionControl || 'cubic',
            // Accept either spelling on the way in. udpStream is the boolean the
            // upstream config struct declares; udpRelayMode is what every TUIC
            // client, share link and piece of documentation calls it.
            json.udpRelayMode || (json.udpStream ? 'quic' : 'native'),
            !!json.zeroRttHandshake,
            json.heartbeat ?? null,
        );
    }

    toJson() {
        const quicRelay = this.udpRelayMode === 'quic';
        return {
            address: this.address,
            port: this.port,
            id: this.id,
            password: this.password,
            congestionControl: this.congestionControl,
            // BOTH spellings, deliberately, and they are always consistent
            // because one is derived from the other. The core ignores JSON keys
            // it does not declare (nothing in it sets DisallowUnknownFields), so
            // the cost of the extra key is a line in the JSON tab. The cost of
            // guessing wrong is not symmetric: whichever name the core does not
            // read leaves udpStream at its zero value, which is native, so an
            // operator who deliberately selected quic would get native with the
            // form still showing quic and no error anywhere.
            udpRelayMode: this.udpRelayMode,
            udpStream: quicRelay,
            zeroRttHandshake: !!this.zeroRttHandshake,
            heartbeat: optionalNumber(this.heartbeat),
        };
    }
};

Outbound.NaiveSettings = class extends CommonClass {
    constructor(
        address = '',
        port = 443,
        // BOTH halves exist because the server's account has both. naive sends one
        // `Proxy-Authorization: Basic base64(user:password)`, and the user half is the
        // account's username when it has one and its EMAIL when it does not, which is
        // what every account created before naive had a username field uses.
        //
        // The core prefers username when both are set, so an operator dialling an older
        // server fills in Email and leaves Username blank, exactly as before this field
        // existed.
        //
        // Unlike the inbound's client list, which degrades a bad account with a warning,
        // this config ERRORS out of Build(): carrying neither, carrying no password, or
        // putting a colon in the username makes Xray refuse the WHOLE config, taking
        // every unrelated inbound on the box with it. Nothing panel-side stops that yet,
        // which is why the form says so.
        email = '',
        username = '',
        password = '',
        // Which HTTP the dialer speaks: tcp is h2 over TLS, udp is h3 over QUIC.
        // A single value, unlike the inbound's, which accepts "tcp,udp" because
        // it can listen for both at once. A dialer picks one, and the core reads
        // "udp" as h3 only when tcp is absent.
        //
        // NOT independent of streamSettings.network: the two have to be set
        // together or the outbound dials the wrong stack. See setNaiveNetwork.
        network = 'tcp',
    ) {
        super();
        this.address = address;
        this.port = port;
        this.email = email;
        this.username = username;
        this.password = password;
        this.network = network;
    }

    // Which wire a `network` string actually dials, by the core's own rules.
    //
    // A SECOND IMPLEMENTATION of ParseNetwork in
    // third_party/Xray-core/transport/internet/naive/config.go, and therefore a
    // thing that can drift, in the same way clientIdentityKey and
    // getClientIdentity can. Edit them together. That pair has a test parsing the
    // JS to hold it; this one deliberately does not, because the blast radius is
    // much smaller: the panel only ever WRITES a bare "tcp" or "udp", so a drift
    // here cannot produce a bad config, only a wrong reading of a hand-written
    // one.
    //
    // The drift is also one-sided. An unrecognised string falls back to h2, and
    // h2 is what every tcp spelling resolves to anyway, so a tcp spelling added
    // upstream and not mirrored here still lands on the right answer by accident.
    // Only a NEW UDP SPELLING can be read wrongly: it would dial h3 upstream and
    // resolve to tcp here, which is the "form shows a tcp stream for an HTTP/3
    // connection" bug this function exists to fix.
    //
    // ParseNetwork is more permissive than the two values this form offers: it
    // accepts h2/http2 alongside tcp and h3/http3/quic alongside udp, reads a
    // comma-separated list, and falls back to BOTH for an empty or unrecognised
    // string. A dialer can only open one wire, so h3 is chosen only when it is
    // asked for ALONE and everything else resolves to h2.
    //
    // Normalising on the way in matters for a hand-written config. "h3" and
    // "quic" dial h3, so leaving them unresolved would park the form on the TCP
    // option and show a tcp stream for an HTTP/3 connection. "tcp,udp" and a typo
    // are the other half: both dial h2, and neither matches an option in the
    // picker, so the select would render blank and the operator could not tell
    // which wire they were on.
    static resolveNetwork(network) {
        let tcp = false;
        let udp = false;
        String(network ?? '').toLowerCase().split(',').forEach(part => {
            switch (part.trim()) {
                case 'tcp': case 'h2': case 'http2': tcp = true; break;
                case 'udp': case 'h3': case 'http3': case 'quic': udp = true; break;
            }
        });
        return udp && !tcp ? 'udp' : 'tcp';
    }

    static fromJson(json = {}) {
        const server = firstServerOf(json)[0];
        return new Outbound.NaiveSettings(
            json.address ?? server.address ?? '',
            json.port ?? server.port ?? 443,
            // Read apart, not collapsed. They used to fold into one field because the
            // core had only `email`; a config carrying both would now lose the email,
            // and the email is what the server books the traffic against.
            json.email ?? server.email ?? '',
            json.username ?? server.username ?? '',
            json.password ?? server.password ?? '',
            Outbound.NaiveSettings.resolveNetwork(json.network),
        );
    }

    toJson() {
        return {
            address: this.address,
            port: this.port,
            email: this.email,
            username: this.username,
            password: this.password,
            network: this.network,
        };
    }
};

Outbound.ShadowsocksSettings = class extends CommonClass {
    constructor(address, port, password, method, uot, UoTVersion) {
        super();
        this.address = address;
        this.port = port;
        this.password = password;
        this.method = method;
        this.uot = uot;
        this.UoTVersion = UoTVersion;
    }

    static fromJson(json = {}) {
        let servers = json.servers;
        if (ObjectUtil.isArrEmpty(servers)) servers = [{}];
        return new Outbound.ShadowsocksSettings(
            servers[0].address,
            servers[0].port,
            servers[0].password,
            servers[0].method,
            servers[0].uot,
            servers[0].UoTVersion,
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                password: this.password,
                method: this.method,
                uot: this.uot,
                UoTVersion: this.UoTVersion,
            }],
        };
    }
};

Outbound.SocksSettings = class extends CommonClass {
    constructor(address, port, user, pass) {
        super();
        this.address = address;
        this.port = port;
        this.user = user;
        this.pass = pass;
    }

    // `users` is optional in a socks outbound and absent from every one this panel
    // synthesises (the SSH tunnel's, WARP's). ObjectUtil.isArrEmpty(undefined) is
    // FALSE, so guarding with it read straight through to servers[0].users[0] and
    // threw. That throw landed inside outModal.show() AFTER it had already set
    // visible, so Edit on such a row opened the dialog holding the previously
    // edited outbound with OK live, and confirming overwrote the real one.
    static fromJson(json = {}) {
        const servers = firstServerOf(json);
        const users = Array.isArray(servers[0].users) ? servers[0].users : [];
        return new Outbound.SocksSettings(
            servers[0].address,
            servers[0].port,
            users.length ? users[0].user : '',
            users.length ? users[0].pass : '',
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                users: ObjectUtil.isEmpty(this.user) ? [] : [{ user: this.user, pass: this.pass }],
            }],
        };
    }
};
// An operator-configured SSH egress tunnel. Only socksPort reaches the Xray
// config: the panel dials the SSH server itself and serves a local SOCKS5 proxy
// on 127.0.0.1:socksPort, and Xray is pointed at that. Everything else here is
// posted to /panel/xray/sshoutbound/save, which owns the tunnel.
//
// toJson therefore emits the SOCKS server shape, and Outbound.toJson rewrites the
// protocol to match, so the JSON tab shows the outbound Xray will really get
// rather than an `ssh` protocol Xray would reject.
//
// Blank password/privateKey/passphrase mean "keep the stored secret" on the
// server, which is why they are never pre-filled when editing.
Outbound.SshSettings = class extends CommonClass {
    constructor(
        address = '',
        port = 22,
        username = '',
        authType = 'password',
        password = '',
        privateKey = '',
        passphrase = '',
        knownHost = '',
        // 0 asks the server to allocate a free loopback port and report it back.
        // Never operator-supplied: the port only exists on 127.0.0.1 between Xray
        // and the panel, so there is nothing for an operator to decide and a
        // hand-picked one just collides with another tunnel.
        socksPort = 0,
    ) {
        super();
        this.address = address;
        this.port = port;
        this.username = username;
        this.authType = authType;
        this.password = password;
        this.privateKey = privateKey;
        this.passphrase = passphrase;
        this.knownHost = knownHost;
        this.socksPort = socksPort;
    }

    // Reads back the local port from the socks outbound this became, so an
    // ssh-shaped outbound survives a round trip through the JSON tab. The tunnel
    // fields themselves live server-side and are not echoed into the config.
    static fromJson(json = {}) {
        const servers = firstServerOf(json);
        const s = new Outbound.SshSettings();
        if (servers[0].port) s.socksPort = servers[0].port;
        return s;
    }

    toJson() {
        return {
            servers: [{
                address: '127.0.0.1',
                port: this.socksPort,
            }],
        };
    }
};

// The nine client tunnels behind the "vpn:" protocols, and the fields each one
// needs.
//
// ONE table instead of nine settings classes and nine blocks of form markup.
// Every kind serialises to the same freedom+sockopt outbound, so the only thing
// that actually differs between them is this list of fields: nine hand-written
// blocks would be ~350 lines of near-identical markup that nobody can keep
// aligned with nine driver files. More importantly, `secret` is declared here
// ONCE. Nine blocks would each have to remember which fields are secrets, and
// the one that forgot would write a private key into the Xray config, where the
// JSON tab shows it to anyone who can open the page.
//
// Field keys:
//   name        key in the settings object POSTed to /panel/xray/vpnoutbound/save
//   type        text | password | textarea | number | switch | select
//   def         initial value. Arrays are copied per instance, never shared, and
//               null means "leave it blank": a blank number is dropped from the
//               POST, which is how the operator asks the DRIVER for its default
//               (every numeric setting on the Go side treats 0/absent that way).
//   label       i18n key under pages.xray.outbound, resolved in the outbound modal.
//               This file is a static asset the template engine never sees, so the
//               i18n helper cannot run here.
//   plain       literal label for protocol jargon that is the same word in every
//               language (MTU, TTL, Jc, H1). Used when there is no label key.
//   help        i18n key for a tooltip on the label. Where the explanation goes,
//               because antd-vue 1.7.8 gives .ant-form-item-label overflow:hidden
//               and white-space:nowrap: a label longer than its 8-of-24 column
//               does not wrap, it is silently cut off mid-word.
//   secret      posted out-of-band only, never pre-filled on edit, and omitted
//               from the POST when blank so the server keeps the stored one.
//   options     select values, [{value,text}]
//   showIf      predicate over the kind's own parameters; hides a field that the
//               current mode does not use (an IKEv2 PSK under EAP, say). Hidden
//               fields are still POSTed: they are a mode the operator may switch
//               back to, and silently dropping them would empty that mode.
//   clears      the name of a SECRET this field is validated as a pair with.
//               Emptying this one also posts that one empty, because a secret
//               left out of the POST is restored from what is stored, and half a
//               restored pair fails validation (see openvpn cert/key).
//
// Adding a protocol is one entry here, one "vpn:<kind>" entry in Protocols so it
// appears in the Add Outbound picker, and one driver file, which is the same
// shape the server side has (RegisterVpnOutDriver from the driver's own init()).
// A kind that is in this table and not in Protocols has fields and no way to be
// chosen; one that is in Protocols and not here is an empty form.
//
// Every `name` below is a json tag on that kind's Go settings struct in
// web/service/vpnout_<kind>.go. They have to match exactly: the driver
// unmarshals this object and silently ignores a key it does not know, so a typo
// here does not fail, it produces a tunnel missing the field the operator filled
// in. wireguard/awg/gre/openvpn/l2tp/ikev2 are mirrored from the landed drivers;
// pptp, openconnect and sstp have no driver yet and are marked below.
const VPN_OUT_WG_FIELDS = [
    { name: 'endpoint', type: 'text', def: '', label: 'vpnOutEndpoint', placeholder: '203.0.113.10:51820' },
    // Takes the [Interface] Address line of a wg .conf verbatim, comma-separated
    // forms included, so the operator can paste rather than transcribe.
    { name: 'address', type: 'text', def: '', label: 'vpnOutTunAddress', placeholder: '10.7.0.2/32, fd00::2/128' },
    { name: 'privateKey', type: 'password', def: '', label: 'vpnOutPrivateKey', secret: true },
    { name: 'peerPublicKey', type: 'text', def: '', label: 'vpnOutPeerKey' },
    { name: 'presharedKey', type: 'password', def: '', label: 'vpnOutPresharedKey', secret: true },
    // Seconds. 25 is the driver's own default; 0 turns keepalive off, which is
    // why this one is not left blank: blank would read as "off" to an operator
    // and as "use 25" to the driver.
    { name: 'keepalive', type: 'number', def: 25, min: 0, max: 65535, label: 'vpnOutKeepAlive' },
    { name: 'mtu', type: 'number', def: null, min: 576, max: 9000, plain: 'MTU', placeholder: '1420' },
];

// AmneziaWG is WireGuard plus obfuscation parameters. They are NOT free choices:
// every one has to match the server's config exactly, which is why they start
// BLANK rather than at the AWG inbound's defaults. A guessed junk-packet count
// that disagrees with the far side does not fail loudly, it produces a tunnel
// that handshakes and carries nothing.
//
// H1-H4 are text and not numbers because they are uint32 magic headers, and
// values above 2^31 are exactly where an <a-input-number> starts rounding.
const VPN_OUT_AWG_FIELDS = VPN_OUT_WG_FIELDS.concat([
    { name: 'jc', type: 'number', def: null, min: 0, max: 128, plain: 'Jc' },
    { name: 'jmin', type: 'number', def: null, min: 0, max: 1280, plain: 'Jmin' },
    { name: 'jmax', type: 'number', def: null, min: 0, max: 1280, plain: 'Jmax' },
    { name: 's1', type: 'number', def: null, min: 0, max: 1280, plain: 'S1' },
    { name: 's2', type: 'number', def: null, min: 0, max: 1280, plain: 'S2' },
    // All four or none: they replace the four packet types together, so a partial
    // set breaks half the packets. The driver rejects it, but the rule is not
    // guessable from the form.
    { name: 'h1', type: 'text', def: '', plain: 'H1', help: 'vpnOutAwgHeadersHelp' },
    { name: 'h2', type: 'text', def: '', plain: 'H2' },
    { name: 'h3', type: 'text', def: '', plain: 'H3' },
    { name: 'h4', type: 'text', def: '', plain: 'H4' },
]);

const VPN_OUT_KINDS = {
    // "(kernel)" is not decoration: it is what separates this row from Xray's own
    // wireguard outbound in the picker, and it is the same word Core Settings
    // already uses for the server-side twin. See PROTOCOL_LABELS.
    wireguard: { label: 'WireGuard (kernel)', fields: VPN_OUT_WG_FIELDS },
    awg: { label: 'AmneziaWG', fields: VPN_OUT_AWG_FIELDS },
    openvpn: {
        label: 'OpenVPN',
        fields: [
            // The whole .ovpn, pasted. It carries the remote, port, cipher and the
            // inline certificates, so filling it in is what makes every discrete
            // field below unnecessary; the driver uses those only when it is empty.
            // Secret because a provider profile usually embeds a key or a
            // tls-crypt block.
            { name: 'profile', type: 'textarea', def: '', rows: 6, label: 'vpnOutProfile', secret: true, placeholder: 'client\nremote 203.0.113.10 1194 udp\n...' },
            // Credentials belong to the account, not the profile, so they stay
            // visible in both modes.
            { name: 'username', type: 'text', def: '', label: 'vpnOutUsername' },
            { name: 'password', type: 'password', def: '', label: 'vpnOutPassword', secret: true },
            // The discrete alternative. Hidden while a profile is pasted, because
            // the driver ignores them then and a filled-in field that does nothing
            // is worse than no field.
            { name: 'server', type: 'text', def: '', label: 'vpnOutServer', placeholder: '203.0.113.10', showIf: p => !p.profile },
            { name: 'port', type: 'number', def: null, min: 1, max: 65535, label: 'vpnOutPort', placeholder: '1194', showIf: p => !p.profile },
            {
                name: 'proto', type: 'select', def: 'udp', label: 'vpnOutProto', showIf: p => !p.profile,
                options: [{ value: 'udp', text: 'UDP' }, { value: 'tcp', text: 'TCP' }],
            },
            { name: 'ca', type: 'textarea', def: '', rows: 4, label: 'vpnOutCaCert', showIf: p => !p.profile },
            // The driver takes cert and key together or not at all. `key` is a
            // secret, so leaving it untouched restores the stored one: without
            // `clears`, emptying just the certificate would save a tunnel with a
            // key and no certificate, which Validate refuses.
            { name: 'cert', type: 'textarea', def: '', rows: 4, label: 'vpnOutCert', showIf: p => !p.profile, clears: 'key' },
            { name: 'key', type: 'textarea', def: '', rows: 4, label: 'vpnOutKey', secret: true, showIf: p => !p.profile },
            { name: 'tlsAuth', type: 'textarea', def: '', rows: 3, label: 'vpnOutTlsAuth', secret: true, showIf: p => !p.profile },
            { name: 'tlsCrypt', type: 'textarea', def: '', rows: 3, label: 'vpnOutTlsCrypt', secret: true, showIf: p => !p.profile },
            { name: 'remoteCertTls', type: 'switch', def: false, label: 'vpnOutRemoteCertTls', showIf: p => !p.profile },
            { name: 'mtu', type: 'number', def: null, min: 576, max: 9000, plain: 'MTU' },
            // Appended verbatim and NOT filtered, so it is also how an operator
            // puts back a directive the driver stripped. It is also NOT masked in
            // the tunnel list, which is why the driver refuses an inline key block
            // here and the tooltip says where those go instead.
            { name: 'extra', type: 'textarea', def: '', rows: 3, label: 'vpnOutExtra', help: 'vpnOutExtraHelp' },
        ],
    },
    l2tp: {
        label: 'L2TP/IPsec',
        fields: [
            { name: 'server', type: 'text', def: '', label: 'vpnOutServer', placeholder: '203.0.113.10' },
            { name: 'username', type: 'text', def: '', label: 'vpnOutUsername' },
            { name: 'password', type: 'password', def: '', label: 'vpnOutPassword', secret: true },
            {
                name: 'authProto', type: 'select', def: 'auto', label: 'vpnOutAuthProto',
                options: [
                    { value: 'auto', text: 'Automatic (anything but EAP)' },
                    { value: 'mschapv2', text: 'MS-CHAPv2' },
                    { value: 'chap', text: 'CHAP' },
                    { value: 'pap', text: 'PAP' },
                ],
            },
            // There is no IPsec switch: the key IS the switch. An empty one means
            // plain L2TP to the driver, so a separate toggle could only disagree
            // with it.
            { name: 'ipsecPsk', type: 'password', def: '', label: 'vpnOutIpsecPsk', help: 'vpnOutIpsecPskHelp', secret: true },
            { name: 'mtu', type: 'number', def: null, min: 576, max: 1500, plain: 'MTU', placeholder: '1400' },
        ],
    },
    ikev2: {
        label: 'IKEv2',
        fields: [
            { name: 'server', type: 'text', def: '', label: 'vpnOutServer', placeholder: 'vpn.example.com' },
            // The driver's three modes. Note "cert" and not the inbound's
            // "eap-tls": this side is the initiator, so it presents its own
            // certificate rather than terminating somebody else's EAP.
            {
                name: 'authMode', type: 'select', def: 'eap-mschapv2', label: 'vpnOutAuthMode',
                options: [
                    { value: 'eap-mschapv2', text: 'EAP-MSCHAPv2 (username/password)' },
                    { value: 'psk', text: 'PSK (shared secret)' },
                    { value: 'cert', text: 'Client certificate' },
                ],
            },
            { name: 'username', type: 'text', def: '', label: 'vpnOutUsername', showIf: p => p.authMode === 'eap-mschapv2' },
            { name: 'password', type: 'password', def: '', label: 'vpnOutPassword', secret: true, showIf: p => p.authMode === 'eap-mschapv2' },
            { name: 'psk', type: 'password', def: '', label: 'vpnOutPsk', secret: true, showIf: p => p.authMode === 'psk' },
            { name: 'localId', type: 'text', def: '', label: 'vpnOutLocalId' },
            // The identity the gateway must prove (IKEv2 IDr). Blank defaults to
            // the dialled address, which is what a correctly issued gateway
            // certificate carries; "%any" turns the check off entirely.
            { name: 'serverId', type: 'text', def: '', label: 'vpnOutServerId' },
            // Inline PEM or paths on the server, mirroring the same choice the
            // IKEv2 and SSTP inbounds offer.
            { name: 'tlsUseFile', type: 'switch', def: false, label: 'vpnOutTlsUseFile' },
            { name: 'certificate', type: 'textarea', def: '', rows: 4, label: 'vpnOutCert', showIf: p => p.authMode === 'cert' && !p.tlsUseFile },
            { name: 'key', type: 'textarea', def: '', rows: 4, label: 'vpnOutKey', secret: true, showIf: p => p.authMode === 'cert' && !p.tlsUseFile },
            // Verifying the gateway is not a cert-mode concern: EAP and PSK
            // tunnels are dialled against the same CA.
            { name: 'caCert', type: 'textarea', def: '', rows: 4, label: 'vpnOutCaCert', showIf: p => !p.tlsUseFile },
            { name: 'certificateFile', type: 'text', def: '', label: 'vpnOutCertFile', showIf: p => p.authMode === 'cert' && p.tlsUseFile },
            { name: 'keyFile', type: 'text', def: '', label: 'vpnOutKeyFile', showIf: p => p.authMode === 'cert' && p.tlsUseFile },
            { name: 'caCertFile', type: 'text', def: '', label: 'vpnOutCaCertFile', showIf: p => p.tlsUseFile },
            // Blank asks the gateway for a virtual IP through the configuration
            // payload, which is what a remote-access gateway expects.
            { name: 'localAddr', type: 'text', def: '', label: 'vpnOutLocalAddress' },
            { name: 'remoteTs', type: 'text', def: '', label: 'vpnOutRemoteTs', placeholder: '0.0.0.0/0' },
            { name: 'mtu', type: 'number', def: null, min: 576, max: 9000, plain: 'MTU' },
        ],
    },
    sstp: {
        label: 'SSTP',
        fields: [
            { name: 'server', type: 'text', def: '', label: 'vpnOutServer', placeholder: 'vpn.example.com' },
            { name: 'username', type: 'text', def: '', label: 'vpnOutUsername' },
            { name: 'password', type: 'password', def: '', label: 'vpnOutPassword', secret: true },
            {
                name: 'authProto', type: 'select', def: 'mschapv2', label: 'vpnOutAuthProto',
                options: [
                    { value: 'mschapv2', text: 'MS-CHAPv2' },
                    { value: 'mschap', text: 'MS-CHAP' },
                    { value: 'chap', text: 'CHAP' },
                    { value: 'pap', text: 'PAP' },
                    { value: 'auto', text: 'Automatic' },
                ],
            },
            // For the very common self-signed SSTP gateway, this panel's own SSTP
            // core included.
            { name: 'caCert', type: 'textarea', def: '', rows: 4, label: 'vpnOutCaCert', showIf: p => !p.allowInsecureCert },
            // Off by default on purpose: SSTP is PPP inside TLS, so turning the
            // certificate failure into a warning gives up the only thing
            // authenticating the server.
            { name: 'allowInsecureCert', type: 'switch', def: false, label: 'vpnOutInsecure' },
            { name: 'proxy', type: 'text', def: '', label: 'vpnOutProxy', placeholder: 'http://10.0.0.1:3128' },
            { name: 'mtu', type: 'number', def: null, min: 576, max: 1500, plain: 'MTU' },
        ],
    },
    openconnect: {
        label: 'OpenConnect',
        fields: [
            { name: 'server', type: 'text', def: '', label: 'vpnOutServer', placeholder: 'https://vpn.example.com' },
            {
                name: 'protocol', type: 'select', def: 'anyconnect', label: 'vpnOutOcProtocol',
                options: [
                    { value: 'anyconnect', text: 'AnyConnect (also ocserv)' },
                    { value: 'nc', text: 'Juniper Network Connect' },
                    { value: 'pulse', text: 'Pulse Connect Secure' },
                    { value: 'gp', text: 'GlobalProtect' },
                    { value: 'f5', text: 'F5 BIG-IP' },
                    { value: 'fortinet', text: 'Fortinet' },
                    { value: 'array', text: 'Array Networks' },
                ],
            },
            { name: 'username', type: 'text', def: '', label: 'vpnOutUsername' },
            { name: 'password', type: 'password', def: '', label: 'vpnOutPassword', secret: true },
            // The gateway's realm/domain/tunnel-group. Wrong or missing, most
            // gateways answer with a form no unattended client can fill in.
            { name: 'authgroup', type: 'text', def: '', label: 'vpnOutAuthGroup' },
            { name: 'totpSecret', type: 'password', def: '', label: 'vpnOutTotpSecret', secret: true },
            // Certificate auth, alone or alongside a password: several gateways
            // require both.
            { name: 'cert', type: 'textarea', def: '', rows: 4, label: 'vpnOutCert' },
            { name: 'key', type: 'textarea', def: '', rows: 4, label: 'vpnOutKey', secret: true },
            { name: 'keyPassword', type: 'password', def: '', label: 'vpnOutKeyPassword', secret: true },
            { name: 'caCert', type: 'textarea', def: '', rows: 4, label: 'vpnOutCaCert' },
            // Pins one certificate rather than trusting a CA that signs for
            // everyone, which is the right answer for a self-signed gateway.
            { name: 'serverCert', type: 'text', def: '', label: 'vpnOutServerCert', placeholder: 'pin-sha256:...' },
            // Drops the UDP data channel. Slower, and the only thing that works
            // where UDP is blocked.
            { name: 'noDtls', type: 'switch', def: false, label: 'vpnOutNoDtls' },
            { name: 'mtu', type: 'number', def: null, min: 576, max: 1500, plain: 'MTU' },
        ],
    },
    pptp: {
        label: 'PPTP',
        fields: [
            { name: 'server', type: 'text', def: '', label: 'vpnOutServer', placeholder: '203.0.113.10' },
            { name: 'username', type: 'text', def: '', label: 'vpnOutUsername' },
            { name: 'password', type: 'password', def: '', label: 'vpnOutPassword', secret: true },
            {
                name: 'authProto', type: 'select', def: 'mschapv2', label: 'vpnOutAuthProto',
                options: [
                    { value: 'mschapv2', text: 'MS-CHAPv2' },
                    { value: 'mschap', text: 'MS-CHAP' },
                    { value: 'chap', text: 'CHAP' },
                    { value: 'pap', text: 'PAP' },
                    { value: 'auto', text: 'Automatic' },
                ],
            },
            // Not a switch, because "off" is not a preference: PPTP without MPPE
            // is a cleartext tunnel, and it is also the only setting in which PAP
            // or CHAP work at all, since the MPPE keys come from the MS-CHAP
            // exchange and nothing else produces them.
            {
                name: 'mppe', type: 'select', def: 'required', label: 'vpnOutMppe', help: 'vpnOutMppeHelp',
                options: [
                    { value: 'required', text: 'Required (128-bit)' },
                    { value: 'off', text: 'Off (cleartext tunnel)' },
                ],
            },
            { name: 'mtu', type: 'number', def: null, min: 576, max: 1500, plain: 'MTU', placeholder: '1400' },
        ],
    },
    gre: {
        label: 'GRE',
        fields: [
            { name: 'server', type: 'text', def: '', label: 'vpnOutServer', placeholder: '203.0.113.10' },
            // Blank lets the kernel source the tunnel from whatever address the
            // route to the server picks, which is right on a single-homed host and
            // wrong to guess on exactly the multi-homed one whose operator knows it.
            { name: 'local', type: 'text', def: '', label: 'vpnOutLocalAddress' },
            { name: 'address', type: 'text', def: '', label: 'vpnOutTunAddress', placeholder: '10.11.0.2/30' },
            // The far side's inner address. Nothing routes by it (a point-to-point
            // GRE device sends everything to its outer remote), but it is half of
            // the pair of numbers the far side hands out and it is what an operator
            // pings to prove the tunnel carries traffic.
            { name: 'peer', type: 'text', def: '', label: 'vpnOutPeerAddress', placeholder: '10.11.0.1' },
            { name: 'ttl', type: 'number', def: null, min: 0, max: 255, plain: 'TTL', placeholder: '64' },
            // Blank = let the kernel choose, as the GRE inbound documents: the
            // right MTU differs between raw GRE and GRE-in-FOU and the kernel
            // knows which is in play, so a number pinned here would be wrong for
            // the other mode.
            { name: 'mtu', type: 'number', def: null, min: 576, max: 9000, plain: 'MTU' },
            { name: 'fouEnable', type: 'switch', def: false, label: 'vpnOutFou' },
            { name: 'fouPort', type: 'number', def: 15547, min: 1, max: 65535, label: 'vpnOutFouPort', showIf: p => p.fouEnable },
            { name: 'ipsecEnable', type: 'switch', def: false, label: 'vpnOutIpsec' },
            { name: 'ipsecPsk', type: 'password', def: '', label: 'vpnOutIpsecPsk', secret: true, showIf: p => p.ipsecEnable },
            // The far side's IKE identity. Exposed because a vpn-ui GRE inbound
            // presents "gre-<id>.vpn-ui" and its recipe tells the peer to pin it:
            // a shared charon holding several PSKs cannot otherwise tell which key
            // this tunnel is meant to use.
            { name: 'ipsecRemoteId', type: 'text', def: '', label: 'vpnOutIpsecRemoteId', showIf: p => p.ipsecEnable },
            { name: 'ipsecLocalId', type: 'text', def: '', label: 'vpnOutIpsecLocalId', showIf: p => p.ipsecEnable },
            // Blank accepts either version and initiates IKEv2, which is right
            // almost always. It is offered because IKEv1 is the only thing that
            // brings a tunnel up against an older router that answers nothing at
            // all to an IKEv2 proposal, and nothing on this side can discover that.
            {
                name: 'ipsecIkeVersion', type: 'select', def: 0, label: 'vpnOutIkeVersion', showIf: p => p.ipsecEnable,
                options: [
                    { value: 0, text: 'Automatic' },
                    { value: 2, text: 'IKEv2' },
                    { value: 1, text: 'IKEv1' },
                ],
            },
        ],
    },
};

const VPN_OUT_DEFAULT_KIND = 'wireguard';

// wg-quick .conf key -> field name in VPN_OUT_KINDS, per section. Lower-cased
// keys because the format is case-insensitive and every generator picks its own
// spelling (PublicKey, publickey, PUBLICKEY are the same key to wg).
//
// The AmneziaWG obfuscation keys sit in [Interface] alongside the WireGuard
// ones, which is why they are listed here rather than in a table of their own:
// the same file parses for both kinds, and the ones the plain wireguard kind has
// no field for are reported as ignored instead of silently dropped.
const WG_CONF_INTERFACE_KEYS = {
    privatekey: 'privateKey',
    address: 'address',
    mtu: 'mtu',
    jc: 'jc',
    jmin: 'jmin',
    jmax: 'jmax',
    s1: 's1',
    s2: 's2',
    h1: 'h1',
    h2: 'h2',
    h3: 'h3',
    h4: 'h4',
};
const WG_CONF_PEER_KEYS = {
    publickey: 'peerPublicKey',
    presharedkey: 'presharedKey',
    endpoint: 'endpoint',
    persistentkeepalive: 'keepalive',
};

// Parses a wg-quick / AmneziaWG .conf into values for `kind`'s fields.
//
// Returns { values, ignored, error, errorLine }. Nothing is written into the
// form here: the caller applies `values` only after this reports no error,
// because a half-applied import is the worst outcome available. It leaves a form
// that looks filled in and saves a tunnel dialling the previous peer with the
// new file's keys, and nothing on screen says so.
//
// `ignored` names every key in the file that this did not use, spelled as the
// file spelled it. wg-quick carries a lot that has no equivalent here (DNS,
// Table, PostUp, AllowedIPs, a second [Peer], AmneziaWG 1.5's I1-I5), and a key
// dropped in silence is exactly the failure that shows up later as a tunnel
// which handshakes and carries nothing.
function parseWgConf(text, kind = VPN_OUT_DEFAULT_KIND) {
    const out = { values: {}, ignored: [], error: '', errorLine: 0 };
    if (!text || !text.trim()) {
        out.error = 'empty';
        return out;
    }
    const known = {};
    Outbound.VpnSettings.fieldsOf(kind).forEach(f => { known[f.name] = f; });
    const lines = String(text).split(/\r?\n/);
    let section = '';
    let peers = 0;
    for (let i = 0; i < lines.length; i++) {
        // Trailing comments only where a comment can start: a bare strip of
        // everything after a '#' would cut a value that legitimately contains one.
        const line = lines[i].replace(/(^|\s)[#;].*$/, '').trim();
        if (!line) continue;
        const header = line.match(/^\[(.+)\]$/);
        if (header) {
            section = header[1].trim().toLowerCase();
            if (section === 'peer') peers++;
            continue;
        }
        const eq = line.indexOf('=');
        if (eq < 1) {
            // Neither a section nor key = value. Refusing the whole file is the
            // point: this is not a wg config, and guessing at the rest of it
            // fills the form with something the operator never wrote.
            out.error = 'malformed';
            out.errorLine = i + 1;
            return out;
        }
        // First '=' only: a base64 key ends in '=' padding and must survive.
        const key = line.slice(0, eq).trim();
        const value = line.slice(eq + 1).trim();
        const name = section === 'interface'
            ? WG_CONF_INTERFACE_KEYS[key.toLowerCase()]
            : (section === 'peer' && peers === 1 ? WG_CONF_PEER_KEYS[key.toLowerCase()] : undefined);
        // Only the first [Peer] is applied: a tunnel here dials one peer, and
        // merging a second one's keys over the first would produce a config that
        // matches neither.
        if (!name || !known[name] || value === '') {
            out.ignored.push(peers > 1 && section === 'peer' ? key + ' ([Peer] ' + peers + ')' : key);
            continue;
        }
        if (known[name].type === 'number') {
            const n = Number(value);
            if (!Number.isFinite(n)) {
                out.ignored.push(key);
                continue;
            }
            out.values[name] = n;
            continue;
        }
        out.values[name] = value;
    }
    // A file that parsed cleanly and carries neither end of the keypair is some
    // other kind of ini file. Accepting it would blank nothing and fill nothing,
    // which reads as an import that worked.
    if (out.values.privateKey === undefined && out.values.peerPublicKey === undefined) {
        out.error = 'notWireguard';
        return out;
    }
    return out;
}

// The kinds whose upstream config file the panel can read, and what to do with
// one. Everything happens in the browser: the file is read with FileReader and
// there is no upload endpoint, so a profile full of private keys is never posted
// anywhere except to /vpnoutbound/save with the rest of the tunnel.
//
//   accept  the file picker's filter, which is a hint and not a guarantee
//   into    a single field that takes the file verbatim (OpenVPN's .ovpn, which
//           the driver prefers over every discrete field anyway)
//   parse   a parser producing values for the discrete fields
const VPN_OUT_IMPORT = {
    wireguard: { accept: '.conf,.txt,text/plain', parse: parseWgConf },
    awg: { accept: '.conf,.txt,text/plain', parse: parseWgConf },
    openvpn: { accept: '.ovpn,.conf,.txt,text/plain', into: 'profile' },
};

// One client VPN tunnel, dialled by the panel and egressed through by Xray.
//
// Nothing in here except `iface` reaches the Xray config: the tunnel itself is
// POSTed to /panel/xray/vpnoutbound/save, which raises it and reports back the
// netdev the driver landed on, and the outbound is a freedom one pinned to that
// device with SO_BINDTODEVICE. Same division as Outbound.SshSettings, where only
// the loopback port crosses over.
Outbound.VpnSettings = class extends CommonClass {
    constructor(kind = VPN_OUT_DEFAULT_KIND, params = {}, iface = '', remark = '') {
        super();
        this.kind = kind;
        this.params = Outbound.VpnSettings.paramsFor(kind, params);
        // Decided by the driver at Up() time, never typed: an interface name typed
        // into the panel is a promise about the kernel that nothing checks, and a
        // wrong one binds egress to some other device that happens to exist.
        this.iface = iface;
        this.remark = remark;
        // The kind this tunnel is STORED as, fixed at construction. Changing the
        // picker moves `kind` and leaves this behind, which is how the form knows
        // to warn: the server skips its keep-the-stored-secret merge when the kind
        // changes, because the stored settings belong to another protocol's shape.
        this.storedKind = kind;
        // Secret fields the operator has actually typed into during this edit.
        //
        // The server distinguishes an ABSENT key ("keep what is stored") from a
        // key present and empty ("clear it"). The form cannot tell those apart from
        // the value alone, because a stored secret is never rendered, so both look
        // like an empty input. This records the difference: untouched and blank is
        // absent, touched and blank is an explicit clear.
        //
        // Every secret gets a key up front, false, for the same Vue 2 reason
        // `params` does. Built empty first, this silently half-worked: touch()
        // set a property Vue was not watching, so the POST was right while the
        // form never redrew, and the field that was about to be deleted looked
        // exactly like one that was being kept.
        this.touched = Outbound.VpnSettings.touchedFor(kind);
    }

    // The touch-tracking object for a kind: one false per secret field.
    static touchedFor(kind) {
        const out = {};
        Outbound.VpnSettings.fieldsOf(kind).forEach(f => {
            if (f.secret) out[f.name] = false;
        });
        return out;
    }

    // Called from the form when a secret input changes. See `touched`.
    touch(name) {
        this.touched[name] = true;
    }

    // Builds the parameter object for a kind, seeded from `params` where present.
    // Every field of the kind gets a key even when it is empty, because Vue 2
    // cannot observe a property added to an object after that object was made
    // reactive: a field created lazily by v-model would swallow what the operator
    // typed, never re-render, and never reach the POST.
    static paramsFor(kind, params = {}) {
        const out = {};
        const fields = (VPN_OUT_KINDS[kind] || {}).fields || [];
        const src = params || {};
        fields.forEach(f => {
            // A secret is never seeded from stored settings. /vpnoutbound/list now
            // strips the keys a driver declares secret, so normally there is
            // nothing to seed anyway; this is the belt to that braces, for a driver
            // that has not declared one yet. A private key that reaches the browser
            // is a private key in a page anyone looking over a shoulder can reveal.
            // Enforced here rather than at each call site, so no future caller can
            // forget it.
            const v = f.secret ? undefined : src[f.name];
            if (v === undefined || v === null) {
                out[f.name] = Array.isArray(f.def) ? f.def.slice() : f.def;
                return;
            }
            out[f.name] = Array.isArray(f.def) && !Array.isArray(v) ? [v] : v;
        });
        return out;
    }

    static fieldsOf(kind) {
        return (VPN_OUT_KINDS[kind] || {}).fields || [];
    }

    // The fields to draw for the parameters as they stand. On the model rather
    // than in the template so the form and anything else reasoning about a tunnel
    // agree on what a mode actually uses.
    visibleFields() {
        return Outbound.VpnSettings.fieldsOf(this.kind).filter(f => !f.showIf || f.showIf(this.params));
    }

    // Switches protocol, discarding the previous kind's parameters. Deliberate:
    // the fields only look alike (an L2TP `password` is not an OpenVPN one), and
    // carrying them over would post the old protocol's leftovers to a driver that
    // never asked for them.
    //
    // Clearing is also what the server's merge expects. It skips keep-the-stored-
    // value when the kind changes, since those settings describe another protocol,
    // so every field including the secrets has to be typed again. A form that kept
    // the old values would look filled in and save as half a tunnel.
    setKind(kind) {
        this.kind = kind;
        this.params = Outbound.VpnSettings.paramsFor(kind);
        this.touched = Outbound.VpnSettings.touchedFor(kind);
    }

    // True when the picker has moved off the stored protocol, so the operator is
    // re-creating the tunnel rather than editing it.
    kindChanged() {
        return !!this.storedKind && this.kind !== this.storedKind;
    }

    // What goes to /panel/xray/vpnoutbound/save as the `settings` field.
    //
    // The server merges this over the stored settings key by key: ABSENT keeps the
    // stored value, PRESENT wins even when empty. Both blanks below rely on that,
    // and they mean different things.
    //
    // A secret the operator never typed into is dropped, because the form never
    // rendered the stored one (the API strips the keys a driver declares secret)
    // and sending "" would clear a working key. A secret the operator DID type
    // into and then emptied is sent as "", which is how the panel spells "remove
    // this preshared key". `touched` is the only thing that tells those apart.
    //
    // A blank NUMBER is dropped for a different reason: it has to reach the driver
    // as an absent key, because that is how every numeric setting on the Go side
    // spells "use your own default" (mtu <= 0, ttl <= 0, a nil *int for the AWG
    // junk parameters). Sending it as "" would not merely be wrong, it would fail
    // the unmarshal of the whole settings blob into the driver's struct.
    settingsPayload() {
        const out = {};
        const fields = Outbound.VpnSettings.fieldsOf(this.kind);
        fields.forEach(f => {
            const v = this.params[f.name];
            const blank = v === undefined || v === null || v === '';
            if (blank && f.secret && !this.touched[f.name]) return;
            if (blank && f.type === 'number') return;
            out[f.name] = v;
        });
        // Second pass, after every field has had its say: emptying one half of a
        // validated pair has to empty the other half explicitly, or the absent
        // secret is restored from storage and the tunnel saves with a key and no
        // certificate.
        fields.forEach(f => {
            if (!f.clears) return;
            const v = this.params[f.name];
            if (v === undefined || v === null || v === '') out[f.clears] = '';
        });
        return out;
    }

    // Marks a secret for removal: the field is emptied AND recorded as touched, so
    // it is POSTed as "" (delete the stored value) rather than left out (keep it).
    // Without this the only way to clear one would be to type something into an
    // empty-looking box and delete it again, which nobody would guess.
    clearSecret(name) {
        this.params[name] = '';
        this.touch(name);
    }

    // True once a secret is staged for removal, so the form can say so: an emptied
    // field and an untouched one look identical, and they do opposite things.
    isCleared(name) {
        const v = this.params[name];
        return !!this.touched[name] && (v === undefined || v === null || v === '');
    }

    // A stored vpn outbound is a freedom one in the config, so this is only ever
    // reached from the JSON tab, which is read-only for this protocol. The tunnel
    // itself is rebuilt from /vpnoutbound/list when a row is edited. The kind
    // comes from the protocol value rather than from `json`, which holds the
    // freedom settings and knows nothing about tunnels.
    static fromJson(json = {}, kind = VPN_OUT_DEFAULT_KIND) {
        return new Outbound.VpnSettings(kind);
    }

    // The freedom settings. UseIP because the tunnel is being asked to carry the
    // traffic: a name resolved on the host's own resolver before the socket is
    // pinned would answer for the host's network and not the tunnel's.
    toJson() {
        return { domainStrategy: 'UseIP' };
    }
};
Outbound.HttpSettings = class extends CommonClass {
    constructor(address, port, user, pass) {
        super();
        this.address = address;
        this.port = port;
        this.user = user;
        this.pass = pass;
    }

    // Same optional-`users` trap as SocksSettings.fromJson above.
    static fromJson(json = {}) {
        const servers = firstServerOf(json);
        const users = Array.isArray(servers[0].users) ? servers[0].users : [];
        return new Outbound.HttpSettings(
            servers[0].address,
            servers[0].port,
            users.length ? users[0].user : '',
            users.length ? users[0].pass : '',
        );
    }

    toJson() {
        return {
            servers: [{
                address: this.address,
                port: this.port,
                users: ObjectUtil.isEmpty(this.user) ? [] : [{ user: this.user, pass: this.pass }],
            }],
        };
    }
};

Outbound.WireguardSettings = class extends CommonClass {
    constructor(
        mtu = 1420,
        secretKey = '',
        address = [''],
        workers = 2,
        domainStrategy = '',
        reserved = '',
        peers = [new Outbound.WireguardSettings.Peer()],
        noKernelTun = false,
    ) {
        super();
        this.mtu = mtu;
        this.secretKey = secretKey;
        this.pubKey = secretKey.length > 0 ? Wireguard.generateKeypair(secretKey).publicKey : '';
        this.address = Array.isArray(address) ? address.join(',') : address;
        this.workers = workers;
        this.domainStrategy = domainStrategy;
        this.reserved = Array.isArray(reserved) ? reserved.join(',') : reserved;
        this.peers = peers;
        this.noKernelTun = noKernelTun;
    }

    addPeer() {
        this.peers.push(new Outbound.WireguardSettings.Peer());
    }

    delPeer(index) {
        this.peers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Outbound.WireguardSettings(
            json.mtu,
            json.secretKey,
            json.address,
            json.workers,
            json.domainStrategy,
            json.reserved,
            json.peers.map(peer => Outbound.WireguardSettings.Peer.fromJson(peer)),
            json.noKernelTun,
        );
    }

    toJson() {
        return {
            mtu: this.mtu ?? undefined,
            secretKey: this.secretKey,
            address: this.address ? this.address.split(",") : [],
            workers: this.workers ?? undefined,
            domainStrategy: WireguardDomainStrategy.includes(this.domainStrategy) ? this.domainStrategy : undefined,
            reserved: this.reserved ? this.reserved.split(",").map(Number) : undefined,
            peers: Outbound.WireguardSettings.Peer.toJsonArray(this.peers),
            noKernelTun: this.noKernelTun,
        };
    }
};

Outbound.WireguardSettings.Peer = class extends CommonClass {
    constructor(
        publicKey = '',
        psk = '',
        allowedIPs = ['0.0.0.0/0', '::/0'],
        endpoint = '',
        keepAlive = 0
    ) {
        super();
        this.publicKey = publicKey;
        this.psk = psk;
        this.allowedIPs = allowedIPs;
        this.endpoint = endpoint;
        this.keepAlive = keepAlive;
    }

    static fromJson(json = {}) {
        return new Outbound.WireguardSettings.Peer(
            json.publicKey,
            json.preSharedKey,
            json.allowedIPs,
            json.endpoint,
            json.keepAlive
        );
    }

    toJson() {
        return {
            publicKey: this.publicKey,
            preSharedKey: this.psk.length > 0 ? this.psk : undefined,
            allowedIPs: this.allowedIPs ? this.allowedIPs : undefined,
            endpoint: this.endpoint,
            keepAlive: this.keepAlive ?? undefined,
        };
    }
};

Outbound.HysteriaSettings = class extends CommonClass {
    constructor(address = '', port = 443, version = 2) {
        super();
        this.address = address;
        this.port = port;
        this.version = version;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return new Outbound.HysteriaSettings();
        return new Outbound.HysteriaSettings(
            json.address,
            json.port,
            json.version
        );
    }

    toJson() {
        return {
            address: this.address,
            port: this.port,
            version: this.version
        };
    }
};