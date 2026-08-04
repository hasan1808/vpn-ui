const Protocols = {
    VMESS: 'vmess',
    VLESS: 'vless',
    TROJAN: 'trojan',
    SHADOWSOCKS: 'shadowsocks',
    WIREGUARD: 'wireguard',
    HYSTERIA: 'hysteria',
    ANYTLS: 'anytls',
    TUIC: 'tuic',
    NAIVE: 'naive',
    MIXED: 'mixed',
    HTTP: 'http',
    TUNNEL: 'tunnel',
    TUN: 'tun',
    L2TP: 'l2tp',
    PPTP: 'pptp',
    OPENVPN: 'openvpn',
    OPENCONNECT: 'openconnect',
    SSTP: 'sstp',
    IKEV2: 'ikev2',
    WGC: 'wg-c',
    AWG: 'awg',
    GRE: 'gre',
    MTPROTO: 'mtproto',
    SSH: 'ssh',
};

// The panel-wide client identity: the value that goes in the URL of
// /panel/api/inbounds/updateClient/:clientId and /:id/delClient/:clientId.
//
// This MUST stay in lockstep with clientIdentityKey() in web/service/inbound.go. It
// lives here, once, because the two template-local copies of this switch are exactly
// how it drifted last time: openconnect/sstp/ikev2 were added to the browser's list
// and not to the backend's, so an edit was keyed on the password while the server
// looked the account up by id, and every edit came back "empty client ID".
function getClientIdentity(protocol, client) {
    switch (protocol) {
        // Username+password VPN protocols: the password is the key, because the
        // username is the field operators actually rename.
        case Protocols.TROJAN:
        case Protocols.L2TP:
        case Protocols.PPTP:
        case Protocols.OPENVPN:
        case Protocols.OPENCONNECT:
        case Protocols.SSTP:
        case Protocols.IKEV2:
            return client.password;
        // Password-credential proxy protocols. AnyTLS authenticates on a bare
        // password; naive sends a Basic username:password, and the username is both
        // renameable and optional (empty falls back to the email), so the password is
        // again the only field that can address the account.
        case Protocols.ANYTLS:
        case Protocols.NAIVE:
            return client.password;
        case Protocols.SHADOWSOCKS:
            return client.email;
        case Protocols.HYSTERIA:
        // 'hysteria2' has no Protocols constant because the inbound form cannot
        // create one, but the server knows it (model.Hysteria2) and an inbound
        // made through the API shows up on every page that lists them. Left to the
        // default it would be keyed on `id`, which a hysteria account does not
        // have, and every write against it would answer "empty client ID".
        case 'hysteria2':
            return client.auth;
        // Spelled out rather than left to the default below: a TUIC account carries
        // BOTH a uuid and a password, so which of the two addresses it has to be a
        // decision written down on the page, not a fallthrough nobody can see.
        case Protocols.TUIC:
            return client.id;
        default:
            // vmess/vless (uuid) and the email-identity protocols (wg-c, awg, gre,
            // mtproto, ssh), whose models expose id via a `get id()` returning email.
            return client.id;
    }
}

// Display labels for the protocol picker. The Add/Edit inbound dropdown shows
// these while binding the lowercase Protocols VALUE (openvpn/http/openconnect/…),
// which is what the backend parses — so the pretty text never reaches the server.
const ProtocolLabels = {
    vmess: 'VMess',
    vless: 'VLESS',
    trojan: 'Trojan',
    shadowsocks: 'Shadowsocks',
    wireguard: 'WireGuard (Xray)',
    hysteria: 'Hysteria',
    anytls: 'AnyTLS',
    tuic: 'TUIC',
    naive: 'NaiveProxy',
    mixed: 'Mixed',
    http: 'HTTP',
    tunnel: 'Tunnel',
    tun: 'TUN',
    l2tp: 'L2TP',
    pptp: 'PPTP',
    openvpn: 'OpenVPN',
    openconnect: 'OpenConnect (cisco)',
    sstp: 'SSTP',
    ikev2: 'IKEv2',
    'wg-c': 'WireGuard (C)',
    'awg': 'AmneziaWG',
    gre: 'GRE',
    mtproto: 'MTProto Proxy',
    ssh: 'SSH',
};

const SSMethods = {
    AES_256_GCM: 'aes-256-gcm',
    AES_128_GCM: 'aes-128-gcm',
    CHACHA20_POLY1305: 'chacha20-poly1305',
    CHACHA20_IETF_POLY1305: 'chacha20-ietf-poly1305',
    XCHACHA20_IETF_POLY1305: 'xchacha20-ietf-poly1305',
    BLAKE3_AES_128_GCM: '2022-blake3-aes-128-gcm',
    BLAKE3_AES_256_GCM: '2022-blake3-aes-256-gcm',
    BLAKE3_CHACHA20_POLY1305: '2022-blake3-chacha20-poly1305',
};

const TLS_FLOW_CONTROL = {
    VISION: "xtls-rprx-vision",
    VISION_UDP443: "xtls-rprx-vision-udp443",
};

const TLS_VERSION_OPTION = {
    TLS10: "1.0",
    TLS11: "1.1",
    TLS12: "1.2",
    TLS13: "1.3",
};

const TLS_CIPHER_OPTION = {
    AES_128_GCM: "TLS_AES_128_GCM_SHA256",
    AES_256_GCM: "TLS_AES_256_GCM_SHA384",
    CHACHA20_POLY1305: "TLS_CHACHA20_POLY1305_SHA256",
    ECDHE_ECDSA_AES_128_CBC: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    ECDHE_ECDSA_AES_256_CBC: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    ECDHE_RSA_AES_128_CBC: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    ECDHE_RSA_AES_256_CBC: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    ECDHE_ECDSA_AES_128_GCM: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    ECDHE_ECDSA_AES_256_GCM: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ECDHE_RSA_AES_128_GCM: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ECDHE_RSA_AES_256_GCM: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ECDHE_ECDSA_CHACHA20_POLY1305: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ECDHE_RSA_CHACHA20_POLY1305: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
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

const SNIFFING_OPTION = {
    HTTP: "http",
    TLS: "tls",
    QUIC: "quic",
    FAKEDNS: "fakedns"
};

const USAGE_OPTION = {
    ENCIPHERMENT: "encipherment",
    VERIFY: "verify",
    ISSUE: "issue",
};

const DOMAIN_STRATEGY_OPTION = {
    AS_IS: "AsIs",
    USE_IP: "UseIP",
    USE_IPV6V4: "UseIPv6v4",
    USE_IPV6: "UseIPv6",
    USE_IPV4V6: "UseIPv4v6",
    USE_IPV4: "UseIPv4",
    FORCE_IP: "ForceIP",
    FORCE_IPV6V4: "ForceIPv6v4",
    FORCE_IPV6: "ForceIPv6",
    FORCE_IPV4V6: "ForceIPv4v6",
    FORCE_IPV4: "ForceIPv4",
};

const TCP_CONGESTION_OPTION = {
    BBR: "bbr",
    CUBIC: "cubic",
    RENO: "reno",
};

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

Object.freeze(Protocols);
Object.freeze(ProtocolLabels);
Object.freeze(SSMethods);
Object.freeze(TLS_FLOW_CONTROL);
Object.freeze(TLS_VERSION_OPTION);
Object.freeze(TLS_CIPHER_OPTION);
Object.freeze(UTLS_FINGERPRINT);
Object.freeze(ALPN_OPTION);
Object.freeze(SNIFFING_OPTION);
Object.freeze(USAGE_OPTION);
Object.freeze(DOMAIN_STRATEGY_OPTION);
Object.freeze(TCP_CONGESTION_OPTION);
Object.freeze(USERS_SECURITY);
Object.freeze(MODE_OPTION);

class XrayCommonClass {

    static toJsonArray(arr) {
        return arr.map(obj => obj.toJson());
    }

    static fromJson() {
        return new XrayCommonClass();
    }

    toJson() {
        return this;
    }

    toString(format = true) {
        return format ? JSON.stringify(this.toJson(), null, 2) : JSON.stringify(this.toJson());
    }

    static toHeaders(v2Headers) {
        let newHeaders = [];
        if (v2Headers) {
            Object.keys(v2Headers).forEach(key => {
                let values = v2Headers[key];
                if (typeof (values) === 'string') {
                    newHeaders.push({ name: key, value: values });
                } else {
                    for (let i = 0; i < values.length; ++i) {
                        newHeaders.push({ name: key, value: values[i] });
                    }
                }
            });
        }
        return newHeaders;
    }

    static toV2Headers(headers, arr = true) {
        let v2Headers = {};
        for (let i = 0; i < headers.length; ++i) {
            let name = headers[i].name;
            let value = headers[i].value;
            if (ObjectUtil.isEmpty(name) || ObjectUtil.isEmpty(value)) {
                continue;
            }
            if (!(name in v2Headers)) {
                v2Headers[name] = arr ? [value] : value;
            } else {
                if (arr) {
                    v2Headers[name].push(value);
                } else {
                    v2Headers[name] = value;
                }
            }
        }
        return v2Headers;
    }
}

class TcpStreamSettings extends XrayCommonClass {
    constructor(
        acceptProxyProtocol = false,
        type = 'none',
        request = new TcpStreamSettings.TcpRequest(),
        response = new TcpStreamSettings.TcpResponse(),
    ) {
        super();
        this.acceptProxyProtocol = acceptProxyProtocol;
        this.type = type;
        this.request = request;
        this.response = response;
    }

    static fromJson(json = {}) {
        let header = json.header;
        if (!header) {
            header = {};
        }
        return new TcpStreamSettings(json.acceptProxyProtocol,
            header.type,
            TcpStreamSettings.TcpRequest.fromJson(header.request),
            TcpStreamSettings.TcpResponse.fromJson(header.response),
        );
    }

    toJson() {
        return {
            acceptProxyProtocol: this.acceptProxyProtocol,
            header: {
                type: this.type,
                request: this.type === 'http' ? this.request.toJson() : undefined,
                response: this.type === 'http' ? this.response.toJson() : undefined,
            },
        };
    }
}

TcpStreamSettings.TcpRequest = class extends XrayCommonClass {
    constructor(
        version = '1.1',
        method = 'GET',
        path = ['/'],
        headers = [],
    ) {
        super();
        this.version = version;
        this.method = method;
        this.path = path.length === 0 ? ['/'] : path;
        this.headers = headers;
    }

    addPath(path) {
        this.path.push(path);
    }

    removePath(index) {
        this.path.splice(index, 1);
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new TcpStreamSettings.TcpRequest(
            json.version,
            json.method,
            json.path,
            XrayCommonClass.toHeaders(json.headers),
        );
    }

    toJson() {
        return {
            version: this.version,
            method: this.method,
            path: ObjectUtil.clone(this.path),
            headers: XrayCommonClass.toV2Headers(this.headers),
        };
    }
};

TcpStreamSettings.TcpResponse = class extends XrayCommonClass {
    constructor(
        version = '1.1',
        status = '200',
        reason = 'OK',
        headers = [],
    ) {
        super();
        this.version = version;
        this.status = status;
        this.reason = reason;
        this.headers = headers;
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new TcpStreamSettings.TcpResponse(
            json.version,
            json.status,
            json.reason,
            XrayCommonClass.toHeaders(json.headers),
        );
    }

    toJson() {
        return {
            version: this.version,
            status: this.status,
            reason: this.reason,
            headers: XrayCommonClass.toV2Headers(this.headers),
        };
    }
};

class KcpStreamSettings extends XrayCommonClass {
    constructor(
        mtu = 1350,
        tti = 20,
        uplinkCapacity = 5,
        downlinkCapacity = 20,
        cwndMultiplier = 1,
        maxSendingWindow = 2097152,
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

class WsStreamSettings extends XrayCommonClass {
    constructor(
        acceptProxyProtocol = false,
        path = '/',
        host = '',
        headers = [],
        heartbeatPeriod = 0,
    ) {
        super();
        this.acceptProxyProtocol = acceptProxyProtocol;
        this.path = path;
        this.host = host;
        this.headers = headers;
        this.heartbeatPeriod = heartbeatPeriod;
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new WsStreamSettings(
            json.acceptProxyProtocol,
            json.path,
            json.host,
            XrayCommonClass.toHeaders(json.headers),
            json.heartbeatPeriod,
        );
    }

    toJson() {
        return {
            acceptProxyProtocol: this.acceptProxyProtocol,
            path: this.path,
            host: this.host,
            headers: XrayCommonClass.toV2Headers(this.headers, false),
            heartbeatPeriod: this.heartbeatPeriod,
        };
    }
}

class GrpcStreamSettings extends XrayCommonClass {
    constructor(
        serviceName = "",
        authority = "",
        multiMode = false,
    ) {
        super();
        this.serviceName = serviceName;
        this.authority = authority;
        this.multiMode = multiMode;
    }

    static fromJson(json = {}) {
        return new GrpcStreamSettings(
            json.serviceName,
            json.authority,
            json.multiMode
        );
    }

    toJson() {
        return {
            serviceName: this.serviceName,
            authority: this.authority,
            multiMode: this.multiMode,
        }
    }
}

class HTTPUpgradeStreamSettings extends XrayCommonClass {
    constructor(
        acceptProxyProtocol = false,
        path = '/',
        host = '',
        headers = []
    ) {
        super();
        this.acceptProxyProtocol = acceptProxyProtocol;
        this.path = path;
        this.host = host;
        this.headers = headers;
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new HTTPUpgradeStreamSettings(
            json.acceptProxyProtocol,
            json.path,
            json.host,
            XrayCommonClass.toHeaders(json.headers),
        );
    }

    toJson() {
        return {
            acceptProxyProtocol: this.acceptProxyProtocol,
            path: this.path,
            host: this.host,
            headers: XrayCommonClass.toV2Headers(this.headers, false),
        };
    }
}

// The value the xhttp form starts each field on. A share link only carries a
// field once the admin has actually moved it off this default: a stock xhttp
// inbound has to keep producing a short link (QR codes stop being scannable
// fast) and links handed out before this existed must not change.
//
// xPaddingBytes is deliberately absent. It has always been put on the wire
// even at its default value and clients in the field already read it, so that
// exact behaviour is preserved in Inbound.collectXhttpShareFields instead.
//
// Mirrored on the Go side by xhttpShareDefaults in sub/subService.go.
// xmux and downloadSettings are deliberately absent: both are objects, and this
// table is compared by value. They are handled explicitly in
// Inbound.collectXhttpShareFields instead (see xhttpShareDefaults in
// sub/subService.go, where putting a map here would be an outright panic).
const XHTTP_SHARE_DEFAULTS = {
    scMaxBufferedPosts: 30,
    scMaxEachPostBytes: "1000000",
    scStreamUpServerSecs: "20-80",
    uplinkChunkSize: 0,
    scMinPostsIntervalMs: "30",
    serverMaxHeaderBytes: 0,
};
Object.freeze(XHTTP_SHARE_DEFAULTS);

// The plain scalar xhttp settings copied into a share link as-is once they
// differ from XHTTP_SHARE_DEFAULTS (an absent default means "skip when empty").
// The xPadding* / headers / noSSEHeader / noGRPCHeader fields need shaping and
// xmux / downloadSettings are objects, so all of those are handled explicitly
// rather than from this list.
const XHTTP_SHARE_FIELDS = [
    "scMaxBufferedPosts",
    "scMaxEachPostBytes",
    "scStreamUpServerSecs",
    "uplinkHTTPMethod",
    "sessionPlacement",
    "sessionKey",
    "seqPlacement",
    "seqKey",
    "uplinkDataPlacement",
    "uplinkDataKey",
    "uplinkChunkSize",
    "scMinPostsIntervalMs",
    "serverMaxHeaderBytes",
];
Object.freeze(XHTTP_SHARE_FIELDS);

// xray's own xmux defaults, which are also what the outbound form starts on
// (web/assets/js/model/outbound.js, class xHTTPStreamSettings). The inbound and
// the outbound have to agree here: an admin who reads "16-32" on one form and a
// blank on the other has no way to tell which side is actually in force.
// Mirrored on the Go side by xhttpXmuxDefaults in sub/subService.go.
const XHTTP_XMUX_DEFAULTS = {
    maxConcurrency: "16-32",
    maxConnections: 0,
    cMaxReuseTimes: 0,
    hMaxRequestTimes: "600-900",
    hMaxReusableSecs: "1800-3000",
    hKeepAlivePeriod: 0,
};
Object.freeze(XHTTP_XMUX_DEFAULTS);

class xHTTPStreamSettings extends XrayCommonClass {
    constructor(
        path = '/',
        host = '',
        headers = [],
        scMaxBufferedPosts = 30,
        scMaxEachPostBytes = "1000000",
        scStreamUpServerSecs = "20-80",
        noSSEHeader = false,
        xPaddingBytes = "100-1000",
        mode = MODE_OPTION.AUTO,
        xPaddingObfsMode = false,
        xPaddingKey = '',
        xPaddingHeader = '',
        xPaddingPlacement = '',
        xPaddingMethod = '',
        uplinkHTTPMethod = '',
        sessionPlacement = '',
        sessionKey = '',
        seqPlacement = '',
        seqKey = '',
        uplinkDataPlacement = '',
        uplinkDataKey = '',
        uplinkChunkSize = 0,
        noGRPCHeader = false,
        scMinPostsIntervalMs = "30",
        serverMaxHeaderBytes = 0,
        xmux = undefined,
        downloadSettings = undefined,
        extra = {},
    ) {
        super();
        this.path = path;
        this.host = host;
        this.headers = headers;
        this.scMaxBufferedPosts = scMaxBufferedPosts;
        this.scMaxEachPostBytes = scMaxEachPostBytes;
        this.scStreamUpServerSecs = scStreamUpServerSecs;
        this.noSSEHeader = noSSEHeader;
        this.xPaddingBytes = xPaddingBytes;
        this.mode = mode;
        this.xPaddingObfsMode = xPaddingObfsMode;
        this.xPaddingKey = xPaddingKey;
        this.xPaddingHeader = xPaddingHeader;
        this.xPaddingPlacement = xPaddingPlacement;
        this.xPaddingMethod = xPaddingMethod;
        this.uplinkHTTPMethod = uplinkHTTPMethod;
        this.sessionPlacement = sessionPlacement;
        this.sessionKey = sessionKey;
        this.seqPlacement = seqPlacement;
        this.seqKey = seqKey;
        this.uplinkDataPlacement = uplinkDataPlacement;
        this.uplinkDataKey = uplinkDataKey;
        this.uplinkChunkSize = uplinkChunkSize;
        this.noGRPCHeader = noGRPCHeader;
        this.scMinPostsIntervalMs = scMinPostsIntervalMs;
        this.serverMaxHeaderBytes = serverMaxHeaderBytes;
        // Always a full six-key object so every control in the form has
        // something to bind to, even for an inbound saved before xmux existed
        // or one whose stored blob only carries a subset.
        this.xmux = xHTTPStreamSettings.normalizeXmux(xmux);
        // downloadSettings is a whole nested stream-settings object (the client
        // fetches the downlink over a different transport). The form edits it as
        // raw JSON rather than modelling its internals, so keep the parsed
        // object and the text the admin is typing side by side: a half-typed
        // blob has to stay on screen to be fixed instead of being swallowed.
        this.downloadSettings = xHTTPStreamSettings.normalizeDownloadSettings(downloadSettings);
        this.downloadSettingsRaw = this.downloadSettings
            ? JSON.stringify(this.downloadSettings, null, 2)
            : '';
        this.downloadSettingsError = '';
        // Any xhttp key this form does not model structurally is kept verbatim
        // here: a hand-edited xhttpSettings blob (xray's own nested `extra`
        // object, a key from a newer core) must survive being opened and saved
        // in the panel instead of being silently dropped. Mirrors the same bag
        // on the outbound xHTTPStreamSettings.
        this.extra = extra && typeof extra === 'object' ? extra : {};
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    // Fill in every xmux key the stored blob left out, so all six controls have
    // something to bind to.
    //
    // A key that is PRESENT but empty is kept as-is rather than pushed back to
    // the default. The core reads an empty Int32Range as 0 (ParseRangeString
    // treats "" as zero, it does not reject it), and 0 is the only way to say
    // "this strategy is off": clearing maxConcurrency is exactly how an admin
    // switches to the maxConnections strategy, so restoring the default here
    // would make that combination unreachable and leave a conflict error the
    // admin has no way to clear. Unknown sub-keys (a newer core's
    // cMaxLifetimeMs, a hand edit) ride along untouched.
    //
    // Mirrored on the Go side by normalizeXhttpXmux in sub/subService.go.
    static normalizeXmux(raw) {
        const out = Object.assign({}, XHTTP_XMUX_DEFAULTS);
        if (!raw || typeof raw !== 'object') return out;
        Object.keys(raw).forEach(k => {
            const v = raw[k];
            if (v === undefined || v === null) return;
            out[k] = v;
        });
        return out;
    }

    // Whether an xmux knob carries a real value, the way the core reads it. All
    // six are Int32Range, and the checks in transport_internet.go are on the
    // range's upper end (`.To > 0`), so a range string counts as set when its
    // larger end is positive.
    static xmuxIsSet(value) {
        if (typeof value === 'number') return Number.isFinite(value) && value > 0;
        if (typeof value !== 'string') return false;
        const nums = (value.match(/-?\d+/g) || []).map(Number).filter(Number.isFinite);
        return nums.length > 0 && Math.max(...nums) > 0;
    }

    // maxConnections and maxConcurrency are two different multiplexing
    // strategies and the core refuses to build a config that sets both
    // (transport_internet.go: `maxConnections cannot be specified together with
    // maxConcurrency`). It refuses the WHOLE config, so an inbound saved this
    // way would stop xray from starting rather than just misbehave. The stock
    // pair (maxConcurrency "16-32", maxConnections 0) is the one-strategy case
    // and is fine.
    hasXmuxConflict() {
        if (!this.xmux) return false;
        return xHTTPStreamSettings.xmuxIsSet(this.xmux.maxConnections)
            && xHTTPStreamSettings.xmuxIsSet(this.xmux.maxConcurrency);
    }

    // ---- the rest of the core's xhttp rules --------------------------------
    // Every check below mirrors a hard rejection in SplitHTTPConfig.Build()
    // (third_party/Xray-core/infra/conf/transport_internet.go). They all refuse
    // the WHOLE config rather than the offending key, so an inbound saved in any
    // of these shapes leaves xray refusing to start, which surfaces as a panel
    // that saved happily and a service that never comes up.
    //
    // These were checked against the shipping binary, not read off the source,
    // and the rules that LOOK like they belong here are deliberately absent: an
    // empty sessionKey / seqKey / uplinkDataKey alongside a non-default
    // placement is accepted, because the core fills each one in itself
    // (x_session/X-Session, x_seq/X-Seq, x_data/X-Data) on both ends. Requiring
    // them here would block a config the core is happy with.

    // The core matches this case-insensitively and rejects any casing of "host";
    // the host header has its own field on this form.
    hasHostHeader() {
        return (this.headers || []).some(h => h && typeof h.name === 'string'
            && h.name.trim().toLowerCase() === 'host');
    }

    // Two separate rejections live here. A range the core cannot parse at all
    // ("Invalid integer range"), and "xPaddingBytes cannot be disabled": once
    // the range carries anything, BOTH ends have to be above zero. An all-zero
    // range, which is what a blank field parses to, is the untouched case and is
    // accepted.
    hasPaddingBytesProblem() {
        const value = this.xPaddingBytes;
        if (value === undefined || value === null) return false;
        const range = xHTTPStreamSettings.parseRange(value);
        if (!range) return true;
        if (range.from === 0 && range.to === 0) return false;
        return range.from <= 0 || range.to <= 0;
    }

    // cookie and header are packet-up only; query is not a placement this
    // transport takes at all, in any mode. An inbound saved before this was
    // checked can still be carrying either, so validate rather than trust the
    // select's options.
    uplinkDataPlacementProblem() {
        const placement = this.uplinkDataPlacement;
        if (!placement || placement === 'body' || placement === 'auto') return '';
        if (placement !== 'cookie' && placement !== 'header') return 'unsupported';
        return this.mode === MODE_OPTION.PACKET_UP ? '' : 'mode';
    }

    // GET carries the uplink in the query string, which only packet-up does.
    hasUplinkMethodProblem() {
        return String(this.uplinkHTTPMethod || '').toUpperCase() === 'GET'
            && this.mode !== MODE_OPTION.PACKET_UP;
    }

    // "invalid negative value of maxHeaderBytes". The input carries :min="0", so
    // this only catches a value that arrived from an imported or hand-edited blob.
    hasServerMaxHeaderBytesProblem() {
        const value = this.serverMaxHeaderBytes;
        return typeof value === 'number' && Number.isFinite(value) && value < 0;
    }

    // The uplink data controls are the only ones the mode hides, so a value left
    // behind by a mode change would otherwise block the save with nothing on
    // screen to explain it. The uplink HTTP method select is always visible, so
    // it can carry its own error and is not listed here.
    hasHiddenUplinkProblem() {
        return this.uplinkDataPlacementProblem() === 'mode';
    }

    // Anything here means the core would reject the config outright, so the
    // modal's OK button stays disabled (modalFormValid in
    // web/html/modals/inbound_modal.html).
    hasCoreConfigProblem() {
        return this.hasXmuxConflict()
            || this.hasHostHeader()
            || this.hasPaddingBytesProblem()
            || this.uplinkDataPlacementProblem() !== ''
            || this.hasUplinkMethodProblem()
            || this.hasServerMaxHeaderBytesProblem()
            || !!this.downloadSettingsError
            || (this.mode === MODE_OPTION.STREAM_ONE && !!this.downloadSettingsText);
    }

    // Drop the uplink data placement the current mode has made illegal, for the
    // clear button the form shows next to that error.
    clearUplinkDataPlacement() {
        this.uplinkDataPlacement = '';
        this.uplinkDataKey = '';
    }

    // Both ends of an xray Int32Range, or null when the value is absent. Mirrors
    // ParseRangeString: a plain number is a one-point range, "" is zero, and
    // "a-b" is the pair (with the negative-aware split the core uses).
    static parseRange(value) {
        if (typeof value === 'number') {
            return Number.isFinite(value) ? { from: value, to: value } : null;
        }
        if (typeof value !== 'string') return null;
        const str = value.trim();
        if (str === '') return { from: 0, to: 0 };
        if (/^-?\d+$/.test(str)) {
            const n = Number(str);
            return { from: n, to: n };
        }
        const parts = str.startsWith('-')
            ? str.slice(1).split('-').map((p, i) => (i === 0 ? '-' + p : p))
            : str.split('-');
        if (parts.length < 2) return null;
        const left = Number(parts[0]);
        const right = Number(parts.slice(1).join('-'));
        if (!Number.isFinite(left) || !Number.isFinite(right)) return null;
        return left > right ? { from: right, to: left } : { from: left, to: right };
    }

    // True while xmux still sits exactly on the stock set, which is what keeps
    // it out of the share link for an inbound nobody has touched.
    static isStockXmux(xmux) {
        if (!xmux || typeof xmux !== 'object') return true;
        const keys = Object.keys(xmux);
        if (keys.length !== Object.keys(XHTTP_XMUX_DEFAULTS).length) return false;
        return keys.every(k => XHTTP_XMUX_DEFAULTS[k] === xmux[k]);
    }

    // downloadSettings is only meaningful as a non-empty JSON object. A null, an
    // array or an empty object all mean "not set", and the key then has to be
    // omitted entirely rather than emitted empty: xray builds a whole
    // StreamConfig out of whatever is there, and an empty one is not the same
    // thing as none.
    static normalizeDownloadSettings(value) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
        return Object.keys(value).length > 0 ? value : undefined;
    }

    // The textarea buffer for downloadSettings. Defined on the prototype rather
    // than as an own field so Vue's observer leaves it alone; it reads and
    // writes the reactive own fields underneath, so the binding stays live.
    get downloadSettingsText() {
        return this.downloadSettingsRaw;
    }

    set downloadSettingsText(text) {
        this.downloadSettingsRaw = typeof text === 'string' ? text : '';
        const trimmed = this.downloadSettingsRaw.trim();
        if (trimmed === '') {
            this.downloadSettings = undefined;
            this.downloadSettingsError = '';
            return;
        }
        try {
            const parsed = JSON.parse(trimmed);
            const normalized = xHTTPStreamSettings.normalizeDownloadSettings(parsed);
            if (normalized === undefined) throw new Error('expected a non-empty JSON object');
            this.downloadSettings = normalized;
            this.downloadSettingsError = '';
        } catch (e) {
            // Drop the value rather than keep a stale parse that no longer
            // matches what is on screen. Saving is blocked for as long as the
            // error is set (modalFormValid in
            // web/html/modals/inbound_modal.html), so the admin is told about it
            // instead of quietly losing the block.
            this.downloadSettings = undefined;
            this.downloadSettingsError = e && e.message ? e.message : String(e);
        }
    }

    clearDownloadSettings() {
        this.downloadSettingsText = '';
    }

    static fromJson(json = {}) {
        // Everything the structured fields don't own is kept verbatim.
        const extra = {};
        Object.keys(json).forEach(k => {
            if (!xHTTPStreamSettings.STRUCTURED_KEYS.has(k)) extra[k] = json[k];
        });
        return new xHTTPStreamSettings(
            json.path,
            json.host,
            XrayCommonClass.toHeaders(json.headers),
            json.scMaxBufferedPosts,
            json.scMaxEachPostBytes,
            json.scStreamUpServerSecs,
            json.noSSEHeader,
            json.xPaddingBytes,
            json.mode,
            json.xPaddingObfsMode,
            json.xPaddingKey,
            json.xPaddingHeader,
            json.xPaddingPlacement,
            json.xPaddingMethod,
            json.uplinkHTTPMethod,
            json.sessionPlacement,
            json.sessionKey,
            json.seqPlacement,
            json.seqKey,
            json.uplinkDataPlacement,
            json.uplinkDataKey,
            json.uplinkChunkSize,
            json.noGRPCHeader,
            json.scMinPostsIntervalMs,
            json.serverMaxHeaderBytes,
            json.xmux,
            json.downloadSettings,
            extra,
        );
    }

    toJson() {
        // Start from the preserved passthrough so unmodeled keys survive; the
        // structured fields below then overwrite their own keys. For an xhttp
        // object that only uses modeled keys `extra` is empty, so the output
        // stays byte-identical to what this returned before.
        const o = Object.assign({}, this.extra, {
            path: this.path,
            host: this.host,
            headers: XrayCommonClass.toV2Headers(this.headers, false),
            scMaxBufferedPosts: this.scMaxBufferedPosts,
            scMaxEachPostBytes: this.scMaxEachPostBytes,
            scStreamUpServerSecs: this.scStreamUpServerSecs,
            noSSEHeader: this.noSSEHeader,
            xPaddingBytes: this.xPaddingBytes,
            mode: this.mode,
            xPaddingObfsMode: this.xPaddingObfsMode,
            xPaddingKey: this.xPaddingKey,
            xPaddingHeader: this.xPaddingHeader,
            xPaddingPlacement: this.xPaddingPlacement,
            xPaddingMethod: this.xPaddingMethod,
            uplinkHTTPMethod: this.uplinkHTTPMethod,
            sessionPlacement: this.sessionPlacement,
            sessionKey: this.sessionKey,
            seqPlacement: this.seqPlacement,
            seqKey: this.seqKey,
            uplinkDataPlacement: this.uplinkDataPlacement,
            uplinkDataKey: this.uplinkDataKey,
            uplinkChunkSize: this.uplinkChunkSize,
            noGRPCHeader: this.noGRPCHeader,
            // Spread the live xmux so any sub-key beyond the six the form knows
            // about (a newer core's, a hand edit) rides along instead of being
            // flattened away. Same treatment as the outbound form.
            xmux: Object.assign({}, this.xmux),
        });
        // The remaining three only go in when they carry a real value, because
        // for all three "absent" is what selects the core's own behaviour:
        // scMinPostsIntervalMs falls back to its default when the range is zero,
        // serverMaxHeaderBytes falls back when it is not positive, and
        // downloadSettings is a pointer whose absence is what says "use this
        // transport for the downlink too". Omitting is therefore exactly what an
        // emptied control should mean, and it keeps the stored blob smaller.
        if (typeof this.scMinPostsIntervalMs === 'string' && this.scMinPostsIntervalMs !== '') {
            o.scMinPostsIntervalMs = this.scMinPostsIntervalMs;
        } else if (typeof this.scMinPostsIntervalMs === 'number' && Number.isFinite(this.scMinPostsIntervalMs)) {
            o.scMinPostsIntervalMs = this.scMinPostsIntervalMs;
        }
        if (Number.isFinite(this.serverMaxHeaderBytes) && this.serverMaxHeaderBytes > 0) {
            o.serverMaxHeaderBytes = this.serverMaxHeaderBytes;
        }
        // stream-one is the one mode where the core refuses downloadSettings
        // outright (transport_internet.go: `Can not use "downloadSettings" in
        // "stream-one" mode.`), and it refuses the whole config, not just the
        // key. The form blocks saving that combination, but drop it here too so
        // an inbound whose mode was changed elsewhere can never emit a blob that
        // stops xray from starting.
        const download = xHTTPStreamSettings.normalizeDownloadSettings(this.downloadSettings);
        if (download && this.mode !== MODE_OPTION.STREAM_ONE) {
            o.downloadSettings = download;
        }
        return o;
    }
}
// Keys the structured constructor/toJson own; everything else is preserved
// verbatim in `extra` so any xhttp object shape round-trips losslessly.
// Mirrored on the Go side by xhttpModeledKeys in sub/subService.go.
xHTTPStreamSettings.STRUCTURED_KEYS = new Set([
    'path', 'host', 'headers', 'scMaxBufferedPosts', 'scMaxEachPostBytes',
    'scStreamUpServerSecs', 'noSSEHeader', 'xPaddingBytes', 'mode',
    'xPaddingObfsMode', 'xPaddingKey', 'xPaddingHeader', 'xPaddingPlacement',
    'xPaddingMethod', 'uplinkHTTPMethod', 'sessionPlacement', 'sessionKey',
    'seqPlacement', 'seqKey', 'uplinkDataPlacement', 'uplinkDataKey',
    'uplinkChunkSize', 'noGRPCHeader', 'scMinPostsIntervalMs',
    'serverMaxHeaderBytes', 'xmux', 'downloadSettings',
]);

class HysteriaStreamSettings extends XrayCommonClass {
    constructor(
        protocol,
        version = 2,
        auth = '',
        udpIdleTimeout = 60,
        masquerade,
    ) {
        super(protocol);
        this.version = version;
        this.auth = auth;
        this.udpIdleTimeout = udpIdleTimeout;
        this.masquerade = masquerade;
    }

    static fromJson(json = {}) {
        return new HysteriaStreamSettings(
            json.protocol,
            json.version ?? 2,
            json.auth ?? '',
            json.udpIdleTimeout ?? 60,
            json.masquerade ? HysteriaMasquerade.fromJson(json.masquerade) : undefined,
        );
    }

    toJson() {
        return {
            protocol: this.protocol,
            version: this.version,
            auth: this.auth,
            udpIdleTimeout: this.udpIdleTimeout,
            masquerade: this.masqueradeSwitch ? this.masquerade.toJson() : undefined,
        };
    }

    get masqueradeSwitch() {
        return this.masquerade != undefined;
    }

    set masqueradeSwitch(value) {
        this.masquerade = value ? new HysteriaMasquerade() : undefined;
    }
};

class HysteriaMasquerade extends XrayCommonClass {
    constructor(
        type = 'proxy',
        dir = '',
        url = '',
        rewriteHost = false,
        insecure = false,
        content = '',
        headers = [],
        statusCode = 0,
    ) {
        super();
        this.type = type;
        this.dir = dir;
        this.url = url;
        this.rewriteHost = rewriteHost;
        this.insecure = insecure;
        this.content = content;
        this.headers = headers;
        this.statusCode = statusCode;
    }

    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }

    removeHeader(index) {
        this.headers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new HysteriaMasquerade(
            json.type,
            json.dir,
            json.url,
            json.rewriteHost,
            json.insecure,
            json.content,
            XrayCommonClass.toHeaders(json.headers),
            json.statusCode,
        );
    }

    toJson() {
        return {
            type: this.type,
            dir: this.dir,
            url: this.url,
            rewriteHost: this.rewriteHost,
            insecure: this.insecure,
            content: this.content,
            headers: XrayCommonClass.toV2Headers(this.headers, false),
            statusCode: this.statusCode,
        };
    }
};
class TlsStreamSettings extends XrayCommonClass {
    constructor(
        serverName = '',
        minVersion = TLS_VERSION_OPTION.TLS12,
        maxVersion = TLS_VERSION_OPTION.TLS13,
        cipherSuites = '',
        rejectUnknownSni = false,
        disableSystemRoot = false,
        enableSessionResumption = false,
        certificates = [new TlsStreamSettings.Cert()],
        alpn = [ALPN_OPTION.H2, ALPN_OPTION.HTTP1],
        echServerKeys = '',
        echForceQuery = 'none',
        settings = new TlsStreamSettings.Settings()
    ) {
        super();
        this.sni = serverName;
        this.minVersion = minVersion;
        this.maxVersion = maxVersion;
        this.cipherSuites = cipherSuites;
        this.rejectUnknownSni = rejectUnknownSni;
        this.disableSystemRoot = disableSystemRoot;
        this.enableSessionResumption = enableSessionResumption;
        this.certs = certificates;
        this.alpn = alpn;
        this.echServerKeys = echServerKeys;
        this.echForceQuery = echForceQuery;
        this.settings = settings;
    }

    addCert() {
        this.certs.push(new TlsStreamSettings.Cert());
    }

    removeCert(index) {
        this.certs.splice(index, 1);
    }

    static fromJson(json = {}) {
        let certs;
        let settings;
        if (!ObjectUtil.isEmpty(json.certificates)) {
            certs = json.certificates.map(cert => TlsStreamSettings.Cert.fromJson(cert));
        }

        if (!ObjectUtil.isEmpty(json.settings)) {
            settings = new TlsStreamSettings.Settings(json.settings.fingerprint, json.settings.echConfigList);
        }
        return new TlsStreamSettings(
            json.serverName,
            json.minVersion,
            json.maxVersion,
            json.cipherSuites,
            json.rejectUnknownSni,
            json.disableSystemRoot,
            json.enableSessionResumption,
            certs,
            json.alpn,
            json.echServerKeys,
            json.echForceQuery,
            settings,
        );
    }

    toJson() {
        return {
            serverName: this.sni,
            minVersion: this.minVersion,
            maxVersion: this.maxVersion,
            cipherSuites: this.cipherSuites,
            rejectUnknownSni: this.rejectUnknownSni,
            disableSystemRoot: this.disableSystemRoot,
            enableSessionResumption: this.enableSessionResumption,
            certificates: TlsStreamSettings.toJsonArray(this.certs),
            alpn: this.alpn,
            echServerKeys: this.echServerKeys,
            echForceQuery: this.echForceQuery,
            settings: this.settings,
        };
    }
}

TlsStreamSettings.Cert = class extends XrayCommonClass {
    constructor(
        useFile = true,
        certificateFile = '',
        keyFile = '',
        certificate = '',
        key = '',
        oneTimeLoading = false,
        usage = USAGE_OPTION.ENCIPHERMENT,
        buildChain = false,
    ) {
        super();
        this.useFile = useFile;
        this.certFile = certificateFile;
        this.keyFile = keyFile;
        this.cert = Array.isArray(certificate) ? certificate.join('\n') : certificate;
        this.key = Array.isArray(key) ? key.join('\n') : key;
        this.oneTimeLoading = oneTimeLoading;
        this.usage = usage;
        this.buildChain = buildChain
    }

    static fromJson(json = {}) {
        if ('certificateFile' in json && 'keyFile' in json) {
            return new TlsStreamSettings.Cert(
                true,
                json.certificateFile,
                json.keyFile, '', '',
                json.oneTimeLoading,
                json.usage,
                json.buildChain,
            );
        } else {
            return new TlsStreamSettings.Cert(
                false, '', '',
                json.certificate.join('\n'),
                json.key.join('\n'),
                json.oneTimeLoading,
                json.usage,
                json.buildChain,
            );
        }
    }

    toJson() {
        if (this.useFile) {
            return {
                certificateFile: this.certFile,
                keyFile: this.keyFile,
                oneTimeLoading: this.oneTimeLoading,
                usage: this.usage,
                buildChain: this.buildChain,
            };
        } else {
            return {
                certificate: this.cert.split('\n'),
                key: this.key.split('\n'),
                oneTimeLoading: this.oneTimeLoading,
                usage: this.usage,
                buildChain: this.buildChain,
            };
        }
    }
};

TlsStreamSettings.Settings = class extends XrayCommonClass {
    constructor(
        fingerprint = UTLS_FINGERPRINT.UTLS_CHROME,
        echConfigList = '',
    ) {
        super();
        this.fingerprint = fingerprint;
        this.echConfigList = echConfigList;
    }
    static fromJson(json = {}) {
        return new TlsStreamSettings.Settings(
            json.fingerprint,
            json.echConfigList,
        );
    }
    toJson() {
        return {
            fingerprint: this.fingerprint,
            echConfigList: this.echConfigList
        };
    }
};


class RealityStreamSettings extends XrayCommonClass {
    constructor(
        show = false,
        xver = 0,
        target = '',
        serverNames = '',
        privateKey = '',
        minClientVer = '',
        maxClientVer = '',
        maxTimediff = 0,
        shortIds = RandomUtil.randomShortIds(),
        mldsa65Seed = '',
        settings = new RealityStreamSettings.Settings()
    ) {
        super();
        // If target/serverNames are not provided, use random values
        if (!target && !serverNames) {
            const randomTarget = typeof getRandomRealityTarget !== 'undefined'
                ? getRandomRealityTarget()
                : { target: 'www.apple.com:443', sni: 'www.apple.com,apple.com' };
            target = randomTarget.target;
            serverNames = randomTarget.sni;
        }
        this.show = show;
        this.xver = xver;
        this.target = target;
        this.serverNames = Array.isArray(serverNames) ? serverNames.join(",") : serverNames;
        this.privateKey = privateKey;
        this.minClientVer = minClientVer;
        this.maxClientVer = maxClientVer;
        this.maxTimediff = maxTimediff;
        this.shortIds = Array.isArray(shortIds) ? shortIds.join(",") : shortIds;
        this.mldsa65Seed = mldsa65Seed;
        this.settings = settings;
    }

    static fromJson(json = {}) {
        let settings;
        if (!ObjectUtil.isEmpty(json.settings)) {
            settings = new RealityStreamSettings.Settings(
                json.settings.publicKey,
                json.settings.fingerprint,
                json.settings.serverName,
                json.settings.spiderX,
                json.settings.mldsa65Verify,
            );
        }
        return new RealityStreamSettings(
            json.show,
            json.xver,
            json.target,
            json.serverNames,
            json.privateKey,
            json.minClientVer,
            json.maxClientVer,
            json.maxTimediff,
            json.shortIds,
            json.mldsa65Seed,
            settings,
        );
    }

    toJson() {
        return {
            show: this.show,
            xver: this.xver,
            target: this.target,
            serverNames: this.serverNames.split(","),
            privateKey: this.privateKey,
            minClientVer: this.minClientVer,
            maxClientVer: this.maxClientVer,
            maxTimediff: this.maxTimediff,
            shortIds: this.shortIds.split(","),
            mldsa65Seed: this.mldsa65Seed,
            settings: this.settings,
        };
    }
}

RealityStreamSettings.Settings = class extends XrayCommonClass {
    constructor(
        publicKey = '',
        fingerprint = UTLS_FINGERPRINT.UTLS_CHROME,
        serverName = '',
        spiderX = '/',
        mldsa65Verify = ''
    ) {
        super();
        this.publicKey = publicKey;
        this.fingerprint = fingerprint;
        this.serverName = serverName;
        this.spiderX = spiderX;
        this.mldsa65Verify = mldsa65Verify;
    }
    static fromJson(json = {}) {
        return new RealityStreamSettings.Settings(
            json.publicKey,
            json.fingerprint,
            json.serverName,
            json.spiderX,
            json.mldsa65Verify
        );
    }
    toJson() {
        return {
            publicKey: this.publicKey,
            fingerprint: this.fingerprint,
            serverName: this.serverName,
            spiderX: this.spiderX,
            mldsa65Verify: this.mldsa65Verify
        };
    }
};

class SockoptStreamSettings extends XrayCommonClass {
    constructor(
        acceptProxyProtocol = false,
        tcpFastOpen = false,
        mark = 0,
        tproxy = "off",
        tcpMptcp = false,
        penetrate = false,
        domainStrategy = DOMAIN_STRATEGY_OPTION.USE_IP,
        tcpMaxSeg = 1440,
        dialerProxy = "",
        tcpKeepAliveInterval = 0,
        tcpKeepAliveIdle = 300,
        tcpUserTimeout = 10000,
        tcpcongestion = TCP_CONGESTION_OPTION.BBR,
        V6Only = false,
        tcpWindowClamp = 600,
        interfaceName = "",
        trustedXForwardedFor = [],
    ) {
        super();
        this.acceptProxyProtocol = acceptProxyProtocol;
        this.tcpFastOpen = tcpFastOpen;
        this.mark = mark;
        this.tproxy = tproxy;
        this.tcpMptcp = tcpMptcp;
        this.penetrate = penetrate;
        this.domainStrategy = domainStrategy;
        this.tcpMaxSeg = tcpMaxSeg;
        this.dialerProxy = dialerProxy;
        this.tcpKeepAliveInterval = tcpKeepAliveInterval;
        this.tcpKeepAliveIdle = tcpKeepAliveIdle;
        this.tcpUserTimeout = tcpUserTimeout;
        this.tcpcongestion = tcpcongestion;
        this.V6Only = V6Only;
        this.tcpWindowClamp = tcpWindowClamp;
        this.interfaceName = interfaceName;
        this.trustedXForwardedFor = trustedXForwardedFor;
    }

    static fromJson(json = {}) {
        if (Object.keys(json).length === 0) return undefined;
        return new SockoptStreamSettings(
            json.acceptProxyProtocol,
            json.tcpFastOpen,
            json.mark,
            json.tproxy,
            json.tcpMptcp,
            json.penetrate,
            json.domainStrategy,
            json.tcpMaxSeg,
            json.dialerProxy,
            json.tcpKeepAliveInterval,
            json.tcpKeepAliveIdle,
            json.tcpUserTimeout,
            json.tcpcongestion,
            json.V6Only,
            json.tcpWindowClamp,
            json.interface,
            json.trustedXForwardedFor || [],
        );
    }

    toJson() {
        const result = {
            acceptProxyProtocol: this.acceptProxyProtocol,
            tcpFastOpen: this.tcpFastOpen,
            mark: this.mark,
            tproxy: this.tproxy,
            tcpMptcp: this.tcpMptcp,
            penetrate: this.penetrate,
            domainStrategy: this.domainStrategy,
            tcpMaxSeg: this.tcpMaxSeg,
            dialerProxy: this.dialerProxy,
            tcpKeepAliveInterval: this.tcpKeepAliveInterval,
            tcpKeepAliveIdle: this.tcpKeepAliveIdle,
            tcpUserTimeout: this.tcpUserTimeout,
            tcpcongestion: this.tcpcongestion,
            V6Only: this.V6Only,
            tcpWindowClamp: this.tcpWindowClamp,
            interface: this.interfaceName,
        };
        if (this.trustedXForwardedFor && this.trustedXForwardedFor.length > 0) {
            result.trustedXForwardedFor = this.trustedXForwardedFor;
        }
        return result;
    }
}

class UdpMask extends XrayCommonClass {
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
                return { domains: Array.isArray(settings.domains) ? settings.domains : [] };
            case 'xicmp':
                return { ip: settings.ip || '', id: settings.id ?? 0 };
            case 'mkcp-original':
            case 'header-dtls':
            case 'header-srtp':
            case 'header-utp':
            case 'header-wechat':
            case 'header-wireguard':
                return {};
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

class TcpMask extends XrayCommonClass {
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

class QuicParams extends XrayCommonClass {
    constructor(
        congestion = 'bbr',
        debug = false,
        brutalUp = '',
        brutalDown = '',
        udpHop = undefined,
        initStreamReceiveWindow = 8388608,
        maxStreamReceiveWindow = 8388608,
        initConnectionReceiveWindow = 20971520,
        maxConnectionReceiveWindow = 20971520,
        maxIdleTimeout = 30,
        keepAlivePeriod = 0,
        disablePathMTUDiscovery = false,
        maxIncomingStreams = 1024,
    ) {
        super();
        this.congestion = congestion;
        this.debug = debug;
        this.brutalUp = brutalUp;
        this.brutalDown = brutalDown;
        this.udpHop = udpHop;
        this.initStreamReceiveWindow = initStreamReceiveWindow;
        this.maxStreamReceiveWindow = maxStreamReceiveWindow;
        this.initConnectionReceiveWindow = initConnectionReceiveWindow;
        this.maxConnectionReceiveWindow = maxConnectionReceiveWindow;
        this.maxIdleTimeout = maxIdleTimeout;
        this.keepAlivePeriod = keepAlivePeriod;
        this.disablePathMTUDiscovery = disablePathMTUDiscovery;
        this.maxIncomingStreams = maxIncomingStreams;
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
            json.initStreamReceiveWindow,
            json.maxStreamReceiveWindow,
            json.initConnectionReceiveWindow,
            json.maxConnectionReceiveWindow,
            json.maxIdleTimeout,
            json.keepAlivePeriod,
            json.disablePathMTUDiscovery,
            json.maxIncomingStreams,
        );
    }

    toJson() {
        const result = { congestion: this.congestion };
        if (this.debug) result.debug = this.debug;
        if (this.brutalUp) result.brutalUp = this.brutalUp;
        if (this.brutalDown) result.brutalDown = this.brutalDown;
        if (this.udpHop) result.udpHop = { ports: this.udpHop.ports, interval: this.udpHop.interval };
        if (this.initStreamReceiveWindow > 0) result.initStreamReceiveWindow = this.initStreamReceiveWindow;
        if (this.maxStreamReceiveWindow > 0) result.maxStreamReceiveWindow = this.maxStreamReceiveWindow;
        if (this.initConnectionReceiveWindow > 0) result.initConnectionReceiveWindow = this.initConnectionReceiveWindow;
        if (this.maxConnectionReceiveWindow > 0) result.maxConnectionReceiveWindow = this.maxConnectionReceiveWindow;
        if (this.maxIdleTimeout !== 30 && this.maxIdleTimeout > 0) result.maxIdleTimeout = this.maxIdleTimeout;
        if (this.keepAlivePeriod > 0) result.keepAlivePeriod = this.keepAlivePeriod;
        if (this.disablePathMTUDiscovery) result.disablePathMTUDiscovery = this.disablePathMTUDiscovery;
        if (this.maxIncomingStreams > 0) result.maxIncomingStreams = this.maxIncomingStreams;
        return result;
    }
}

class FinalMaskStreamSettings extends XrayCommonClass {
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

class StreamSettings extends XrayCommonClass {
    constructor(network = 'tcp',
        security = 'none',
        externalProxy = [],
        tlsSettings = new TlsStreamSettings(),
        realitySettings = new RealityStreamSettings(),
        tcpSettings = new TcpStreamSettings(),
        kcpSettings = new KcpStreamSettings(),
        wsSettings = new WsStreamSettings(),
        grpcSettings = new GrpcStreamSettings(),
        httpupgradeSettings = new HTTPUpgradeStreamSettings(),
        xhttpSettings = new xHTTPStreamSettings(),
        hysteriaSettings = new HysteriaStreamSettings(),
        finalmask = new FinalMaskStreamSettings(),
        sockopt = undefined,
    ) {
        super();
        this.network = network;
        this.security = security;
        this.externalProxy = externalProxy;
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
        return this.security === "tls";
    }

    set isTls(isTls) {
        if (isTls) {
            this.security = 'tls';
        } else {
            this.security = 'none';
        }
    }

    //for Reality
    get isReality() {
        return this.security === "reality";
    }

    set isReality(isReality) {
        if (isReality) {
            this.security = 'reality';
        } else {
            this.security = 'none';
        }
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
            json.externalProxy,
            TlsStreamSettings.fromJson(json.tlsSettings),
            RealityStreamSettings.fromJson(json.realitySettings),
            TcpStreamSettings.fromJson(json.tcpSettings),
            KcpStreamSettings.fromJson(json.kcpSettings),
            WsStreamSettings.fromJson(json.wsSettings),
            GrpcStreamSettings.fromJson(json.grpcSettings),
            HTTPUpgradeStreamSettings.fromJson(json.httpupgradeSettings),
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
            externalProxy: this.externalProxy,
            tlsSettings: this.isTls ? this.tls.toJson() : undefined,
            realitySettings: this.isReality ? this.reality.toJson() : undefined,
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

class Sniffing extends XrayCommonClass {
    constructor(
        enabled = false,
        destOverride = ['http', 'tls', 'quic', 'fakedns'],
        metadataOnly = false,
        routeOnly = false,
        ipsExcluded = [],
        domainsExcluded = []) {
        super();
        this.enabled = enabled;
        this.destOverride = Array.isArray(destOverride) && destOverride.length > 0 ? destOverride : ['http', 'tls', 'quic', 'fakedns'];
        this.metadataOnly = metadataOnly;
        this.routeOnly = routeOnly;
        this.ipsExcluded = Array.isArray(ipsExcluded) ? ipsExcluded : [];
        this.domainsExcluded = Array.isArray(domainsExcluded) ? domainsExcluded : [];
    }

    static fromJson(json = {}) {
        let destOverride = ObjectUtil.clone(json.destOverride);
        if (ObjectUtil.isEmpty(destOverride) || ObjectUtil.isArrEmpty(destOverride) || ObjectUtil.isEmpty(destOverride[0])) {
            destOverride = ['http', 'tls', 'quic', 'fakedns'];
        }
        return new Sniffing(
            !!json.enabled,
            destOverride,
            json.metadataOnly,
            json.routeOnly,
            json.ipsExcluded || [],
            json.domainsExcluded || [],
        );
    }

    toJson() {
        return {
            enabled: this.enabled,
            destOverride: this.destOverride,
            metadataOnly: this.metadataOnly,
            routeOnly: this.routeOnly,
            ipsExcluded: this.ipsExcluded.length > 0 ? this.ipsExcluded : undefined,
            domainsExcluded: this.domainsExcluded.length > 0 ? this.domainsExcluded : undefined,
        };
    }
}

class Inbound extends XrayCommonClass {
    constructor(
        port = RandomUtil.randomInteger(10000, 60000),
        listen = '',
        protocol = Protocols.VLESS,
        settings = null,
        streamSettings = new StreamSettings(),
        tag = '',
        sniffing = new Sniffing(),
        clientStats = '',
    ) {
        super();
        this.port = port;
        this.listen = listen;
        this._protocol = protocol;
        this.settings = ObjectUtil.isEmpty(settings) ? Inbound.Settings.getSettings(protocol) : settings;
        this.stream = streamSettings;
        this.tag = tag;
        this.sniffing = sniffing;
        this.clientStats = clientStats;
    }
    getClientStats() {
        return this.clientStats;
    }

    // Gather every xhttp setting a client has to match the server on, minus
    // path / host / mode which the link already carries as its own top-level
    // params. An xhttp client that guesses any of these wrong does not
    // degrade, it fails: the wrong xPaddingBytes range alone is enough for
    // the server to reject every handshake with `invalid padding (...)
    // length: 0`, and the same goes for a session/seq/uplink placement or an
    // uplink HTTP method the two sides disagree on.
    //
    // Only what the admin actually supplied is returned. Empty strings, false
    // booleans, empty header lists and anything still sitting on its
    // XHTTP_SHARE_DEFAULTS value are skipped, so a stock inbound keeps
    // producing the same short link it produced before this existed.
    //
    // Mirrored on the Go side by collectXhttpShareFields in sub/subService.go;
    // the two generators have to agree key for key, because the panel's
    // copy-link button and the subscription URL must not hand out two
    // different configs for one inbound.
    static collectXhttpShareFields(xhttp) {
        const out = {};
        if (!xhttp) return out;

        // Unmodeled keys first so a structurally modeled key always wins if a
        // hand-edited blob somehow carries both. Insertion order only matters
        // for the VMess object; the query-string blob is emitted sorted.
        const passthrough = xhttp.extra;
        if (passthrough && typeof passthrough === 'object') {
            Object.keys(passthrough).forEach(k => {
                if (xHTTPStreamSettings.STRUCTURED_KEYS.has(k)) return;
                out[k] = passthrough[k];
            });
        }

        // xPaddingBytes is emitted even when it still holds the panel default,
        // which is what this generator has always done. Clients already in the
        // field read it, so narrowing it now would break working links.
        if (typeof xhttp.xPaddingBytes === 'string' && xhttp.xPaddingBytes.length > 0) {
            out.xPaddingBytes = xhttp.xPaddingBytes;
        }
        if (xhttp.xPaddingObfsMode === true) {
            out.xPaddingObfsMode = true;
            // Obfs-mode-only fields: only the ones the admin actually set, so
            // xray-core keeps its own defaults for the rest instead of seeing
            // spurious empty strings.
            ["xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod"].forEach(k => {
                if (typeof xhttp[k] === 'string' && xhttp[k].length > 0) {
                    out[k] = xhttp[k];
                }
            });
        }

        // The panel keeps headers as [{name, value}]; xray wants a name->value
        // map. Empty names/values are dropped by toV2Headers.
        const headers = XrayCommonClass.toV2Headers(xhttp.headers ?? [], false);
        if (Object.keys(headers).length > 0) {
            out.headers = headers;
        }
        if (xhttp.noSSEHeader === true) {
            out.noSSEHeader = true;
        }
        if (xhttp.noGRPCHeader === true) {
            out.noGRPCHeader = true;
        }

        XHTTP_SHARE_FIELDS.forEach(k => {
            const value = xhttp[k];
            if (value === undefined || value === null || value === '') return;
            if (value === XHTTP_SHARE_DEFAULTS[k]) return;
            out[k] = value;
        });

        // xmux and downloadSettings are objects, so they cannot ride in the
        // scalar loop above (it compares against its defaults by value).
        //
        // xmux goes on the wire only once the admin has moved a knob off the
        // stock set, and then it goes whole: a partial xmux would leave the
        // client filling the gaps from its own defaults, which is the exact kind
        // of silent server/client divergence this function exists to prevent.
        const xmux = xHTTPStreamSettings.normalizeXmux(xhttp.xmux);
        if (!xHTTPStreamSettings.isStockXmux(xmux)) {
            out.xmux = xmux;
        }

        // downloadSettings has no default at all, so it rides verbatim whenever
        // it is set. Except in stream-one mode, where the core rejects it
        // outright (transport_internet.go: `Can not use "downloadSettings" in
        // "stream-one" mode.`) and rejects the entire config with it. The panel
        // will not save that combination, but a blob hand-edited outside the
        // panel can still hold it, and a link that no client can build is worse
        // than a link that quietly drops one key.
        const download = xHTTPStreamSettings.normalizeDownloadSettings(xhttp.downloadSettings);
        if (download && xhttp.mode !== MODE_OPTION.STREAM_ONE) {
            out.downloadSettings = download;
        }

        return out;
    }

    // JSON with object keys sorted, recursively. Go's encoding/json always
    // writes map keys sorted, so sorting here is what keeps the panel and the
    // Go subscription generator from handing out two textually different
    // `extra=` blobs for the very same inbound.
    static stableJsonStringify(value) {
        const sort = v => {
            if (Array.isArray(v)) return v.map(sort);
            if (v && typeof v === 'object') {
                const sorted = {};
                Object.keys(v).sort().forEach(k => { sorted[k] = sort(v[k]); });
                return sorted;
            }
            return v;
        };
        return JSON.stringify(sort(value));
    }

    // Copy the xhttp settings into the query-string of a vless/trojan/ss link.
    // Two encodings are emitted so each client family can pick at least one up:
    //   - x_padding_bytes=<range>       flat, for sing-box-family clients
    //     (Podkop, OpenWRT sing-box, Karing, NekoBox) which never look inside
    //     `extra`.
    //   - extra=<url-encoded-json>      the whole xhttp object, which is how
    //     xray-core clients (v2rayNG, Happ, Furious, Exclave) pick it up.
    static applyXhttpShareParams(xhttp, params) {
        if (!xhttp) return;
        if (typeof xhttp.xPaddingBytes === 'string' && xhttp.xPaddingBytes.length > 0) {
            params.set("x_padding_bytes", xhttp.xPaddingBytes);
        }
        const extra = Inbound.collectXhttpShareFields(xhttp);
        if (Object.keys(extra).length > 0) {
            params.set("extra", Inbound.stableJsonStringify(extra));
        }
    }

    // VMess variant: VMess links are a base64-encoded JSON object, so the
    // fields go straight into that JSON instead of into a query string.
    static applyXhttpShareObj(xhttp, obj) {
        if (!xhttp || !obj) return;
        const fields = Inbound.collectXhttpShareFields(xhttp);
        Object.keys(fields).forEach(k => {
            // The padding range has always ridden along under the flat
            // sing-box style name here; keep it so clients already in the
            // field keep reading it.
            obj[k === 'xPaddingBytes' ? 'x_padding_bytes' : k] = fields[k];
        });
    }

    static hasShareableFinalMaskValue(value) {
        if (value == null) {
            return false;
        }
        if (Array.isArray(value)) {
            return value.some(item => Inbound.hasShareableFinalMaskValue(item));
        }
        if (typeof value === 'object') {
            return Object.values(value).some(item => Inbound.hasShareableFinalMaskValue(item));
        }
        if (typeof value === 'string') {
            return value.length > 0;
        }
        return true;
    }

    static serializeFinalMask(finalmask) {
        if (!finalmask) {
            return '';
        }
        const value = typeof finalmask.toJson === 'function' ? finalmask.toJson() : finalmask;
        return Inbound.hasShareableFinalMaskValue(value) ? JSON.stringify(value) : '';
    }

    // Export finalmask with the same compact JSON payload shape that
    // v2rayN-compatible share links use: fm=<json>.
    static applyFinalMaskToParams(finalmask, params) {
        if (!params) return;
        const payload = Inbound.serializeFinalMask(finalmask);
        if (payload.length > 0) {
            params.set("fm", payload);
        }
    }

    // VMess links are a base64 JSON object, so keep the same fm payload
    // under a flat property instead of a URL query string.
    static applyFinalMaskToObj(finalmask, obj) {
        if (!obj) return;
        const payload = Inbound.serializeFinalMask(finalmask);
        if (payload.length > 0) {
            obj.fm = payload;
        }
    }

    // Empties the client list without needing to know which key holds it.
    //
    // Every protocol's settings class seeds ONE client in its constructor, which
    // made "create an inbound" and "create an account" the same act. They are not
    // the same act any more: accounts are made on the Clients page, where one can
    // be put on several inbounds at once. A new inbound therefore starts empty and
    // the operator adds accounts to it afterwards.
    clearClients() {
        const list = this.clients;
        if (Array.isArray(list)) list.splice(0, list.length);
    }

    get clients() {
        switch (this.protocol) {
            case Protocols.VMESS: return this.settings.vmesses;
            case Protocols.VLESS: return this.settings.vlesses;
            case Protocols.TROJAN: return this.settings.trojans;
            case Protocols.SHADOWSOCKS: return this.isSSMultiUser ? this.settings.shadowsockses : null;
            case Protocols.HYSTERIA: return this.settings.hysterias;
            case Protocols.ANYTLS: return this.settings.anytlses;
            case Protocols.TUIC: return this.settings.tuics;
            case Protocols.NAIVE: return this.settings.naives;
            case Protocols.L2TP: return this.settings.l2tpUsers;
            case Protocols.PPTP: return this.settings.pptpUsers;
            case Protocols.OPENVPN: return this.settings.openvpnUsers;
            case Protocols.OPENCONNECT: return this.settings.ocservUsers;
            case Protocols.SSTP: return this.settings.sstpUsers;
            case Protocols.IKEV2: return this.settings.ikev2Users;
            case Protocols.WGC: return this.settings.wgcUsers;
            case Protocols.AWG: return this.settings.awgUsers;
            case Protocols.GRE: return this.settings.greUsers;
            case Protocols.MTPROTO: return this.settings.mtprotoUsers;
            case Protocols.SSH: return this.settings.sshUsers;
            default: return null;
        }
    }

    get protocol() {
        return this._protocol;
    }

    set protocol(protocol) {
        this._protocol = protocol;
        this.settings = Inbound.Settings.getSettings(protocol);
        // getSettings builds a fresh settings object and every settings class seeds
        // ONE client in its constructor, so picking a protocol puts an account back
        // even when the form deliberately started empty. startEmpty is set by the
        // add-inbound form and by nothing else: on an EDIT the inbound already has
        // accounts and clearing them here would drop them without saying so.
        if (this.startEmpty) this.clearClients();
        this.stream = new StreamSettings();
        if (protocol === Protocols.TROJAN) {
            this.tls = false;
        }
        if (protocol === Protocols.HYSTERIA) {
            this.stream.network = 'hysteria';
            this.stream.security = 'tls';
            // Hysteria runs over QUIC and must not inherit TCP TLS ALPN defaults.
            this.stream.tls.alpn = [ALPN_OPTION.H3];
        }
        if (protocol === Protocols.TUIC) {
            // TUIC carries its own QUIC transport, the same shape as Hysteria: the
            // network is fixed and TLS is not optional. The ALPN is pinned to h3
            // because the server forces it, and a client that negotiates anything
            // else is refused with an opaque "no application protocol" TLS alert.
            this.stream.network = 'tuic';
            this.stream.security = 'tls';
            this.stream.tls.alpn = [ALPN_OPTION.H3];
        }
        if (protocol === Protocols.ANYTLS || protocol === Protocols.NAIVE) {
            // Both are TLS-only over a plain stream: AnyTLS is a TLS-shaped session
            // multiplexer, naive is HTTP/2 over TLS. Neither has a cleartext mode,
            // so the switch starts on rather than leaving a new inbound listening
            // in the clear until someone notices.
            this.stream.security = 'tls';
        }
    }

    get network() {
        return this.stream.network;
    }

    set network(network) {
        this.stream.network = network;
    }

    get isTcp() {
        return this.network === "tcp";
    }

    get isWs() {
        return this.network === "ws";
    }

    get isKcp() {
        return this.network === "kcp";
    }

    get isGrpc() {
        return this.network === "grpc";
    }

    get isHttpupgrade() {
        return this.network === "httpupgrade";
    }

    get isXHTTP() {
        return this.network === "xhttp";
    }

    // Shadowsocks
    get method() {
        switch (this.protocol) {
            case Protocols.SHADOWSOCKS:
                return this.settings.method;
            default:
                return "";
        }
    }
    get isSSMultiUser() {
        return this.method != SSMethods.BLAKE3_CHACHA20_POLY1305;
    }
    get isSS2022() {
        return this.method.substring(0, 4) === "2022";
    }

    get serverName() {
        if (this.stream.isTls) return this.stream.tls.sni;
        if (this.stream.isReality) return this.stream.reality.serverNames;
        return "";
    }

    getHeader(obj, name) {
        for (const header of obj.headers) {
            if (header.name.toLowerCase() === name.toLowerCase()) {
                return header.value;
            }
        }
        return "";
    }

    get host() {
        if (this.isTcp) {
            return this.getHeader(this.stream.tcp.request, 'host');
        } else if (this.isWs) {
            return this.stream.ws.host?.length > 0 ? this.stream.ws.host : this.getHeader(this.stream.ws, 'host');
        } else if (this.isHttpupgrade) {
            return this.stream.httpupgrade.host?.length > 0 ? this.stream.httpupgrade.host : this.getHeader(this.stream.httpupgrade, 'host');
        } else if (this.isXHTTP) {
            return this.stream.xhttp.host?.length > 0 ? this.stream.xhttp.host : this.getHeader(this.stream.xhttp, 'host');
        }
        return null;
    }

    get path() {
        if (this.isTcp) {
            return this.stream.tcp.request.path[0];
        } else if (this.isWs) {
            return this.stream.ws.path;
        } else if (this.isHttpupgrade) {
            return this.stream.httpupgrade.path;
        } else if (this.isXHTTP) {
            return this.stream.xhttp.path;
        }
        return null;
    }

    get serviceName() {
        return this.stream.grpc.serviceName;
    }

    isExpiry(index) {
        let exp = this.clients[index].expiryTime;
        return exp > 0 ? exp < new Date().getTime() : false;
    }

    canEnableTls() {
        if (this.protocol === Protocols.HYSTERIA) return true;
        // TUIC's TLS lives under its own transport, not under one of the stream
        // networks listed below, so it is always available (and mandatory).
        if (this.protocol === Protocols.TUIC) return true;
        // AnyTLS and naive ride the standard stream TLS, so they fall through to
        // the transport check: both are stream protocols and both need it.
        if (![Protocols.VMESS, Protocols.VLESS, Protocols.TROJAN, Protocols.SHADOWSOCKS,
            Protocols.ANYTLS, Protocols.NAIVE].includes(this.protocol)) return false;
        return ["tcp", "ws", "http", "grpc", "httpupgrade", "xhttp"].includes(this.network);
    }

    // Protocols whose transport IS TLS, so "no TLS" is not a state they can hold.
    // Both run over QUIC, and QUIC's handshake is TLS 1.3 (RFC 9001): no plaintext
    // QUIC wire format exists, so security 'none' on either describes nothing the
    // core could be running. The security picker is hidden for exactly this set in
    // web/html/form/tls_settings.html, so gate on this rather than restating the pair.
    //
    // Deliberately NOT anytls or naive. They are as TLS-dependent in practice but run
    // over TCP, where 'none' is a real TLS-offload deployment (a terminator in front
    // forwarding plaintext to a local port), so they keep the choice and warn instead.
    static protocolRequiresTls(protocol) {
        return [Protocols.HYSTERIA, Protocols.TUIC].includes(protocol);
    }

    requiresTls() {
        return Inbound.protocolRequiresTls(this.protocol);
    }

    //this is used for xtls-rprx-vision
    canEnableTlsFlow() {
        if (((this.stream.security === 'tls') || (this.stream.security === 'reality')) && (this.network === "tcp")) {
            return this.protocol === Protocols.VLESS;
        }
        return false;
    }

    // Vision seed applies only when vision flow is selected
    canEnableVisionSeed() {
        if (!this.canEnableTlsFlow()) return false;
        const clients = this.settings?.vlesses;
        if (!Array.isArray(clients)) return false;
        return clients.some(c => c?.flow === TLS_FLOW_CONTROL.VISION || c?.flow === TLS_FLOW_CONTROL.VISION_UDP443);
    }

    // AnyTLS belongs here and naive/tuic do not: REALITY is transport-layer, so it
    // works under any stream protocol, but it only helps if the CLIENT speaks it.
    // sing-box's anytls outbound does; every naive client does plain TLS only, and
    // tuic is QUIC, which REALITY does not cover.
    canEnableReality() {
        if (![Protocols.VLESS, Protocols.TROJAN, Protocols.ANYTLS].includes(this.protocol)) return false;
        return ["tcp", "http", "grpc", "xhttp"].includes(this.network);
    }

    // Whether toJson() emits streamSettings AT ALL. A protocol missing from this list
    // silently ships an inbound with no transport and no TLS block, which for a
    // TLS-only protocol means a listener nothing can ever connect to.
    canEnableStream() {
        return [Protocols.VMESS, Protocols.VLESS, Protocols.TROJAN, Protocols.SHADOWSOCKS, Protocols.HYSTERIA,
            Protocols.ANYTLS, Protocols.TUIC, Protocols.NAIVE].includes(this.protocol);
    }

    reset() {
        this.port = RandomUtil.randomInteger(10000, 60000);
        this.listen = '';
        this.protocol = Protocols.VMESS;
        this.settings = Inbound.Settings.getSettings(Protocols.VMESS);
        this.stream = new StreamSettings();
        this.tag = '';
        this.sniffing = new Sniffing();
    }

    genVmessLink(address = '', port = this.port, forceTls, remark = '', clientId, security) {
        if (this.protocol !== Protocols.VMESS) {
            return '';
        }
        const tls = forceTls == 'same' ? this.stream.security : forceTls;
        let obj = {
            v: '2',
            ps: remark,
            add: address,
            port: port,
            id: clientId,
            scy: security,
            net: this.stream.network,
            tls: tls,
        };
        const network = this.stream.network;
        if (network === 'tcp') {
            const tcp = this.stream.tcp;
            obj.type = tcp.type;
            if (tcp.type === 'http') {
                const request = tcp.request;
                obj.path = request.path.join(',');
                const host = this.getHeader(request, 'host');
                if (host) obj.host = host;
            }
        } else if (network === 'kcp') {
            const kcp = this.stream.kcp;
            obj.mtu = kcp.mtu;
            obj.tti = kcp.tti;
        } else if (network === 'ws') {
            const ws = this.stream.ws;
            obj.path = ws.path;
            obj.host = ws.host?.length > 0 ? ws.host : this.getHeader(ws, 'host');
        } else if (network === 'grpc') {
            obj.path = this.stream.grpc.serviceName;
            obj.authority = this.stream.grpc.authority;
            if (this.stream.grpc.multiMode) {
                obj.type = 'multi'
            }
        } else if (network === 'httpupgrade') {
            const httpupgrade = this.stream.httpupgrade;
            obj.path = httpupgrade.path;
            obj.host = httpupgrade.host?.length > 0 ? httpupgrade.host : this.getHeader(httpupgrade, 'host');
        } else if (network === 'xhttp') {
            const xhttp = this.stream.xhttp;
            obj.path = xhttp.path;
            obj.host = xhttp.host?.length > 0 ? xhttp.host : this.getHeader(xhttp, 'host');
            // The mode goes out under both names on purpose. This generator has
            // always written it as `type` (where v2rayN-family clients read the
            // per-network sub-type), the Go subscription generator has always
            // written it as `mode`, and our own vmess importer
            // (Outbound.fromVmessLink) only reads `mode`. Emitting both is the
            // union of the two shipped behaviours, so the panel link and the
            // subscription link finally agree without regressing either client.
            obj.type = xhttp.mode;
            obj.mode = xhttp.mode;
            Inbound.applyXhttpShareObj(xhttp, obj);
        }

        Inbound.applyFinalMaskToObj(this.stream.finalmask, obj);

        if (tls === 'tls') {
            if (!ObjectUtil.isEmpty(this.stream.tls.sni)) {
                obj.sni = this.stream.tls.sni;
            }
            if (!ObjectUtil.isEmpty(this.stream.tls.settings.fingerprint)) {
                obj.fp = this.stream.tls.settings.fingerprint;
            }
            if (this.stream.tls.alpn.length > 0) {
                obj.alpn = this.stream.tls.alpn.join(',');
            }
        }

        return 'vmess://' + Base64.encode(JSON.stringify(obj, null, 2));
    }

    genVLESSLink(address = '', port = this.port, forceTls, remark = '', clientId, flow) {
        const uuid = clientId;
        const type = this.stream.network;
        const security = forceTls == 'same' ? this.stream.security : forceTls;
        const params = new Map();
        params.set("type", this.stream.network);
        params.set("encryption", this.settings.encryption);
        switch (type) {
            case "tcp":
                const tcp = this.stream.tcp;
                if (tcp.type === 'http') {
                    const request = tcp.request;
                    params.set("path", request.path.join(','));
                    const index = request.headers.findIndex(header => header.name.toLowerCase() === 'host');
                    if (index >= 0) {
                        const host = request.headers[index].value;
                        params.set("host", host);
                    }
                    params.set("headerType", 'http');
                }
                break;
            case "kcp":
                const kcp = this.stream.kcp;
                params.set("mtu", kcp.mtu);
                params.set("tti", kcp.tti);
                break;
            case "ws":
                const ws = this.stream.ws;
                params.set("path", ws.path);
                params.set("host", ws.host?.length > 0 ? ws.host : this.getHeader(ws, 'host'));
                break;
            case "grpc":
                const grpc = this.stream.grpc;
                params.set("serviceName", grpc.serviceName);
                params.set("authority", grpc.authority);
                if (grpc.multiMode) {
                    params.set("mode", "multi");
                }
                break;
            case "httpupgrade":
                const httpupgrade = this.stream.httpupgrade;
                params.set("path", httpupgrade.path);
                params.set("host", httpupgrade.host?.length > 0 ? httpupgrade.host : this.getHeader(httpupgrade, 'host'));
                break;
            case "xhttp":
                const xhttp = this.stream.xhttp;
                params.set("path", xhttp.path);
                params.set("host", xhttp.host?.length > 0 ? xhttp.host : this.getHeader(xhttp, 'host'));
                params.set("mode", xhttp.mode);
                Inbound.applyXhttpShareParams(xhttp, params);
                break;
        }

        Inbound.applyFinalMaskToParams(this.stream.finalmask, params);

        if (security === 'tls') {
            params.set("security", "tls");
            if (this.stream.isTls) {
                params.set("fp", this.stream.tls.settings.fingerprint);
                params.set("alpn", this.stream.tls.alpn);
                if (!ObjectUtil.isEmpty(this.stream.tls.sni)) {
                    params.set("sni", this.stream.tls.sni);
                }
                if (this.stream.tls.settings.echConfigList?.length > 0) {
                    params.set("ech", this.stream.tls.settings.echConfigList);
                }
                if (type == "tcp" && !ObjectUtil.isEmpty(flow)) {
                    params.set("flow", flow);
                }
            }
        }

        else if (security === 'reality') {
            params.set("security", "reality");
            params.set("pbk", this.stream.reality.settings.publicKey);
            params.set("fp", this.stream.reality.settings.fingerprint);
            if (!ObjectUtil.isArrEmpty(this.stream.reality.serverNames)) {
                params.set("sni", this.stream.reality.serverNames.split(",")[0]);
            }
            if (this.stream.reality.shortIds.length > 0) {
                params.set("sid", this.stream.reality.shortIds.split(",")[0]);
            }
            if (!ObjectUtil.isEmpty(this.stream.reality.settings.spiderX)) {
                params.set("spx", this.stream.reality.settings.spiderX);
            }
            if (!ObjectUtil.isEmpty(this.stream.reality.settings.mldsa65Verify)) {
                params.set("pqv", this.stream.reality.settings.mldsa65Verify);
            }
            if (type == 'tcp' && !ObjectUtil.isEmpty(flow)) {
                params.set("flow", flow);
            }
        }

        else {
            params.set("security", "none");
        }

        const link = `vless://${uuid}@${address}:${port}`;
        const url = new URL(link);
        for (const [key, value] of params) {
            url.searchParams.set(key, value)
        }
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    genSSLink(address = '', port = this.port, forceTls, remark = '', clientPassword) {
        let settings = this.settings;
        const type = this.stream.network;
        const security = forceTls == 'same' ? this.stream.security : forceTls;
        const params = new Map();
        params.set("type", this.stream.network);
        switch (type) {
            case "tcp":
                const tcp = this.stream.tcp;
                if (tcp.type === 'http') {
                    const request = tcp.request;
                    params.set("path", request.path.join(','));
                    const index = request.headers.findIndex(header => header.name.toLowerCase() === 'host');
                    if (index >= 0) {
                        const host = request.headers[index].value;
                        params.set("host", host);
                    }
                    params.set("headerType", 'http');
                }
                break;
            case "kcp":
                const kcp = this.stream.kcp;
                params.set("mtu", kcp.mtu);
                params.set("tti", kcp.tti);
                break;
            case "ws":
                const ws = this.stream.ws;
                params.set("path", ws.path);
                params.set("host", ws.host?.length > 0 ? ws.host : this.getHeader(ws, 'host'));
                break;
            case "grpc":
                const grpc = this.stream.grpc;
                params.set("serviceName", grpc.serviceName);
                params.set("authority", grpc.authority);
                if (grpc.multiMode) {
                    params.set("mode", "multi");
                }
                break;
            case "httpupgrade":
                const httpupgrade = this.stream.httpupgrade;
                params.set("path", httpupgrade.path);
                params.set("host", httpupgrade.host?.length > 0 ? httpupgrade.host : this.getHeader(httpupgrade, 'host'));
                break;
            case "xhttp":
                const xhttp = this.stream.xhttp;
                params.set("path", xhttp.path);
                params.set("host", xhttp.host?.length > 0 ? xhttp.host : this.getHeader(xhttp, 'host'));
                params.set("mode", xhttp.mode);
                Inbound.applyXhttpShareParams(xhttp, params);
                break;
        }

        Inbound.applyFinalMaskToParams(this.stream.finalmask, params);

        if (security === 'tls') {
            params.set("security", "tls");
            if (this.stream.isTls) {
                params.set("fp", this.stream.tls.settings.fingerprint);
                params.set("alpn", this.stream.tls.alpn);
                if (this.stream.tls.settings.echConfigList?.length > 0) {
                    params.set("ech", this.stream.tls.settings.echConfigList);
                }
                if (!ObjectUtil.isEmpty(this.stream.tls.sni)) {
                    params.set("sni", this.stream.tls.sni);
                }
            }
        }


        let password = new Array();
        if (this.isSS2022) password.push(settings.password);
        if (this.isSSMultiUser) password.push(clientPassword);

        let link = `ss://${Base64.encode(`${settings.method}:${password.join(':')}`, true)}@${address}:${port}`;
        const url = new URL(link);
        for (const [key, value] of params) {
            url.searchParams.set(key, value)
        }
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    // The query parameters that describe an ordinary Xray stream: the transport and
    // then the TLS or REALITY block. Shared by every protocol whose link is
    // "scheme://<credential>@host:port?<stream>", which today is trojan and anytls.
    // Mirrored on the Go side by applyShareNetworkParams + applyShareTLSParams /
    // applyShareRealityParams in sub/subService.go, so the two generators of the SAME
    // account's link agree; keep the pair in step.
    streamShareParams(security) {
        const type = this.stream.network;
        const params = new Map();
        params.set("type", this.stream.network);
        switch (type) {
            case "tcp":
                const tcp = this.stream.tcp;
                if (tcp.type === 'http') {
                    const request = tcp.request;
                    params.set("path", request.path.join(','));
                    const index = request.headers.findIndex(header => header.name.toLowerCase() === 'host');
                    if (index >= 0) {
                        const host = request.headers[index].value;
                        params.set("host", host);
                    }
                    params.set("headerType", 'http');
                }
                break;
            case "kcp":
                const kcp = this.stream.kcp;
                params.set("mtu", kcp.mtu);
                params.set("tti", kcp.tti);
                break;
            case "ws":
                const ws = this.stream.ws;
                params.set("path", ws.path);
                params.set("host", ws.host?.length > 0 ? ws.host : this.getHeader(ws, 'host'));
                break;
            case "grpc":
                const grpc = this.stream.grpc;
                params.set("serviceName", grpc.serviceName);
                params.set("authority", grpc.authority);
                if (grpc.multiMode) {
                    params.set("mode", "multi");
                }
                break;
            case "httpupgrade":
                const httpupgrade = this.stream.httpupgrade;
                params.set("path", httpupgrade.path);
                params.set("host", httpupgrade.host?.length > 0 ? httpupgrade.host : this.getHeader(httpupgrade, 'host'));
                break;
            case "xhttp":
                const xhttp = this.stream.xhttp;
                params.set("path", xhttp.path);
                params.set("host", xhttp.host?.length > 0 ? xhttp.host : this.getHeader(xhttp, 'host'));
                params.set("mode", xhttp.mode);
                Inbound.applyXhttpShareParams(xhttp, params);
                break;
        }

        Inbound.applyFinalMaskToParams(this.stream.finalmask, params);

        if (security === 'tls') {
            params.set("security", "tls");
            if (this.stream.isTls) {
                params.set("fp", this.stream.tls.settings.fingerprint);
                params.set("alpn", this.stream.tls.alpn);
                if (this.stream.tls.settings.echConfigList?.length > 0) {
                    params.set("ech", this.stream.tls.settings.echConfigList);
                }
                if (!ObjectUtil.isEmpty(this.stream.tls.sni)) {
                    params.set("sni", this.stream.tls.sni);
                }
            }
        }

        else if (security === 'reality') {
            params.set("security", "reality");
            params.set("pbk", this.stream.reality.settings.publicKey);
            params.set("fp", this.stream.reality.settings.fingerprint);
            if (!ObjectUtil.isArrEmpty(this.stream.reality.serverNames)) {
                params.set("sni", this.stream.reality.serverNames.split(",")[0]);
            }
            if (this.stream.reality.shortIds.length > 0) {
                params.set("sid", this.stream.reality.shortIds.split(",")[0]);
            }
            if (!ObjectUtil.isEmpty(this.stream.reality.settings.spiderX)) {
                params.set("spx", this.stream.reality.settings.spiderX);
            }
            if (!ObjectUtil.isEmpty(this.stream.reality.settings.mldsa65Verify)) {
                params.set("pqv", this.stream.reality.settings.mldsa65Verify);
            }
        }

        else {
            params.set("security", "none");
        }

        return params;
    }

    genTrojanLink(address = '', port = this.port, forceTls, remark = '', clientPassword) {
        const security = forceTls == 'same' ? this.stream.security : forceTls;
        const params = this.streamShareParams(security);

        const link = `trojan://${clientPassword}@${address}:${port}`;
        const url = new URL(link);
        for (const [key, value] of params) {
            url.searchParams.set(key, value)
        }
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    genHysteriaLink(address = '', port = this.port, remark = '', clientAuth) {
        const protocol = this.settings.version == 2 ? "hysteria2" : "hysteria";
        const link = `${protocol}://${clientAuth}@${address}:${port}`;

        const params = new Map();
        params.set("security", "tls");
        if (this.stream.tls.settings.fingerprint?.length > 0) params.set("fp", this.stream.tls.settings.fingerprint);
        if (this.stream.tls.alpn?.length > 0) params.set("alpn", this.stream.tls.alpn);
        if (this.stream.tls.settings.allowInsecure) params.set("insecure", "1");
        if (this.stream.tls.settings.echConfigList?.length > 0) params.set("ech", this.stream.tls.settings.echConfigList);
        if (this.stream.tls.sni?.length > 0) params.set("sni", this.stream.tls.sni);

        const udpMasks = this.stream?.finalmask?.udp;
        if (Array.isArray(udpMasks)) {
            const salamanderMask = udpMasks.find(mask => mask?.type === 'salamander');
            const obfsPassword = salamanderMask?.settings?.password;
            if (typeof obfsPassword === 'string' && obfsPassword.length > 0) {
                params.set("obfs", "salamander");
                params.set("obfs-password", obfsPassword);
            }
        }

        Inbound.applyFinalMaskToParams(this.stream.finalmask, params);

        const url = new URL(link);
        for (const [key, value] of params) {
            url.searchParams.set(key, value);
        }
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    // The three generators below are each written a SECOND time in Go, for the
    // subscription endpoint (sub/subService.go genAnytlsLink / genTuicLink /
    // genNaiveLink). The goal is that an account gets the same bytes from the panel's
    // QR as from its subscription, so two things are deliberate here:
    //
    //   * parameters are set in ALPHABETICAL order, because Go builds its query with
    //     url.Values.Encode(), which sorts;
    //   * credentials go through encodeUserinfo(), because Go escapes them with
    //     url.User / url.UserPassword and encodeURIComponent is not the same set.
    //
    // Keep new parameters sorted and change both sides together.
    //
    // That goal is NOT currently met, and the gap is older and wider than these three
    // protocols: it is in the shared link tail, so trojan, vless and vmess have it too.
    // Measured, not assumed:
    //
    //   * the FRAGMENT. Go assigns url.URL.Fragment and lets String() escape it, which
    //     leaves "@ + /" raw; here it is encodeURIComponent, which escapes all three.
    //     The default remark model is -ieo, and the "e" is the client EMAIL, so every
    //     email's "@" makes the two forms differ. In practice that is nearly every
    //     account, not a corner case.
    //   * EMPTY values on anytls. Go's applyShareTLSParams emits "sni=" when the SNI is
    //     empty and omits "alpn" when it is; streamShareParams below does the reverse.
    //
    // Both forms decode to the same remark and the same parameters, so no client is
    // broken and nothing here is urgent. It is recorded because "the two sides are
    // byte-identical" was previously written down as fact, and anyone who trusts that
    // while diffing a QR against a subscription will lose an afternoon to it.

    // Escapes one half of a userinfo the way Go's url.User does. encodeURIComponent
    // leaves !*'() raw and escapes $&+,;= ; Go does exactly the opposite, so a
    // password holding any of those would otherwise differ by a byte between the two
    // generators (both still decode to the same credential, which is what makes it a
    // silent divergence rather than a broken link).
    static encodeUserinfo(value) {
        return encodeURIComponent(value ?? '')
            .replace(/[!*'()]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())
            .replace(/%24/g, '$')
            .replace(/%26/g, '&')
            .replace(/%2B/g, '+')
            .replace(/%2C/g, ',')
            .replace(/%3B/g, ';')
            .replace(/%3D/g, '=');
    }

    // AnyTLS rides the ordinary transport layer, so its link carries exactly the
    // stream parameters a trojan link does, REALITY included.
    genAnytlsLink(address = '', port = this.port, forceTls = 'same', remark = '', clientPassword = '') {
        const security = forceTls == 'same' ? this.stream.security : forceTls;
        const params = this.streamShareParams(security);

        const link = `anytls://${Inbound.encodeUserinfo(clientPassword)}@${address}:${port}`;
        const url = new URL(link);
        // Sorted, unlike genTrojanLink, which emits streamShareParams in insertion
        // order: this protocol is new enough that its two generators can still be
        // made to agree exactly, and sorting is what the Go half already does.
        for (const [key, value] of [...params].sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)) {
            url.searchParams.set(key, value);
        }
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    // TUIC's TLS is not optional and its transport is its own, so the link carries
    // neither `type` nor `security`: only the handful of parameters its clients read.
    genTuicLink(address = '', port = this.port, remark = '', clientId = '', clientPassword = '') {
        const params = new Map();
        // No allow_insecure. This core dropped `allowInsecure` (it errors out, having
        // been replaced by pinnedPeerCertSha256), and TlsStreamSettings.Settings
        // carries only fingerprint and echConfigList, so there is no stored value to
        // read: TlsStreamSettings.fromJson drops the key even if it is in the DB. A
        // self-signed deployment therefore has to be handled at the client, by
        // trusting or pinning the cert, because the link cannot ask it to skip
        // verification.
        // MANDATORY. The server pins ALPN to h3; sing-box, mihomo and the Rust
        // tuic-client all default to sending none, and the handshake then dies with
        // "tls: no application protocol", which names nothing an operator can act on.
        params.set("alpn", "h3");
        params.set("congestion_control", this.settings?.congestionControl || 'cubic');
        if (this.stream.tls?.sni?.length > 0) params.set("sni", this.stream.tls.sni);
        params.set("udp_relay_mode", "native");

        const link = `tuic://${Inbound.encodeUserinfo(clientId)}:${Inbound.encodeUserinfo(clientPassword)}@${address}:${port}`;
        const url = new URL(link);
        for (const [key, value] of params) {
            url.searchParams.set(key, value);
        }
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    // naive sends exactly one `Proxy-Authorization: Basic base64(username:password)`,
    // and the username here must be the one the SERVER will match: the account's
    // `username` when it has one, its email when it does not. Passing the email
    // unconditionally, as this used to, hands every account with a username a link that
    // authenticates as somebody who does not exist.
    //
    // The scheme is NekoRay/NekoBox's `naive+<transport>://`, the only share-link form
    // a GUI client imports. naiveproxy's own binary takes the same URL with the
    // `naive+` prefix stripped, as its --proxy value.
    genNaiveLink(address = '', port = this.port, remark = '', clientUsername = '', clientPassword = '') {
        // settings.network selects the server's transport: tcp = HTTP/2 over TLS,
        // udp = HTTP/3 over QUIC. An inbound serving both advertises https, which
        // every client speaks; quic-only is the one case that has to say so.
        const network = (this.settings?.network || 'tcp').trim();
        const scheme = network === 'udp' ? 'naive+quic' : 'naive+https';

        // No insecure param, for the same reason as genTuicLink: `allowInsecure` does
        // not exist in this core or in TlsStreamSettings.Settings, so there is nothing
        // to read and the flag could only ever be hardcoded.
        const params = new Map();
        if (this.stream.tls?.sni?.length > 0) params.set("sni", this.stream.tls.sni);

        const link = `${scheme}://${Inbound.encodeUserinfo(clientUsername)}:${Inbound.encodeUserinfo(clientPassword)}@${address}:${port}`;
        const url = new URL(link);
        for (const [key, value] of params) {
            url.searchParams.set(key, value);
        }
        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    getWireguardTxt(address, port, remark, peerId) {
        let txt = `[Interface]\n`
        txt += `PrivateKey = ${this.settings.peers[peerId].privateKey}\n`
        txt += `Address = ${this.settings.peers[peerId].allowedIPs[0]}\n`
        txt += `DNS = 1.1.1.1, 1.0.0.1\n`
        if (this.settings.mtu) {
            txt += `MTU = ${this.settings.mtu}\n`
        }
        txt += `\n# ${remark}\n`
        txt += `[Peer]\n`
        txt += `PublicKey = ${this.settings.pubKey}\n`
        txt += `AllowedIPs = 0.0.0.0/0, ::/0\n`
        txt += `Endpoint = ${address}:${port}`
        if (this.settings.peers[peerId].psk) {
            txt += `\nPresharedKey = ${this.settings.peers[peerId].psk}`
        }
        if (this.settings.peers[peerId].keepAlive) {
            txt += `\nPersistentKeepalive = ${this.settings.peers[peerId].keepAlive}\n`
        }
        return txt;
    }

    getWireguardLink(address, port, remark, peerId) {
        const peer = this.settings?.peers?.[peerId];
        if (!peer) return '';

        const link = `wireguard://${address}:${port}`;
        const url = new URL(link);
        url.username = peer.privateKey || '';

        if (this.settings?.pubKey) {
            url.searchParams.set("publickey", this.settings.pubKey);
        }
        if (Array.isArray(peer.allowedIPs) && peer.allowedIPs.length > 0 && peer.allowedIPs[0]) {
            url.searchParams.set("address", peer.allowedIPs[0]);
        }
        if (this.settings?.mtu) {
            url.searchParams.set("mtu", this.settings.mtu);
        }

        url.hash = encodeURIComponent(remark);
        return url.toString();
    }

    genWireguardLinks(remark = '', remarkModel = '-ieo') {
        const addr = !ObjectUtil.isEmpty(this.listen) && this.listen !== "0.0.0.0" ? this.listen : location.hostname;
        const separationChar = remarkModel.charAt(0);
        let links = [];
        this.settings.peers.forEach((p, index) => {
            links.push(this.getWireguardLink(addr, this.port, remark + separationChar + (index + 1), index));
        });
        return links.join('\r\n');
    }

    genWireguardConfigs(remark = '', remarkModel = '-ieo') {
        const addr = !ObjectUtil.isEmpty(this.listen) && this.listen !== "0.0.0.0" ? this.listen : location.hostname;
        const separationChar = remarkModel.charAt(0);
        let links = [];
        this.settings.peers.forEach((p, index) => {
            links.push(this.getWireguardTxt(addr, this.port, remark + separationChar + (index + 1), index));
        });
        return links.join('\r\n');
    }

    genLink(address = '', port = this.port, forceTls = 'same', remark = '', client) {
        switch (this.protocol) {
            case Protocols.VMESS:
                return this.genVmessLink(address, port, forceTls, remark, client.id, client.security);
            case Protocols.VLESS:
                return this.genVLESSLink(address, port, forceTls, remark, client.id, client.flow);
            case Protocols.SHADOWSOCKS:
                return this.genSSLink(address, port, forceTls, remark, this.isSSMultiUser ? client.password : '');
            case Protocols.TROJAN:
                return this.genTrojanLink(address, port, forceTls, remark, client.password);
            case Protocols.HYSTERIA:
                return this.genHysteriaLink(address, port, remark, client.auth.length > 0 ? client.auth : this.stream.hysteria.auth);
            case Protocols.ANYTLS:
                return this.genAnytlsLink(address, port, forceTls, remark, client.password);
            case Protocols.TUIC:
                return this.genTuicLink(address, port, remark, client.id, client.password);
            case Protocols.NAIVE:
                // The `|| email` is the back-compat fallback, not defensiveness: an
                // account saved before the username field existed has none, and the
                // server matches it by email.
                return this.genNaiveLink(address, port, remark, client.username || client.email, client.password);
            default: return '';
        }
    }

    genAllLinks(remark = '', remarkModel = '-ieo', client) {
        let result = [];
        let email = client ? client.email : '';
        let addr = !ObjectUtil.isEmpty(this.listen) && this.listen !== "0.0.0.0" ? this.listen : location.hostname;
        let port = this.port;
        // MTProto: one link per mode the ACCOUNT has enabled, not one per inbound.
        // The same 16-byte secret is reused across modes (only the prefix differs),
        // so a disabled mode must not be offered here, the proxy would refuse it
        // ([access.user_modes]) and the user would be handed a link that cannot work.
        // External Proxy endpoints are per-account too, so they are applied inside
        // links() rather than from this.stream.externalProxy.
        if (this.protocol === Protocols.MTPROTO) {
            if (!client || typeof client.links !== 'function') return result;
            return client.links(addr, port).map(l => ({
                remark: [remark, email, l.label].filter(x => x && x.length > 0).join(remarkModel.charAt(0)),
                link: l.link,
            }));
        }
        const separationChar = remarkModel.charAt(0);
        const orderChars = remarkModel.slice(1);
        let orders = {
            'i': remark,
            'e': email,
            'o': '',
        };
        if (ObjectUtil.isArrEmpty(this.stream.externalProxy)) {
            let r = orderChars.split('').map(char => orders[char]).filter(x => x.length > 0).join(separationChar);
            result.push({
                remark: r,
                link: this.genLink(addr, port, 'same', r, client)
            });
        } else {
            this.stream.externalProxy.forEach((ep) => {
                orders['o'] = ep.remark;
                let r = orderChars.split('').map(char => orders[char]).filter(x => x.length > 0).join(separationChar);
                result.push({
                    remark: r,
                    link: this.genLink(ep.dest, ep.port, ep.forceTls, r, client)
                });
            });
        }
        return result;
    }

    genInboundLinks(remark = '', remarkModel = '-ieo') {
        let addr = !ObjectUtil.isEmpty(this.listen) && this.listen !== "0.0.0.0" ? this.listen : location.hostname;
        if (this.clients) {
            let links = [];
            this.clients.forEach((client) => {
                this.genAllLinks(remark, remarkModel, client).forEach(l => {
                    links.push(l.link);
                })
            });
            return links.join('\r\n');
        } else {
            if (this.protocol == Protocols.SHADOWSOCKS && !this.isSSMultiUser) return this.genSSLink(addr, this.port, 'same', remark);
            if (this.protocol == Protocols.WIREGUARD) {
                return this.genWireguardConfigs(remark, remarkModel);
            }
            return '';
        }
    }

    static fromJson(json = {}) {
        const stream = StreamSettings.fromJson(json.streamSettings);
        // The ONE case where rewriting a stored value on load is right. An inbound
        // stored on a transport its protocol cannot use describes something real and
        // is shown as-is (the picker renders it disabled), but QUIC without TLS
        // describes nothing, so there is no state to preserve by keeping it.
        //
        // It matters because the security picker is hidden for these protocols: an
        // inbound created over the REST API without an explicit streamSettings
        // security gets 'none' from the StreamSettings constructor default, and would
        // then render a "TLS" heading with no fields under it and no control to fix
        // it. Normalising here is what makes the form's claim true.
        if (Inbound.protocolRequiresTls(json.protocol) && stream.security !== 'tls') {
            stream.security = 'tls';
        }
        return new Inbound(
            json.port,
            json.listen,
            json.protocol,
            Inbound.Settings.fromJson(json.protocol, json.settings),
            stream,
            json.tag,
            Sniffing.fromJson(json.sniffing),
            json.clientStats
        )
    }

    toJson() {
        let streamSettings;
        if (this.canEnableStream() || this.stream?.sockopt) {
            streamSettings = this.stream.toJson();
        }
        return {
            port: this.port,
            listen: this.listen,
            protocol: this.protocol,
            settings: this.settings instanceof XrayCommonClass ? this.settings.toJson() : this.settings,
            streamSettings: streamSettings,
            tag: this.tag,
            sniffing: this.sniffing.toJson(),
            clientStats: this.clientStats
        };
    }
}

Inbound.Settings = class extends XrayCommonClass {
    constructor(protocol) {
        super();
        this.protocol = protocol;
    }

    static getSettings(protocol) {
        switch (protocol) {
            case Protocols.VMESS: return new Inbound.VmessSettings(protocol);
            case Protocols.VLESS: return new Inbound.VLESSSettings(protocol);
            case Protocols.TROJAN: return new Inbound.TrojanSettings(protocol);
            case Protocols.SHADOWSOCKS: return new Inbound.ShadowsocksSettings(protocol);
            case Protocols.TUNNEL: return new Inbound.TunnelSettings(protocol);
            case Protocols.MIXED: return new Inbound.MixedSettings(protocol);
            case Protocols.HTTP: return new Inbound.HttpSettings(protocol);
            case Protocols.WIREGUARD: return new Inbound.WireguardSettings(protocol);
            case Protocols.TUN: return new Inbound.TunSettings(protocol);
            case Protocols.HYSTERIA: return new Inbound.HysteriaSettings(protocol);
            case Protocols.ANYTLS: return new Inbound.AnytlsSettings(protocol);
            case Protocols.TUIC: return new Inbound.TuicSettings(protocol);
            case Protocols.NAIVE: return new Inbound.NaiveSettings(protocol);
            case Protocols.L2TP: return new Inbound.L2tpSettings(protocol);
            case Protocols.PPTP: return new Inbound.PptpSettings(protocol);
            case Protocols.OPENVPN: return new Inbound.OpenvpnSettings(protocol);
            case Protocols.OPENCONNECT: return new Inbound.OcservSettings(protocol);
            case Protocols.SSTP: return new Inbound.SstpSettings(protocol);
            case Protocols.IKEV2: return new Inbound.Ikev2Settings(protocol);
            case Protocols.WGC: return new Inbound.WgcSettings(protocol);
            case Protocols.AWG: return new Inbound.AwgSettings(protocol);
            case Protocols.GRE: return new Inbound.GreSettings(protocol);
            case Protocols.MTPROTO: return new Inbound.MtprotoSettings(protocol);
            case Protocols.SSH: return new Inbound.SshSettings(protocol);
            default: return null;
        }
    }

    static fromJson(protocol, json) {
        switch (protocol) {
            case Protocols.VMESS: return Inbound.VmessSettings.fromJson(json);
            case Protocols.VLESS: return Inbound.VLESSSettings.fromJson(json);
            case Protocols.TROJAN: return Inbound.TrojanSettings.fromJson(json);
            case Protocols.SHADOWSOCKS: return Inbound.ShadowsocksSettings.fromJson(json);
            case Protocols.TUNNEL: return Inbound.TunnelSettings.fromJson(json);
            case Protocols.MIXED: return Inbound.MixedSettings.fromJson(json);
            case Protocols.HTTP: return Inbound.HttpSettings.fromJson(json);
            case Protocols.WIREGUARD: return Inbound.WireguardSettings.fromJson(json);
            case Protocols.TUN: return Inbound.TunSettings.fromJson(json);
            case Protocols.HYSTERIA: return Inbound.HysteriaSettings.fromJson(json);
            case Protocols.ANYTLS: return Inbound.AnytlsSettings.fromJson(json);
            case Protocols.TUIC: return Inbound.TuicSettings.fromJson(json);
            case Protocols.NAIVE: return Inbound.NaiveSettings.fromJson(json);
            case Protocols.L2TP: return Inbound.L2tpSettings.fromJson(json);
            case Protocols.PPTP: return Inbound.PptpSettings.fromJson(json);
            case Protocols.OPENVPN: return Inbound.OpenvpnSettings.fromJson(json);
            case Protocols.OPENCONNECT: return Inbound.OcservSettings.fromJson(json);
            case Protocols.SSTP: return Inbound.SstpSettings.fromJson(json);
            case Protocols.IKEV2: return Inbound.Ikev2Settings.fromJson(json);
            case Protocols.WGC: return Inbound.WgcSettings.fromJson(json);
            case Protocols.AWG: return Inbound.AwgSettings.fromJson(json);
            case Protocols.GRE: return Inbound.GreSettings.fromJson(json);
            case Protocols.MTPROTO: return Inbound.MtprotoSettings.fromJson(json);
            case Protocols.SSH: return Inbound.SshSettings.fromJson(json);
            default: return null;
        }
    }

    toJson() {
        return {};
    }
};

/** Shared user-quota fields and UI helpers for multi-user protocol clients. */
Inbound.ClientBase = class extends XrayCommonClass {
    constructor(
        email = RandomUtil.randomLowerAndNum(8),
        limitIp = 0,
        totalGB = 0,
        expiryTime = 0,
        enable = true,
        tgId = '',
        subId = RandomUtil.randomLowerAndNum(16),
        comment = '',
        reset = 0,
        created_at = undefined,
        updated_at = undefined,
    ) {
        super();
        this.email = email;
        this.limitIp = limitIp;
        this.totalGB = totalGB;
        this.expiryTime = expiryTime;
        this.enable = enable;
        this.tgId = tgId;
        this.subId = subId;
        this.comment = comment;
        this.reset = reset;
        this.created_at = created_at;
        this.updated_at = updated_at;
    }

    static commonArgsFromJson(json = {}) {
        return [
            json.email,
            json.limitIp,
            json.totalGB,
            json.expiryTime,
            json.enable,
            json.tgId,
            json.subId,
            json.comment,
            json.reset,
            json.created_at,
            json.updated_at,
        ];
    }

    _clientBaseToJson() {
        return {
            email: this.email,
            limitIp: this.limitIp,
            totalGB: this.totalGB,
            expiryTime: this.expiryTime,
            enable: this.enable,
            tgId: this.tgId,
            subId: this.subId,
            comment: this.comment,
            reset: this.reset,
            created_at: this.created_at,
            updated_at: this.updated_at,
        };
    }

    get _expiryTime() {
        if (this.expiryTime === 0 || this.expiryTime === '') {
            return null;
        }
        if (this.expiryTime < 0) {
            return this.expiryTime / -86400000;
        }
        return moment(this.expiryTime);
    }

    set _expiryTime(t) {
        if (t == null || t === '') {
            this.expiryTime = 0;
        } else {
            this.expiryTime = t.valueOf();
        }
    }

    get _totalGB() {
        return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
    }

    set _totalGB(gb) {
        this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
    }
};

Inbound.VmessSettings = class extends Inbound.Settings {
    constructor(protocol,
        vmesses = [new Inbound.VmessSettings.VMESS()]) {
        super(protocol);
        this.vmesses = vmesses;
    }

    indexOfVmessById(id) {
        return this.vmesses.findIndex(VMESS => VMESS.id === id);
    }

    addVmess(VMESS) {
        if (this.indexOfVmessById(VMESS.id) >= 0) {
            return false;
        }
        this.vmesses.push(VMESS);
    }

    delVmess(VMESS) {
        const i = this.indexOfVmessById(VMESS.id);
        if (i >= 0) {
            this.vmesses.splice(i, 1);
        }
    }

    static fromJson(json = {}) {
        return new Inbound.VmessSettings(
            Protocols.VMESS,
            (json.clients || []).map(client => Inbound.VmessSettings.VMESS.fromJson(client)),
        );
    }

    toJson() {
        return {
            clients: Inbound.VmessSettings.toJsonArray(this.vmesses),
        };
    }
};

Inbound.VmessSettings.VMESS = class extends Inbound.ClientBase {
    constructor(
        id = RandomUtil.randomUUID(),
        security = USERS_SECURITY.AUTO,
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.id = id;
        this.security = security;
    }

    static fromJson(json = {}) {
        return new Inbound.VmessSettings.VMESS(
            json.id,
            json.security,
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }

    toJson() {
        return {
            id: this.id,
            security: this.security,
            ...this._clientBaseToJson(),
        };
    }
};

Inbound.VLESSSettings = class extends Inbound.Settings {
    constructor(
        protocol,
        vlesses = [new Inbound.VLESSSettings.VLESS()],
        decryption = "none",
        encryption = "none",
        fallbacks = [],
        selectedAuth = undefined,
        testseed = [900, 500, 900, 256],
    ) {
        super(protocol);
        this.vlesses = vlesses;
        this.decryption = decryption;
        this.encryption = encryption;
        this.fallbacks = fallbacks;
        this.selectedAuth = selectedAuth;
        this.testseed = testseed;
    }

    addFallback() {
        this.fallbacks.push(new Inbound.VLESSSettings.Fallback());
    }

    delFallback(index) {
        this.fallbacks.splice(index, 1);
    }

    static fromJson(json = {}) {
        // Ensure testseed is always initialized as an array
        let testseed = [900, 500, 900, 256];
        if (json.testseed && Array.isArray(json.testseed) && json.testseed.length >= 4) {
            testseed = json.testseed;
        }

        const obj = new Inbound.VLESSSettings(
            Protocols.VLESS,
            (json.clients || []).map(client => Inbound.VLESSSettings.VLESS.fromJson(client)),
            json.decryption,
            json.encryption,
            Inbound.VLESSSettings.Fallback.fromJson(json.fallbacks || []),
            json.selectedAuth,
            testseed
        );
        return obj;
    }


    toJson() {
        const json = {
            clients: Inbound.VLESSSettings.toJsonArray(this.vlesses),
        };

        if (this.decryption) {
            json.decryption = this.decryption;
        }

        if (this.encryption) {
            json.encryption = this.encryption;
        }

        if (this.fallbacks && this.fallbacks.length > 0) {
            json.fallbacks = Inbound.VLESSSettings.toJsonArray(this.fallbacks);
        }
        if (this.selectedAuth) {
            json.selectedAuth = this.selectedAuth;
        }

        // Only include testseed if at least one client has a flow set
        const hasFlow = this.vlesses && this.vlesses.some(vless => vless.flow && vless.flow !== '');
        if (hasFlow && this.testseed && this.testseed.length >= 4) {
            json.testseed = this.testseed;
        }

        return json;
    }
};

Inbound.VLESSSettings.VLESS = class extends Inbound.ClientBase {
    constructor(
        id = RandomUtil.randomUUID(),
        flow = '',
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.id = id;
        this.flow = flow;
    }

    static fromJson(json = {}) {
        return new Inbound.VLESSSettings.VLESS(
            json.id,
            json.flow,
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }

    toJson() {
        return {
            id: this.id,
            flow: this.flow,
            ...this._clientBaseToJson(),
        };
    }
};

Inbound.VLESSSettings.Fallback = class extends XrayCommonClass {
    constructor(name = "", alpn = '', path = '', dest = '', xver = 0) {
        super();
        this.name = name;
        this.alpn = alpn;
        this.path = path;
        this.dest = dest;
        this.xver = xver;
    }

    toJson() {
        let xver = this.xver;
        if (!Number.isInteger(xver)) {
            xver = 0;
        }
        return {
            name: this.name,
            alpn: this.alpn,
            path: this.path,
            dest: this.dest,
            xver: xver,
        }
    }

    static fromJson(json = []) {
        const fallbacks = [];
        for (let fallback of json) {
            fallbacks.push(new Inbound.VLESSSettings.Fallback(
                fallback.name,
                fallback.alpn,
                fallback.path,
                fallback.dest,
                fallback.xver,
            ))
        }
        return fallbacks;
    }
};

Inbound.TrojanSettings = class extends Inbound.Settings {
    constructor(protocol,
        trojans = [new Inbound.TrojanSettings.Trojan()],
        fallbacks = [],) {
        super(protocol);
        this.trojans = trojans;
        this.fallbacks = fallbacks;
    }

    addFallback() {
        this.fallbacks.push(new Inbound.TrojanSettings.Fallback());
    }

    delFallback(index) {
        this.fallbacks.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Inbound.TrojanSettings(
            Protocols.TROJAN,
            (json.clients || []).map(client => Inbound.TrojanSettings.Trojan.fromJson(client)),
            Inbound.TrojanSettings.Fallback.fromJson(json.fallbacks),);
    }

    toJson() {
        return {
            clients: Inbound.TrojanSettings.toJsonArray(this.trojans),
            fallbacks: Inbound.TrojanSettings.toJsonArray(this.fallbacks)
        };
    }
};

Inbound.TrojanSettings.Trojan = class extends Inbound.ClientBase {
    constructor(
        password = RandomUtil.randomSeq(10),
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.password = password;
    }

    toJson() {
        return {
            password: this.password,
            ...this._clientBaseToJson(),
        };
    }

    static fromJson(json = {}) {
        return new Inbound.TrojanSettings.Trojan(
            json.password,
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }
};

Inbound.TrojanSettings.Fallback = class extends XrayCommonClass {
    constructor(name = "", alpn = '', path = '', dest = '', xver = 0) {
        super();
        this.name = name;
        this.alpn = alpn;
        this.path = path;
        this.dest = dest;
        this.xver = xver;
    }

    toJson() {
        let xver = this.xver;
        if (!Number.isInteger(xver)) {
            xver = 0;
        }
        return {
            name: this.name,
            alpn: this.alpn,
            path: this.path,
            dest: this.dest,
            xver: xver,
        }
    }

    static fromJson(json = []) {
        const fallbacks = [];
        for (let fallback of json) {
            fallbacks.push(new Inbound.TrojanSettings.Fallback(
                fallback.name,
                fallback.alpn,
                fallback.path,
                fallback.dest,
                fallback.xver,
            ))
        }
        return fallbacks;
    }
};

Inbound.ShadowsocksSettings = class extends Inbound.Settings {
    constructor(protocol,
        method = SSMethods.BLAKE3_AES_256_GCM,
        password = RandomUtil.randomShadowsocksPassword(),
        network = 'tcp,udp',
        shadowsockses = [new Inbound.ShadowsocksSettings.Shadowsocks()],
        ivCheck = false,
    ) {
        super(protocol);
        this.method = method;
        this.password = password;
        this.network = network;
        this.shadowsockses = shadowsockses;
        this.ivCheck = ivCheck;
    }

    static fromJson(json = {}) {
        return new Inbound.ShadowsocksSettings(
            Protocols.SHADOWSOCKS,
            json.method,
            json.password,
            json.network,
            (json.clients || []).map(client => Inbound.ShadowsocksSettings.Shadowsocks.fromJson(client)),
            json.ivCheck,
        );
    }

    toJson() {
        return {
            method: this.method,
            password: this.password,
            network: this.network,
            clients: Inbound.ShadowsocksSettings.toJsonArray(this.shadowsockses),
            ivCheck: this.ivCheck,
        };
    }
};

Inbound.ShadowsocksSettings.Shadowsocks = class extends Inbound.ClientBase {
    constructor(
        method = '',
        password = RandomUtil.randomShadowsocksPassword(),
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.method = method;
        this.password = password;
    }

    toJson() {
        return {
            method: this.method,
            password: this.password,
            ...this._clientBaseToJson(),
        };
    }

    static fromJson(json = {}) {
        return new Inbound.ShadowsocksSettings.Shadowsocks(
            json.method,
            json.password,
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }
};

Inbound.HysteriaSettings = class extends Inbound.Settings {
    constructor(protocol, version = 2, hysterias = [new Inbound.HysteriaSettings.Hysteria()]) {
        super(protocol);
        this.version = version;
        this.hysterias = hysterias;
    }

    static fromJson(json = {}) {
        return new Inbound.HysteriaSettings(
            Protocols.HYSTERIA,
            json.version ?? 2,
            (json.clients || []).map(client => Inbound.HysteriaSettings.Hysteria.fromJson(client)),
        );
    }

    toJson() {
        return {
            version: this.version,
            clients: Inbound.HysteriaSettings.toJsonArray(this.hysterias),
        };
    }
};

Inbound.HysteriaSettings.Hysteria = class extends Inbound.ClientBase {
    constructor(
        auth = RandomUtil.randomSeq(10),
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.auth = auth;
    }

    toJson() {
        return {
            auth: this.auth,
            ...this._clientBaseToJson(),
        };
    }

    static fromJson(json = {}) {
        return new Inbound.HysteriaSettings.Hysteria(
            json.auth,
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }
};

Inbound.AnytlsSettings = class extends Inbound.Settings {
    constructor(protocol,
        anytlses = [new Inbound.AnytlsSettings.Anytls()],
        paddingScheme = Inbound.AnytlsSettings.DEFAULT_PADDING_SCHEME.slice(),
    ) {
        super(protocol);
        this.anytlses = anytlses;
        // The padding scheme is SERVER-AUTHORITATIVE: it is handed to the client in
        // the session's settings frame, so this list is the only copy that matters
        // and a client never has to be reconfigured to match it.
        this.paddingScheme = paddingScheme;
    }

    // A stored inbound is shown exactly as stored, INCLUDING an absent scheme, which
    // is how an operator who deliberately cleared the field sees it stay cleared. The
    // default only seeds a NEW inbound, via the constructor above.
    static fromJson(json = {}) {
        return new Inbound.AnytlsSettings(
            Protocols.ANYTLS,
            (json.clients || []).map(client => Inbound.AnytlsSettings.Anytls.fromJson(client)),
            Array.isArray(json.paddingScheme) ? json.paddingScheme.slice() : [],
        );
    }

    toJson() {
        // The form binds the textarea straight to this array and splits on newlines
        // WITHOUT filtering, so that typing a new line does not move the cursor; the
        // blank entries that leaves are dropped here instead. An empty result omits
        // the key entirely rather than sending [], which the core reads as "no
        // padding at all" instead of falling back to its own default scheme.
        const paddingScheme = (this.paddingScheme || [])
            .map(line => String(line).trim())
            .filter(line => line.length > 0);
        return {
            clients: Inbound.AnytlsSettings.toJsonArray(this.anytlses),
            paddingScheme: paddingScheme.length > 0 ? paddingScheme : undefined,
        };
    }
};

// AnyTLS's upstream default scheme, spelled out rather than left empty so the form
// shows what the server will actually do and an operator can edit one line of it.
Inbound.AnytlsSettings.DEFAULT_PADDING_SCHEME = [
    'stop=8',
    '0=30-30',
    '1=100-400',
    '2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000',
    '3=9-9,500-1000',
    '4=500-1000',
    '5=500-1000',
    '6=500-1000',
    '7=500-1000',
];

Inbound.AnytlsSettings.Anytls = class extends Inbound.ClientBase {
    constructor(
        password = RandomUtil.randomSeq(10),
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.password = password;
    }

    toJson() {
        return {
            password: this.password,
            ...this._clientBaseToJson(),
        };
    }

    static fromJson(json = {}) {
        return new Inbound.AnytlsSettings.Anytls(
            json.password,
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }
};

Inbound.TuicSettings = class extends Inbound.Settings {
    constructor(protocol,
        tuics = [new Inbound.TuicSettings.Tuic()],
        congestionControl = 'cubic',
        authTimeout = 3,
        zeroRttHandshake = false,
        heartbeat = 10,
        udpTimeout = 60,
    ) {
        super(protocol);
        this.tuics = tuics;
        // cubic | bbr | new_reno. Echoed into every share link as
        // congestion_control=, because a client that picks a different one talks
        // past the server's pacing rather than failing outright.
        this.congestionControl = congestionControl;
        // Seconds a connection may stay open before it has authenticated.
        this.authTimeout = authTimeout;
        this.zeroRttHandshake = zeroRttHandshake;
        this.heartbeat = heartbeat;
        this.udpTimeout = udpTimeout;
    }

    static fromJson(json = {}) {
        return new Inbound.TuicSettings(
            Protocols.TUIC,
            (json.clients || []).map(client => Inbound.TuicSettings.Tuic.fromJson(client)),
            json.congestionControl ?? 'cubic',
            json.authTimeout ?? 3,
            json.zeroRttHandshake ?? false,
            json.heartbeat ?? 10,
            json.udpTimeout ?? 60,
        );
    }

    toJson() {
        return {
            clients: Inbound.TuicSettings.toJsonArray(this.tuics),
            congestionControl: this.congestionControl,
            authTimeout: this.authTimeout,
            zeroRttHandshake: this.zeroRttHandshake,
            heartbeat: this.heartbeat,
            udpTimeout: this.udpTimeout,
        };
    }
};

// A TUIC account presents BOTH halves on every connection: the uuid names it and
// the password authenticates it. The uuid is the identity (see getClientIdentity),
// so it is a real `id` field and needs no email-backed getter.
Inbound.TuicSettings.Tuic = class extends Inbound.ClientBase {
    constructor(
        id = RandomUtil.randomUUID(),
        password = RandomUtil.randomSeq(10),
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.id = id;
        this.password = password;
    }

    toJson() {
        return {
            id: this.id,
            password: this.password,
            ...this._clientBaseToJson(),
        };
    }

    static fromJson(json = {}) {
        return new Inbound.TuicSettings.Tuic(
            json.id,
            json.password,
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }
};

Inbound.NaiveSettings = class extends Inbound.Settings {
    constructor(protocol,
        naives = [new Inbound.NaiveSettings.Naive()],
        network = 'tcp',
        masquerade = new Inbound.NaiveSettings.Masquerade(),
    ) {
        super(protocol);
        this.naives = naives;
        // tcp = HTTP/2 over TLS, udp = HTTP/3 over QUIC, "tcp,udp" = both on one port.
        // naive's transport is part of the protocol, so this settings field is the
        // SINGLE SOURCE OF TRUTH for which wires the listener owns: the core's
        // NormalizeNaiveInboundStream forces its own transport onto the stream and
        // takes the mode from here, OVERRIDING whatever streamSettings.network says.
        // The stream still carries TLS and sockopt, which is why the inbound needs
        // canEnableStream(), but its transport picker is decorative for naive.
        this.network = network;
        // What an unauthenticated request gets instead of a proxy error, which is
        // the whole point of naive: a probe must see an ordinary web server.
        this.masquerade = masquerade;
    }

    static fromJson(json = {}) {
        return new Inbound.NaiveSettings(
            Protocols.NAIVE,
            (json.clients || []).map(client => Inbound.NaiveSettings.Naive.fromJson(client)),
            json.network ?? 'tcp',
            Inbound.NaiveSettings.Masquerade.fromJson(json.masquerade),
        );
    }

    toJson() {
        return {
            clients: Inbound.NaiveSettings.toJsonArray(this.naives),
            network: this.network,
            masquerade: this.masquerade.toJson(),
        };
    }
};

Inbound.NaiveSettings.Masquerade = class extends XrayCommonClass {
    constructor(type = '404', file = '', url = '', string = '') {
        super();
        // 404 | file | proxy | string. Each of the three below belongs to exactly one
        // type; they are all kept so switching type back and forth does not lose what
        // was typed under the other one.
        this.type = type;
        this.file = file;
        this.url = url;
        this.string = string;
    }

    static fromJson(json = {}) {
        return new Inbound.NaiveSettings.Masquerade(
            json?.type ?? '404',
            json?.file ?? '',
            json?.url ?? '',
            json?.string ?? '',
        );
    }

    toJson() {
        return {
            type: this.type,
            file: this.file,
            url: this.url,
            string: this.string,
        };
    }
};

// naive sends one `Proxy-Authorization: Basic base64(username:password)`. The username
// half is this field, and an EMPTY one falls back to the email: that is what every
// account created before the field existed authenticates with, and nothing backfills
// them. The email stays the accounting identity either way.
//
// There is still no id field, and the identity remains the password (see
// getClientIdentity): the username is precisely the field an operator renames, and a
// key that moves mid-edit cannot be matched against the one the modal opened with.
Inbound.NaiveSettings.Naive = class extends Inbound.ClientBase {
    constructor(
        password = RandomUtil.randomSeq(10),
        username = '',
        email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at,
    ) {
        super(email, limitIp, totalGB, expiryTime, enable, tgId, subId, comment, reset, created_at, updated_at);
        this.password = password;
        this.username = username;
    }

    toJson() {
        return {
            password: this.password,
            username: this.username,
            ...this._clientBaseToJson(),
        };
    }

    static fromJson(json = {}) {
        return new Inbound.NaiveSettings.Naive(
            json.password,
            json.username ?? '',
            ...Inbound.ClientBase.commonArgsFromJson(json),
        );
    }
};

Inbound.L2tpSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    ipsecEnable = true,
    ipsecPsk = RandomUtil.randomSeq(16),
    allowRaw = false,
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    dns1 = "8.8.8.8",
    dns2 = "8.8.4.4",
    mtu = 1400,
    userLimit = 1,
    userLimitStrategy = "accept",
    l2tpUsers = [new Inbound.L2tpSettings.L2tpUser()],
    externalProxy = [],
  ) {
    super(protocol);
    this.ipsecEnable = ipsecEnable;
    this.ipsecPsk = ipsecPsk;
    this.allowRaw = allowRaw;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // List of client IP ranges; empty rows/list are auto-assigned by the panel.
    this.ipRanges = ipRanges;
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    // Simultaneous devices per account (1..64); 1 = legacy one-IP.
    this.userLimit = userLimit;
    // At the User Limit cap: "reject" a new device, or "accept" (evict oldest).
    this.userLimitStrategy = userLimitStrategy;
    this.l2tpUsers = l2tpUsers;
    // Advertised endpoint override(s): {dest,port,remark}. No config file for this
    // protocol, so this only changes the server address shown in export / info.
    this.externalProxy = externalProxy;
  }

  static fromJson(json = {}) {
    // Back-compat: seed the ipRanges list from a legacy single ipRange field.
    let ipRanges = Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [];
    if (ipRanges.length === 0 && json.ipRange) ipRanges = [json.ipRange];
    return new Inbound.L2tpSettings(
      Protocols.L2TP,
      json.ipsecEnable ?? true,
      json.ipsecPsk,
      json.allowRaw ?? false,
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      ipRanges,
      json.dns1 ?? "8.8.8.8",
      json.dns2 ?? "8.8.4.4",
      json.mtu ?? 1400,
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
      Inbound.L2tpSettings.L2tpUser.fromJson(json.clients),
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
    );
  }

  toJson() {
    return {
      ipsecEnable: this.ipsecEnable,
      ipsecPsk: this.ipsecPsk,
      allowRaw: this.allowRaw,
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: (this.ipRanges || []).filter((r) => r && r.trim() !== ""),
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
      clients: Inbound.L2tpSettings.L2tpUser.toJsonArray(this.l2tpUsers),
      externalProxy: this.externalProxy,
    };
  }
};

Inbound.L2tpSettings.L2tpUser = class extends XrayCommonClass {
  constructor(
    id = RandomUtil.randomLowerAndNum(8),
    password = RandomUtil.randomSeq(10),
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.id = id;
    this.password = password;
    this.email = email;
    this.enable = enable;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json)) return [new Inbound.L2tpSettings.L2tpUser()];
    return json.map(
      (j) =>
        new Inbound.L2tpSettings.L2tpUser(
          j.id,
          j.password,
          j.email,
          j.enable ?? true,
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.id,
      password: this.password,
      email: this.email,
      enable: this.enable,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0 || this.expiryTime === "") {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

Inbound.PptpSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    dns1 = "8.8.8.8",
    dns2 = "8.8.4.4",
    mtu = 1400,
    userLimit = 1,
    userLimitStrategy = "accept",
    pptpUsers = [new Inbound.PptpSettings.PptpUser()],
    externalProxy = [],
  ) {
    super(protocol);
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // List of client IP ranges; empty rows/list are auto-assigned by the panel.
    this.ipRanges = ipRanges;
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    // Simultaneous devices per account (1..64); 1 = legacy one-IP.
    this.userLimit = userLimit;
    // At the User Limit cap: "reject" a new device, or "accept" (evict oldest).
    this.userLimitStrategy = userLimitStrategy;
    this.pptpUsers = pptpUsers;
    // Advertised endpoint override(s): {dest,port,remark}. No config file for this
    // protocol, so this only changes the server address shown in export / info.
    this.externalProxy = externalProxy;
  }

  static fromJson(json = {}) {
    // Back-compat: seed the ipRanges list from a legacy single ipRange field.
    let ipRanges = Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [];
    if (ipRanges.length === 0 && json.ipRange) ipRanges = [json.ipRange];
    return new Inbound.PptpSettings(
      Protocols.PPTP,
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      ipRanges,
      json.dns1 ?? "8.8.8.8",
      json.dns2 ?? "8.8.4.4",
      json.mtu ?? 1400,
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
      Inbound.PptpSettings.PptpUser.fromJson(json.clients),
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
    );
  }

  toJson() {
    return {
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: (this.ipRanges || []).filter((r) => r && r.trim() !== ""),
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
      clients: Inbound.PptpSettings.PptpUser.toJsonArray(this.pptpUsers),
      externalProxy: this.externalProxy,
    };
  }
};

Inbound.PptpSettings.PptpUser = class extends XrayCommonClass {
  constructor(
    id = RandomUtil.randomLowerAndNum(8),
    password = RandomUtil.randomSeq(10),
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.id = id;
    this.password = password;
    this.email = email;
    this.enable = enable;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json)) return [new Inbound.PptpSettings.PptpUser()];
    return json.map(
      (j) =>
        new Inbound.PptpSettings.PptpUser(
          j.id,
          j.password,
          j.email,
          j.enable ?? true,
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.id,
      password: this.password,
      email: this.email,
      enable: this.enable,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0 || this.expiryTime === "") {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

Inbound.OpenvpnSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    udpEnable = true,
    tcpEnable = true,
    tcpPort = 1194,
    dns1 = "8.8.8.8",
    dns2 = "8.8.4.4",
    mtu = 1500,
    caCert = "",
    caKey = "",
    serverCert = "",
    serverKey = "",
    tlsCrypt = "",
    openvpnUsers = [new Inbound.OpenvpnSettings.OpenvpnUser()],
    externalProxy = [],
    cipherMode = "all",
    ciphers = Inbound.OpenvpnSettings.CIPHER_MODES.all.slice(),
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    userLimit = 1,
    userLimitStrategy = "accept",
    separatePorts = false,
    tlsUseFile = false,
    caCertFile = "",
    serverCertFile = "",
    serverKeyFile = "",
    tlsCryptFile = "",
  ) {
    super(protocol);
    this.udpEnable = udpEnable;
    this.tcpEnable = tcpEnable;
    this.tcpPort = tcpPort;
    // TCP + UDP share one port by default (both can bind the same number); flip
    // this to give TCP its own tcpPort.
    this.separatePorts = separatePorts;
    // TLS cert source, mirroring the Xray model: inline content (default) or file
    // paths. Path mode points OpenVPN at existing cert files instead of the
    // generated/pasted PEM content.
    this.tlsUseFile = tlsUseFile;
    this.caCertFile = caCertFile;
    this.serverCertFile = serverCertFile;
    this.serverKeyFile = serverKeyFile;
    this.tlsCryptFile = tlsCryptFile;
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    this.caCert = caCert;
    this.caKey = caKey;
    this.serverCert = serverCert;
    this.serverKey = serverKey;
    this.tlsCrypt = tlsCrypt;
    this.openvpnUsers = openvpnUsers;
    this.externalProxy = externalProxy;
    this.cipherMode = cipherMode;
    this.ciphers = ciphers;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // Panel-managed, auto-assigned block (UDP 10.2.x; TCP mirrors to 10.3.x).
    // Shown read-only in the form; not user-editable (OpenVPN needs one
    // contiguous `server` block per transport).
    this.ipRanges = ipRanges;
    // Simultaneous devices per account (1..64); 1 = legacy one-IP.
    this.userLimit = userLimit;
    // At the User Limit cap: "reject" a new device, or "accept" (evict oldest).
    this.userLimitStrategy = userLimitStrategy;
  }

  static fromJson(json = {}) {
    const ciphers = Array.isArray(json.ciphers)
      ? json.ciphers.slice()
      : Inbound.OpenvpnSettings.CIPHER_MODES.all.slice();
    return new Inbound.OpenvpnSettings(
      Protocols.OPENVPN,
      json.udpEnable ?? true,
      json.tcpEnable ?? true,
      json.tcpPort ?? 1194,
      json.dns1 ?? "8.8.8.8",
      json.dns2 ?? "8.8.4.4",
      json.mtu ?? 1500,
      json.caCert ?? "",
      json.caKey ?? "",
      json.serverCert ?? "",
      json.serverKey ?? "",
      json.tlsCrypt ?? "",
      Inbound.OpenvpnSettings.OpenvpnUser.fromJson(json.clients),
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
      json.cipherMode ?? Inbound.OpenvpnSettings.detectCipherMode(ciphers),
      ciphers,
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [],
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
      json.separatePorts ?? true,
      json.tlsUseFile ?? false,
      json.caCertFile ?? "",
      json.serverCertFile ?? "",
      json.serverKeyFile ?? "",
      json.tlsCryptFile ?? "",
    );
  }

  toJson() {
    return {
      udpEnable: this.udpEnable,
      tcpEnable: this.tcpEnable,
      tcpPort: this.tcpPort,
      separatePorts: this.separatePorts,
      tlsUseFile: this.tlsUseFile,
      caCertFile: this.caCertFile,
      serverCertFile: this.serverCertFile,
      serverKeyFile: this.serverKeyFile,
      tlsCryptFile: this.tlsCryptFile,
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      caCert: this.caCert,
      caKey: this.caKey,
      serverCert: this.serverCert,
      serverKey: this.serverKey,
      tlsCrypt: this.tlsCrypt,
      clients: Inbound.OpenvpnSettings.OpenvpnUser.toJsonArray(
        this.openvpnUsers,
      ),
      externalProxy: this.externalProxy,
      cipherMode: this.cipherMode,
      ciphers: this.ciphers,
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: this.ipRanges || [],
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
    };
  }
};

// Every data cipher the bundled OpenVPN 2.6 / OpenSSL 3 build can negotiate.
// List order is the preference order used for the `data-ciphers` directive.
Inbound.OpenvpnSettings.CIPHERS_AEAD = [
  "AES-256-GCM",
  "AES-192-GCM",
  "AES-128-GCM",
  "CHACHA20-POLY1305",
];
Inbound.OpenvpnSettings.CIPHERS_CBC = [
  "AES-256-CBC",
  "AES-192-CBC",
  "AES-128-CBC",
  "CAMELLIA-256-CBC",
  "CAMELLIA-192-CBC",
  "CAMELLIA-128-CBC",
  "ARIA-256-CBC",
  "ARIA-192-CBC",
  "ARIA-128-CBC",
  "SM4-CBC",
  "SEED-CBC",
  "BF-CBC",
  "CAST5-CBC",
  "DES-EDE3-CBC",
  "DES-EDE-CBC",
  "DES-CBC",
  "RC2-CBC",
  "RC2-64-CBC",
  "RC2-40-CBC",
];
Inbound.OpenvpnSettings.ALL_CIPHERS = [
  ...Inbound.OpenvpnSettings.CIPHERS_AEAD,
  ...Inbound.OpenvpnSettings.CIPHERS_CBC,
];
// Preset cipher selections behind the "Mode" dropdown. Kept in the same
// relative order as ALL_CIPHERS so set comparison in detectCipherMode works.
Inbound.OpenvpnSettings.CIPHER_MODES = {
  new: ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
  old: ["AES-256-CBC", "AES-192-CBC", "AES-128-CBC", "BF-CBC", "DES-EDE3-CBC"],
  all: [
    "AES-256-GCM",
    "AES-128-GCM",
    "CHACHA20-POLY1305",
    "AES-256-CBC",
    "AES-192-CBC",
    "AES-128-CBC",
    "BF-CBC",
    "DES-EDE3-CBC",
  ],
};
Inbound.OpenvpnSettings.detectCipherMode = function (ciphers) {
  const canonical = Inbound.OpenvpnSettings.ALL_CIPHERS.filter((c) =>
    ciphers.includes(c),
  ).join(":");
  for (const [mode, preset] of Object.entries(
    Inbound.OpenvpnSettings.CIPHER_MODES,
  )) {
    if (preset.join(":") === canonical) return mode;
  }
  return "custom";
};

Inbound.OpenvpnSettings.OpenvpnUser = class extends XrayCommonClass {
  constructor(
    id = RandomUtil.randomLowerAndNum(8),
    password = RandomUtil.randomSeq(10),
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.id = id;
    this.password = password;
    this.email = email;
    this.enable = enable;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json))
      return [new Inbound.OpenvpnSettings.OpenvpnUser()];
    return json.map(
      (j) =>
        new Inbound.OpenvpnSettings.OpenvpnUser(
          j.id,
          j.password,
          j.email,
          j.enable ?? true,
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.id,
      password: this.password,
      email: this.email,
      enable: this.enable,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// OpenConnect (ocserv). A single listener carries TLS (TCP) + DTLS (UDP) on the
// inbound's port; there is no udp/tcp split and no cipher selection (GnuTLS
// negotiates). TLS follows the Xray model: operator-supplied path or inline
// content, or a generated self-signed cert. The IP range is panel-managed
// (contiguous 10.4.x block) and shown read-only.
Inbound.OcservSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    dns1 = "8.8.8.8",
    dns2 = "8.8.4.4",
    mtu = 1420,
    tlsUseFile = false,
    certificateFile = "",
    keyFile = "",
    certificate = "",
    key = "",
    caCert = "",
    ocservUsers = [new Inbound.OcservSettings.OcservUser()],
    externalProxy = [],
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    userLimit = 1,
    userLimitStrategy = "accept",
  ) {
    super(protocol);
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    this.tlsUseFile = tlsUseFile;
    this.certificateFile = certificateFile;
    this.keyFile = keyFile;
    this.certificate = certificate;
    this.key = key;
    this.caCert = caCert;
    this.ocservUsers = ocservUsers;
    // Advertised endpoint override(s): {dest,port,remark}. No config file for this
    // protocol, so this only changes the server address shown in export / info.
    this.externalProxy = externalProxy;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // Panel-managed, auto-assigned 10.4.x block. Read-only in the form (ocserv
    // needs one contiguous ipv4-network).
    this.ipRanges = ipRanges;
    this.userLimit = userLimit;
    this.userLimitStrategy = userLimitStrategy;
  }

  static fromJson(json = {}) {
    return new Inbound.OcservSettings(
      Protocols.OPENCONNECT,
      json.dns1 ?? "8.8.8.8",
      json.dns2 ?? "8.8.4.4",
      json.mtu ?? 1420,
      json.tlsUseFile ?? false,
      json.certificateFile ?? "",
      json.keyFile ?? "",
      json.certificate ?? "",
      json.key ?? "",
      json.caCert ?? "",
      Inbound.OcservSettings.OcservUser.fromJson(json.clients),
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [],
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
    );
  }

  toJson() {
    return {
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      tlsUseFile: this.tlsUseFile,
      certificateFile: this.certificateFile,
      keyFile: this.keyFile,
      certificate: this.certificate,
      key: this.key,
      caCert: this.caCert,
      clients: Inbound.OcservSettings.OcservUser.toJsonArray(this.ocservUsers),
      externalProxy: this.externalProxy,
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: this.ipRanges || [],
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
    };
  }
};

Inbound.OcservSettings.OcservUser = class extends XrayCommonClass {
  constructor(
    id = RandomUtil.randomLowerAndNum(8),
    password = RandomUtil.randomSeq(10),
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.id = id;
    this.password = password;
    this.email = email;
    this.enable = enable;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json))
      return [new Inbound.OcservSettings.OcservUser()];
    return json.map(
      (j) =>
        new Inbound.OcservSettings.OcservUser(
          j.id,
          j.password,
          j.email,
          j.enable ?? true,
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.id,
      password: this.password,
      email: this.email,
      enable: this.enable,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// SSTP (accel-ppp). MS-SSTP over TLS (TCP), MSCHAPv2 auth. Same UI shape as
// OpenConnect: TLS follows the Xray model (operator-supplied path or inline
// content, or a generated self-signed cert). The IP range is panel-managed
// (contiguous 10.5.x block) and shown read-only.
Inbound.SstpSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    dns1 = "8.8.8.8",
    dns2 = "8.8.4.4",
    mtu = 1420,
    tlsUseFile = false,
    certificateFile = "",
    keyFile = "",
    certificate = "",
    key = "",
    caCert = "",
    sstpUsers = [new Inbound.SstpSettings.SstpUser()],
    externalProxy = [],
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    userLimit = 1,
    userLimitStrategy = "accept",
  ) {
    super(protocol);
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    this.tlsUseFile = tlsUseFile;
    this.certificateFile = certificateFile;
    this.keyFile = keyFile;
    this.certificate = certificate;
    this.key = key;
    this.caCert = caCert;
    this.sstpUsers = sstpUsers;
    // Advertised endpoint override(s): {dest,port,remark}. No config file for this
    // protocol, so this only changes the server address shown in export / info.
    this.externalProxy = externalProxy;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // Panel-managed, auto-assigned 10.5.x block. Read-only in the form.
    this.ipRanges = ipRanges;
    this.userLimit = userLimit;
    this.userLimitStrategy = userLimitStrategy;
  }

  static fromJson(json = {}) {
    return new Inbound.SstpSettings(
      Protocols.SSTP,
      json.dns1 ?? "8.8.8.8",
      json.dns2 ?? "8.8.4.4",
      json.mtu ?? 1420,
      json.tlsUseFile ?? false,
      json.certificateFile ?? "",
      json.keyFile ?? "",
      json.certificate ?? "",
      json.key ?? "",
      json.caCert ?? "",
      Inbound.SstpSettings.SstpUser.fromJson(json.clients),
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [],
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
    );
  }

  toJson() {
    return {
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      tlsUseFile: this.tlsUseFile,
      certificateFile: this.certificateFile,
      keyFile: this.keyFile,
      certificate: this.certificate,
      key: this.key,
      caCert: this.caCert,
      clients: Inbound.SstpSettings.SstpUser.toJsonArray(this.sstpUsers),
      externalProxy: this.externalProxy,
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: this.ipRanges || [],
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
    };
  }
};

Inbound.SstpSettings.SstpUser = class extends XrayCommonClass {
  constructor(
    id = RandomUtil.randomLowerAndNum(8),
    password = RandomUtil.randomSeq(10),
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.id = id;
    this.password = password;
    this.email = email;
    this.enable = enable;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json))
      return [new Inbound.SstpSettings.SstpUser()];
    return json.map(
      (j) =>
        new Inbound.SstpSettings.SstpUser(
          j.id,
          j.password,
          j.email,
          j.enable ?? true,
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.id,
      password: this.password,
      email: this.email,
      enable: this.enable,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// IKEv2/IPsec (strongSwan/charon). Same UI shape as SSTP/OpenConnect, plus an
// authentication-mode selector: EAP-MSCHAPv2 (username/password, the default),
// PSK (a single shared secret, no server cert), or EAP-TLS (mutual certificates).
// The server/machine cert follows the Xray model (operator-supplied path or
// inline content, or a generated self-signed CA + server cert — hence caCert).
// The IP range is panel-managed (contiguous block) and shown read-only.
Inbound.Ikev2Settings = class extends Inbound.Settings {
  constructor(
    protocol,
    dns1 = "8.8.8.8",
    dns2 = "8.8.4.4",
    mtu = 1420,
    authMode = "eap-mschapv2",
    psk = "",
    serverAddr = "",
    nattPort = 4500,
    tlsUseFile = false,
    certificateFile = "",
    keyFile = "",
    certificate = "",
    key = "",
    caCert = "",
    ikev2Users = [new Inbound.Ikev2Settings.Ikev2User()],
    externalProxy = [],
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    userLimit = 1,
    userLimitStrategy = "accept",
  ) {
    super(protocol);
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    this.authMode = authMode;
    this.psk = psk;
    this.serverAddr = serverAddr;
    // NAT-Traversal UDP port (strongSwan encapsulates ESP-in-UDP here once a
    // NAT is detected between client and server). Standard 4500.
    this.nattPort = nattPort;
    this.tlsUseFile = tlsUseFile;
    this.certificateFile = certificateFile;
    this.keyFile = keyFile;
    this.certificate = certificate;
    this.key = key;
    this.caCert = caCert;
    this.ikev2Users = ikev2Users;
    // Advertised endpoint override(s): {dest,port,remark}. No config file for this
    // protocol, so this only changes the server address shown in export / info.
    this.externalProxy = externalProxy;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // Panel-managed, auto-assigned block. Read-only in the form.
    this.ipRanges = ipRanges;
    this.userLimit = userLimit;
    this.userLimitStrategy = userLimitStrategy;
  }

  static fromJson(json = {}) {
    return new Inbound.Ikev2Settings(
      Protocols.IKEV2,
      json.dns1 ?? "8.8.8.8",
      json.dns2 ?? "8.8.4.4",
      json.mtu ?? 1420,
      json.authMode ?? "eap-mschapv2",
      json.psk ?? "",
      json.serverAddr ?? "",
      json.nattPort ?? 4500,
      json.tlsUseFile ?? false,
      json.certificateFile ?? "",
      json.keyFile ?? "",
      json.certificate ?? "",
      json.key ?? "",
      json.caCert ?? "",
      Inbound.Ikev2Settings.Ikev2User.fromJson(json.clients),
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [],
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
    );
  }

  toJson() {
    return {
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      authMode: this.authMode,
      psk: this.psk,
      serverAddr: this.serverAddr,
      nattPort: this.nattPort,
      tlsUseFile: this.tlsUseFile,
      certificateFile: this.certificateFile,
      keyFile: this.keyFile,
      certificate: this.certificate,
      key: this.key,
      caCert: this.caCert,
      clients: Inbound.Ikev2Settings.Ikev2User.toJsonArray(this.ikev2Users),
      externalProxy: this.externalProxy,
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: this.ipRanges || [],
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
    };
  }
};

Inbound.Ikev2Settings.Ikev2User = class extends XrayCommonClass {
  constructor(
    id = RandomUtil.randomLowerAndNum(8),
    password = RandomUtil.randomSeq(10),
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.id = id;
    this.password = password;
    this.email = email;
    this.enable = enable;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json))
      return [new Inbound.Ikev2Settings.Ikev2User()];
    return json.map(
      (j) =>
        new Inbound.Ikev2Settings.Ikev2User(
          j.id,
          j.password,
          j.email,
          j.enable ?? true,
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.id,
      password: this.password,
      email: this.email,
      enable: this.enable,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// WireGuard (C): the in-kernel wireguard module driven in-process via wgctrl (NO
// daemon, NO RADIUS). Keys are server-side: the backend mints the server keypair
// and one keypair per device (K = the account's User Limit) on save, so the UI
// never generates keys. Same UI shape as SSTP/IKEv2 (auto-managed 10.7.x block
// shown read-only, DNS, MTU, User-Limit, client-to-client), minus TLS (WireGuard
// carries no certificate), plus an optional per-device preshared-key toggle. The
// serverPrivKey/serverPubKey round-trip so a backend-minted keypair survives edits.
Inbound.WgcSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    dns1 = "1.1.1.1",
    dns2 = "1.0.0.1",
    mtu = 1420,
    serverPrivKey = "",
    serverPubKey = "",
    pskEnable = false,
    wgcUsers = [new Inbound.WgcSettings.WgUser()],
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    userLimit = 1,
    userLimitStrategy = "accept",
    externalProxy = [],
  ) {
    super(protocol);
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    // Backend-generated server keypair. Read-only in the UI (never minted client-side).
    this.serverPrivKey = serverPrivKey;
    this.serverPubKey = serverPubKey;
    // Optional preshared key: when on, the backend mints a PSK per device.
    this.pskEnable = pskEnable;
    this.wgcUsers = wgcUsers;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // Panel-managed, auto-assigned 10.7.x block. Read-only in the form.
    this.ipRanges = ipRanges;
    this.userLimit = userLimit;
    this.userLimitStrategy = userLimitStrategy;
    // Optional external-proxy endpoints: alternate Endpoints (relay/CDN host:port)
    // rendered into the generated client config + QR instead of this server's address.
    this.externalProxy = externalProxy;
  }

  static fromJson(json = {}) {
    return new Inbound.WgcSettings(
      Protocols.WGC,
      json.dns1 ?? "1.1.1.1",
      json.dns2 ?? "1.0.0.1",
      json.mtu ?? 1420,
      json.serverPrivKey ?? "",
      json.serverPubKey ?? "",
      json.pskEnable ?? false,
      Inbound.WgcSettings.WgUser.fromJson(json.clients),
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [],
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
    );
  }

  toJson() {
    return {
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      serverPrivKey: this.serverPrivKey,
      serverPubKey: this.serverPubKey,
      pskEnable: this.pskEnable,
      clients: Inbound.WgcSettings.WgUser.toJsonArray(this.wgcUsers),
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: this.ipRanges || [],
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
      externalProxy: this.externalProxy || [],
    };
  }
};

// A WireGuard (C) account (gateway model). Identity is `email` — there is NO username or
// password (the public key is the credential). ONE keypair per account {privKey,pubKey,psk}
// minted by the backend; the config Address is the account's whole block CIDR (e.g. a /29).
// The standard usage/quota/expiry fields are kept so the shared client form works.
Inbound.WgcSettings.WgUser = class extends XrayCommonClass {
  constructor(
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    privKey = "",
    pubKey = "",
    psk = "",
    devices = [],
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.email = email;
    this.enable = enable;
    // One keypair per account, minted by the backend (empty on add). Read-only in the UI.
    this.privKey = privKey;
    this.pubKey = pubKey;
    this.psk = psk;
    // Per-device keypairs, one slot per User Limit device, minted server-side.
    // MUST round-trip: the backend stores clients[].devices, but this model used to
    // drop the field, so every save posted the account back WITHOUT it. ReconcileKeys
    // then rebuilt device 0 from the legacy privKey mirror below and MINTED FRESH KEYS
    // for devices 2..K, silently invalidating every config already downloaded for
    // them. Invisible at User Limit 1 (the default), which is why it survived.
    this.devices = Array.isArray(devices) ? devices : [];
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  // See MtprotoUser.id: same email-as-identity model, same reason. toJson() writes
  // id=email but fromJson() cannot restore it through the constructor, so the live
  // object needs this or every id-keyed path (edit, row-key) sees undefined.
  get id() {
    return this.email;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json))
      return [new Inbound.WgcSettings.WgUser()];
    return json.map(
      (j) =>
        new Inbound.WgcSettings.WgUser(
          j.email,
          j.enable ?? true,
          j.privKey ?? "",
          j.pubKey ?? "",
          j.psk ?? "",
          Array.isArray(j.devices) ? j.devices : [],
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.email, // identity = email (no username); keeps shared id-based client logic working
      email: this.email,
      enable: this.enable,
      privKey: this.privKey,
      pubKey: this.pubKey,
      psk: this.psk,
      devices: this.devices,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// AmneziaWG (awg) inbound settings. A near-exact clone of WgcSettings (same gateway
// model: backend-minted server keypair + one keypair per account, auto-managed IP block,
// DNS/MTU/User-Limit/client-to-client), PLUS the AWG 1.0 DPI-obfuscation parameters.
// Jc/Jmin/Jmax/S1/S2 are editable NUMBERS; the magic headers H1-H4 are strings minted by
// the backend (read-only in the UI, like serverPubKey). The JSON field names here MUST
// match the Go awgSettings struct (web/service/awg.go) exactly.
Inbound.AwgSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    dns1 = "1.1.1.1",
    dns2 = "1.0.0.1",
    mtu = 1420,
    jc = 4,
    jmin = 8,
    jmax = 80,
    s1 = 77,
    s2 = 90,
    h1 = "",
    h2 = "",
    h3 = "",
    h4 = "",
    serverPrivKey = "",
    serverPubKey = "",
    pskEnable = false,
    awgUsers = [new Inbound.AwgSettings.AwgUser()],
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    // User Limit K = how many DEVICES an account gets, and the panel provisions one
    // keypair + one config + one /32 per device. 1 is the default because 0 means the
    // maximum (64), which under that rule would mint 64 keypairs and render 64 configs
    // for every account, and would fit only ~3 accounts per /24. Raise it to the number
    // of devices the account should actually run.
    userLimit = 1,
    userLimitStrategy = "accept",
    externalProxy = [],
  ) {
    super(protocol);
    this.dns1 = dns1;
    this.dns2 = dns2;
    this.mtu = mtu;
    // AWG 1.0 obfuscation. Junk/size params (numbers) are editable; magic headers
    // H1-H4 (strings) are backend-minted and shown read-only, like serverPubKey.
    this.jc = jc;
    this.jmin = jmin;
    this.jmax = jmax;
    this.s1 = s1;
    this.s2 = s2;
    this.h1 = h1;
    this.h2 = h2;
    this.h3 = h3;
    this.h4 = h4;
    // Backend-generated server keypair. Read-only in the UI (never minted client-side).
    this.serverPrivKey = serverPrivKey;
    this.serverPubKey = serverPubKey;
    // Optional preshared key: when on, the backend mints a PSK per device.
    this.pskEnable = pskEnable;
    this.awgUsers = awgUsers;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // Panel-managed, auto-assigned block. Read-only in the form.
    this.ipRanges = ipRanges;
    this.userLimit = userLimit;
    this.userLimitStrategy = userLimitStrategy;
    // Optional external-proxy endpoints: alternate Endpoints (relay/CDN host:port)
    // rendered into the generated client config + QR instead of this server's address.
    this.externalProxy = externalProxy;
  }

  static fromJson(json = {}) {
    return new Inbound.AwgSettings(
      Protocols.AWG,
      json.dns1 ?? "1.1.1.1",
      json.dns2 ?? "1.0.0.1",
      json.mtu ?? 1420,
      json.jc ?? 4,
      json.jmin ?? 8,
      json.jmax ?? 80,
      json.s1 ?? 77,
      json.s2 ?? 90,
      json.h1 ?? "",
      json.h2 ?? "",
      json.h3 ?? "",
      json.h4 ?? "",
      json.serverPrivKey ?? "",
      json.serverPubKey ?? "",
      json.pskEnable ?? false,
      Inbound.AwgSettings.AwgUser.fromJson(json.clients),
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [],
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
    );
  }

  toJson() {
    return {
      dns1: this.dns1,
      dns2: this.dns2,
      mtu: this.mtu,
      jc: this.jc,
      jmin: this.jmin,
      jmax: this.jmax,
      s1: this.s1,
      s2: this.s2,
      h1: this.h1,
      h2: this.h2,
      h3: this.h3,
      h4: this.h4,
      serverPrivKey: this.serverPrivKey,
      serverPubKey: this.serverPubKey,
      pskEnable: this.pskEnable,
      clients: Inbound.AwgSettings.AwgUser.toJsonArray(this.awgUsers),
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: this.ipRanges || [],
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
      externalProxy: this.externalProxy || [],
    };
  }
};

// An AmneziaWG account (gateway model). Identity is `email` — there is NO username or
// password (the public key is the credential). ONE keypair per account {privKey,pubKey,psk}
// minted by the backend; the config Address is the account's whole block CIDR (e.g. a /29).
// The standard usage/quota/expiry fields are kept so the shared client form works.
Inbound.AwgSettings.AwgUser = class extends XrayCommonClass {
  constructor(
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    privKey = "",
    pubKey = "",
    psk = "",
    devices = [],
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.email = email;
    this.enable = enable;
    // One keypair per account, minted by the backend (empty on add). Read-only in the UI.
    this.privKey = privKey;
    this.pubKey = pubKey;
    this.psk = psk;
    // Per-device keypairs, one slot per User Limit device, minted server-side.
    // MUST round-trip: the backend stores clients[].devices, but this model used to
    // drop the field, so every save posted the account back WITHOUT it. ReconcileKeys
    // then rebuilt device 0 from the legacy privKey mirror below and MINTED FRESH KEYS
    // for devices 2..K, silently invalidating every config already downloaded for
    // them. Invisible at User Limit 1 (the default), which is why it survived.
    this.devices = Array.isArray(devices) ? devices : [];
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: the backend allocates clients[].slot (the account's index into
    // the inbound's address pool) and every save posts the whole client back, so a model
    // that forgets it deletes it — and the account's tunnel address would fall back to
    // its position in the list, which is what moved everyone's address when an earlier
    // account was deleted. The browser NEVER invents one: undefined means "server
    // allocates".
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  // See MtprotoUser.id: same email-as-identity model, same reason. toJson() writes
  // id=email but fromJson() cannot restore it through the constructor, so the live
  // object needs this or every id-keyed path (edit, row-key) sees undefined.
  get id() {
    return this.email;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json))
      return [new Inbound.AwgSettings.AwgUser()];
    return json.map(
      (j) =>
        new Inbound.AwgSettings.AwgUser(
          j.email,
          j.enable ?? true,
          j.privKey ?? "",
          j.pubKey ?? "",
          j.psk ?? "",
          Array.isArray(j.devices) ? j.devices : [],
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.email, // identity = email (no username); keeps shared id-based client logic working
      email: this.email,
      enable: this.enable,
      privKey: this.privKey,
      pubKey: this.pubKey,
      psk: this.psk,
      devices: this.devices,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// GRE inbound settings. Same gateway addressing model as wg-c/awg (auto-managed block,
// User-Limit-sized per-account block, client-to-client / cross-inbound), but there is NO
// key material of any kind: GRE carries no credentials, so an account is identified by its
// address alone and a "device" is a customer ROUTER identified by its public IP.
//
// The JSON field names here MUST match the Go greSettings struct (web/service/gre.go).
//
// ipsecEnable/allowRaw mirror the L2TP pair and give the same three states (raw only,
// IPsec only, both). fouEnable is deliberately SEPARATE rather than bundled with IPsec:
// FOU is a Linux/OpenWrt-only UDP encapsulation, so tying it to the encrypted mode would
// lock MikroTik/Cisco/Keenetic out of encryption entirely.
Inbound.GreSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    // mtu 0 = let the kernel choose. The right default differs per encapsulation
    // (1476 raw, 1464 under FOU) and the kernel already knows which, so pinning a
    // number here would be wrong for the other mode.
    mtu = 0,
    ttl = 64,
    ipsecEnable = false,
    ipsecPsk = RandomUtil.randomSeq(24),
    allowRaw = true,
    fouEnable = false,
    fouPort = 15547,
    greUsers = [new Inbound.GreSettings.GreUser()],
    clientToClient = false,
    crossInbound = false,
    ipRanges = [],
    // User Limit K = how many peer ROUTERS an account may attach, and the panel gives it
    // K consecutive inner addresses (one per peer). The cap is structural: only K
    // addresses exist, so there is nothing to enforce at connect time. GRE has no session
    // and no auth event, so a runtime limit could not be enforced anyway.
    userLimit = 1,
    // Kept for parity with the shared form; GRE enforces K structurally, so there is no
    // "evict the oldest" admission decision to make.
    userLimitStrategy = "accept",
  ) {
    super(protocol);
    this.mtu = mtu;
    this.ttl = ttl;
    this.ipsecEnable = ipsecEnable;
    this.ipsecPsk = ipsecPsk;
    this.allowRaw = allowRaw;
    this.fouEnable = fouEnable;
    this.fouPort = fouPort;
    this.greUsers = greUsers;
    this.clientToClient = clientToClient;
    this.crossInbound = crossInbound;
    // Panel-managed, auto-assigned block. Read-only in the form.
    this.ipRanges = ipRanges;
    this.userLimit = userLimit;
    this.userLimitStrategy = userLimitStrategy;
  }

  static fromJson(json = {}) {
    return new Inbound.GreSettings(
      Protocols.GRE,
      json.mtu ?? 0,
      json.ttl ?? 64,
      json.ipsecEnable ?? false,
      json.ipsecPsk ?? "",
      json.allowRaw ?? true,
      json.fouEnable ?? false,
      json.fouPort ?? 15547,
      Inbound.GreSettings.GreUser.fromJson(json.clients),
      json.clientToClient ?? false,
      json.crossInbound ?? false,
      Array.isArray(json.ipRanges) ? json.ipRanges.slice() : [],
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
    );
  }

  toJson() {
    return {
      mtu: this.mtu,
      ttl: this.ttl,
      ipsecEnable: this.ipsecEnable,
      ipsecPsk: this.ipsecPsk,
      allowRaw: this.allowRaw,
      fouEnable: this.fouEnable,
      fouPort: this.fouPort,
      clients: Inbound.GreSettings.GreUser.toJsonArray(this.greUsers),
      clientToClient: this.clientToClient,
      crossInbound: this.crossInbound,
      ipRanges: this.ipRanges || [],
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
    };
  }
};

// A GRE account. Identity is `email` — there is no username, password or key, because the
// protocol carries none. `peers` holds one slot per User Limit peer router.
//
// A peer's `peerIp` is the customer router's own public address. Leaving it EMPTY is a
// deliberate, supported choice, not an incomplete record: that peer is then served by the
// shared catch-all tunnel and its return path is learned from its first packets, which is
// what lets a customer on a dynamic IP (or one who does not know their address yet) work.
Inbound.GreSettings.GreUser = class extends XrayCommonClass {
  constructor(
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    peers = [],
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    slot = undefined,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.email = email;
    this.enable = enable;
    // MUST round-trip: the backend sizes clients[].peers to the User Limit and every save
    // posts the whole client back, so a model that drops the field would wipe the
    // operator's peer addresses on the next edit. Same trap AwgUser.devices documents.
    this.peers = Array.isArray(peers) ? peers : [];
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    // MUST round-trip: see AwgUser.slot. undefined means "server allocates"; the browser
    // never invents one, and forgetting it would move every account's tunnel address when
    // an earlier account is deleted.
    this.slot = slot;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  // See AwgUser.id / MtprotoUser.id: email-as-identity, so the live object needs this or
  // every id-keyed path (edit, row-key) sees undefined and posts to /updateClient/undefined.
  get id() {
    return this.email;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json))
      return [new Inbound.GreSettings.GreUser()];
    return json.map(
      (j) =>
        new Inbound.GreSettings.GreUser(
          j.email,
          j.enable ?? true,
          Array.isArray(j.peers) ? j.peers : [],
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.slot,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.email, // identity = email (no username/key); keeps shared id-based logic working
      email: this.email,
      enable: this.enable,
      peers: this.peers,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      slot: this.slot,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// Peer-slot accessors for the GRE client form.
//
// The backend sizes clients[].peers to the inbound's User Limit on save, but a brand-new
// account has an empty array and the operator still has to be able to type into every
// slot. These render K rows without ever growing the array DURING render: mutating state
// from a v-for expression re-triggers the render and loops. The array is only extended in
// the setter, i.e. from a real user event.
function grePeerCount(inbound) {
  const k = inbound && inbound.settings ? inbound.settings.userLimit : 1;
  // 0 means "the maximum", matching wgcEffectiveK on the Go side.
  if (k === 0 || k === undefined || k === null) return 64;
  return Math.max(1, Math.min(64, Math.floor(k)));
}

function grePeerAt(client, i) {
  if (!client || !Array.isArray(client.peers)) return null;
  return client.peers[i] || null;
}

function grePeerField(client, i, field) {
  const p = grePeerAt(client, i);
  return p && p[field] ? p[field] : "";
}

function greSetPeerField(client, i, field, value) {
  if (!client) return;
  if (!Array.isArray(client.peers)) {
    Vue.set(client, "peers", []);
  }
  while (client.peers.length <= i) {
    client.peers.push({ peerIp: "", remark: "" });
  }
  const next = Object.assign({}, client.peers[i]);
  next[field] = (value || "").trim();
  Vue.set(client.peers, i, next);
}

// MTProto Proxy (Telegram) inbound settings.
//
// Unlike every other VPN protocol here there is NO addressing block: MTProto is a
// userspace relay, so clients keep their own IP and the backend assigns nothing.
// Hence no ipRanges/dns/mtu/localIp, just which connection modes this inbound
// honours, the FakeTLS domain, the device cap, and the optional ad tag.
//
// userLimitStrategy is deliberately absent: the proxy enforces the device cap
// itself by refusing the excess connection, so there is no "evict the oldest"
// choice to make (the panel never sees the admission).
// Shown when the client form refuses to turn off an account's LAST connection mode.
// Not merely advisory: with every mode off, no secret can dial the account, so the
// backend drops it from the proxy config (activeClients) rather than render an entry
// telemt would read as "unrestricted": the exact opposite of what was asked.
const MTPROTO_LAST_MODE_WARNING =
  "At least one connection mode must stay enabled: an account with none has no usable link.";

Inbound.MtprotoSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    mtprotoUsers = [new Inbound.MtprotoSettings.MtprotoUser()],
  ) {
    super(protocol);
    // The inbound owns nothing but its port: modes, FakeTLS domain, User Limit,
    // ad tag and external proxy are all per-account, because the proxy keys them
    // off the authenticated secret rather than the socket.
    this.mtprotoUsers = mtprotoUsers;
  }

  static fromJson(json = {}) {
    return new Inbound.MtprotoSettings(
      Protocols.MTPROTO,
      Inbound.MtprotoSettings.MtprotoUser.fromJson(json.clients),
    );
  }

  toJson() {
    return {
      clients: Inbound.MtprotoSettings.MtprotoUser.toJsonArray(this.mtprotoUsers),
    };
  }
};

// An MTProto Proxy account. Identity is `email`, there is NO username (the
// WireGuard (C) model); the credential is `secret` (32 hex). The secret is minted
// client-side because, unlike a WireGuard keypair, it is just random bytes, and
// having it immediately lets the tg:// links render on add; the backend re-mints
// any account whose secret is blank.
//
// Modes / FakeTLS domain / User Limit / ad tag / external proxy live HERE rather
// than on the inbound: the proxy keys them off the authenticated secret, so one
// inbound can serve accounts with entirely different modes and links.
Inbound.MtprotoSettings.MtprotoUser = class extends XrayCommonClass {
  constructor(
    email = RandomUtil.randomLowerAndNum(9),
    secret = RandomUtil.randomSeq(32, { type: "hex" }),
    enable = true,
    modeClassic = true,
    modeSecure = true,
    modeTls = true,
    tlsDomain = "www.google.com",
    adtagEnable = false,
    adtag = "",
    userLimit = 0,
    externalProxy = [],
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.email = email;
    this.secret = secret;
    this.enable = enable;
    this.modeClassic = modeClassic;
    this.modeSecure = modeSecure;
    this.modeTls = modeTls;
    this.tlsDomain = tlsDomain;
    this.adtagEnable = adtagEnable;
    this.adtag = adtag;
    this.userLimit = userLimit;
    this.externalProxy = externalProxy;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  // Identity is the email (no username), but the panel's shared client plumbing is
  // id-keyed: the client modal's oldClientId, findIndexOfClient, and the client
  // table's row-key all read client.id. toJson() writes id=email, so the STORED
  // client has one, but fromJson() rehydrates through the constructor, which never
  // takes an id. Without this getter the live object's id is undefined, the edit
  // POSTs to /updateClient/undefined, and the backend cannot find the account
  // ("empty client ID"). A getter cannot drift out of sync with email the way a
  // copied field would.
  get id() {
    return this.email;
  }

  static fromJson(json = []) {
    if (!json) return [];
    return json.map((client) =>
      new Inbound.MtprotoSettings.MtprotoUser(
        client.email ?? "",
        client.secret ?? RandomUtil.randomSeq(32, { type: "hex" }),
        client.enable ?? true,
        client.modeClassic ?? true,
        client.modeSecure ?? true,
        client.modeTls ?? true,
        client.tlsDomain ?? "www.google.com",
        client.adtagEnable ?? false,
        client.adtag ?? "",
        client.userLimit ?? 0,
        Array.isArray(client.externalProxy) ? client.externalProxy : [],
        client.expiryTime ?? 0,
        client.tgId ?? "",
        client.subId ?? "",
        client.comment ?? "",
        client.totalGB ?? 0,
        client.limitIp ?? 0,
        client.reset ?? 0,
        client.created_at,
        client.updated_at,
      ),
    );
  }

  // The client-facing secret for one mode. The 16-byte secret is the same in all
  // three; the prefix is what tells the Telegram client (and the proxy) which
  // transport to speak. FakeTLS additionally carries the hex-encoded domain.
  secretFor(mode) {
    if (mode === "secure") return "dd" + this.secret;
    if (mode === "tls") {
      const domain = (this.tlsDomain || "www.google.com").trim();
      const hex = Array.from(new TextEncoder().encode(domain))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      return "ee" + this.secret + hex;
    }
    return this.secret;
  }

  // Which modes this account may actually use, the same set the backend enforces
  // via [access.user_modes]. Drives which links/QRs are offered, so a disabled mode
  // is never handed out as a working link.
  enabledModes() {
    const out = [];
    if (this.modeClassic) out.push("classic");
    if (this.modeSecure) out.push("secure");
    if (this.modeTls) out.push("tls");
    return out;
  }

  // One tg:// link per enabled mode, per endpoint. External Proxy endpoints replace
  // this server's address (a relay/CDN in front); with none set, the panel's own
  // host:port is used.
  links(host, port) {
    const endpoints =
      Array.isArray(this.externalProxy) && this.externalProxy.length > 0
        ? this.externalProxy.map((p) => ({
            host: p.dest,
            port: p.port,
            remark: p.remark || "",
          }))
        : [{ host: host, port: port, remark: "" }];
    const labels = { classic: "Classic", secure: "Secure (dd)", tls: "FakeTLS (ee)" };
    const out = [];
    for (const ep of endpoints) {
      for (const mode of this.enabledModes()) {
        out.push({
          mode: mode,
          label: labels[mode] + (ep.remark ? `, ${ep.remark}` : ""),
          link:
            "tg://proxy?server=" +
            encodeURIComponent(ep.host) +
            "&port=" +
            ep.port +
            "&secret=" +
            this.secretFor(mode),
        });
      }
    }
    return out;
  }

  static toJsonArray(clients) {
    return clients.map((client) => client.toJson());
  }

  toJson() {
    return {
      id: this.email, // identity = email (no username); keeps shared id-based client logic working
      email: this.email,
      secret: this.secret,
      enable: this.enable,
      modeClassic: this.modeClassic,
      modeSecure: this.modeSecure,
      modeTls: this.modeTls,
      tlsDomain: this.tlsDomain,
      adtagEnable: this.adtagEnable,
      adtag: this.adtag,
      userLimit: this.userLimit,
      externalProxy: this.externalProxy || [],
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

// SSH relay inbound settings. Like MTProto this is a userspace RELAY, so there is NO
// addressing block (no ipRanges/dns/mtu): clients keep their own IP and the backend
// assigns nothing. The inbound owns only its listen port, the account list, an
// inbound-level device cap (User Limit K + strategy) and an optional External Proxy
// endpoint list (alternate host:port written into the generated client config, like
// wg-c). The ed25519 host key is server-managed: it round-trips through toJson/fromJson
// so a backend-minted key survives edits and the client's host-key pin stays stable,
// but it is never surfaced in the UI.
Inbound.SshSettings = class extends Inbound.Settings {
  constructor(
    protocol,
    userLimit = 0,
    userLimitStrategy = "accept",
    externalProxy = [],
    sshUsers = [new Inbound.SshSettings.SshUser()],
    hostKey = "",
  ) {
    super(protocol);
    // Inbound-level device cap, same convention as every other protocol: 0 = no limit
    // (the default), 1 = single device, up to 64. An ABSENT value (legacy) resolves to
    // 1 in fromJson, matching the backend's effectiveSshK(nil).
    this.userLimit = userLimit;
    // At the cap: "accept" (default, evict the oldest device) or "reject" a new device.
    this.userLimitStrategy = userLimitStrategy;
    // Optional external-proxy endpoints: alternate host:port (relay/CDN) rendered into
    // the generated client config instead of this server's own address.
    this.externalProxy = externalProxy;
    this.sshUsers = sshUsers;
    // Backend-minted ed25519 host private key (PEM). Round-trips so it survives edits;
    // never shown or edited in the browser.
    this.hostKey = hostKey;
  }

  static fromJson(json = {}) {
    return new Inbound.SshSettings(
      Protocols.SSH,
      // *int on the backend, so an absent value is NOT the same as 0: absent means a
      // legacy single-device inbound (1), 0 means no limit. Mirrors every other protocol.
      json.userLimit ?? 1,
      json.userLimitStrategy ?? "accept",
      Array.isArray(json.externalProxy) ? json.externalProxy : [],
      Inbound.SshSettings.SshUser.fromJson(json.clients),
      json.hostKey ?? "",
    );
  }

  toJson() {
    return {
      userLimit: this.userLimit,
      userLimitStrategy: this.userLimitStrategy,
      externalProxy: this.externalProxy || [],
      clients: Inbound.SshSettings.SshUser.toJsonArray(this.sshUsers),
      hostKey: this.hostKey,
    };
  }
};

// An SSH account. Identity is the real `id` field (the SSH login username, auto-
// generated and user-editable); the credential is `password`. This is NOT an
// email-identity protocol, so there is deliberately no get id() getter (that is only
// for wg-c/mtproto). The standard usage/quota/expiry fields ride along so the shared
// client form and table work unchanged (mirrors the L2TP/IKEv2 user shape).
Inbound.SshSettings.SshUser = class extends XrayCommonClass {
  constructor(
    id = RandomUtil.randomLowerAndNum(8),
    password = RandomUtil.randomSeq(10),
    email = RandomUtil.randomLowerAndNum(9),
    enable = true,
    expiryTime = 0,
    tgId = "",
    subId = RandomUtil.randomLowerAndNum(16),
    comment = "",
    totalGB = 0,
    limitIp = 0,
    reset = 0,
    created_at = undefined,
    updated_at = undefined,
  ) {
    super();
    this.id = id;
    this.password = password;
    this.email = email;
    this.enable = enable;
    this.expiryTime = expiryTime;
    this.tgId = tgId;
    this.subId = subId;
    this.comment = comment;
    this.totalGB = totalGB;
    this.limitIp = limitIp;
    this.reset = reset;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static fromJson(json = []) {
    if (!Array.isArray(json)) return [new Inbound.SshSettings.SshUser()];
    return json.map(
      (j) =>
        new Inbound.SshSettings.SshUser(
          j.id,
          j.password,
          j.email,
          j.enable ?? true,
          j.expiryTime ?? 0,
          j.tgId ?? "",
          j.subId ?? "",
          j.comment ?? "",
          j.totalGB ?? 0,
          j.limitIp ?? j.ipLimit ?? 0,
          j.reset ?? 0,
          j.created_at,
          j.updated_at,
        ),
    );
  }

  static toJsonArray(users) {
    return users.map((u) => u.toJson());
  }

  toJson() {
    return {
      id: this.id,
      password: this.password,
      email: this.email,
      enable: this.enable,
      expiryTime: this.expiryTime,
      tgId: this.tgId,
      subId: this.subId,
      comment: this.comment,
      totalGB: this.totalGB,
      limitIp: this.limitIp,
      reset: this.reset,
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }

  get _expiryTime() {
    if (this.expiryTime === 0) {
      return null;
    }
    if (this.expiryTime < 0) {
      return this.expiryTime / -86400000;
    }
    return moment(this.expiryTime);
  }

  set _expiryTime(t) {
    if (t == null || t === "") {
      this.expiryTime = 0;
    } else {
      this.expiryTime = t.valueOf();
    }
  }

  get _totalGB() {
    return NumberFormatter.toFixed(this.totalGB / SizeFormatter.ONE_GB, 2);
  }

  set _totalGB(gb) {
    this.totalGB = NumberFormatter.toFixed(gb * SizeFormatter.ONE_GB, 0);
  }
};

Inbound.TunnelSettings = class extends Inbound.Settings {
    constructor(
        protocol,
        address,
        port,
        portMap = [],
        network = 'tcp,udp',
        followRedirect = false
    ) {
        super(protocol);
        this.address = address;
        this.port = port;
        this.portMap = portMap;
        this.network = network;
        this.followRedirect = followRedirect;
    }

    static fromJson(json = {}) {
        return new Inbound.TunnelSettings(
            Protocols.TUNNEL,
            json.address,
            json.port,
            XrayCommonClass.toHeaders(json.portMap),
            json.network,
            json.followRedirect,
        );
    }

    toJson() {
        return {
            address: this.address,
            port: this.port,
            portMap: XrayCommonClass.toV2Headers(this.portMap, false),
            network: this.network,
            followRedirect: this.followRedirect,
        };
    }
};

Inbound.MixedSettings = class extends Inbound.Settings {
    constructor(protocol, auth = 'password', accounts = [new Inbound.MixedSettings.SocksAccount()], udp = false, ip = '127.0.0.1') {
        super(protocol);
        this.auth = auth;
        this.accounts = accounts;
        this.udp = udp;
        this.ip = ip;
    }

    addAccount(account) {
        this.accounts.push(account);
    }

    delAccount(index) {
        this.accounts.splice(index, 1);
    }

    static fromJson(json = {}) {
        let accounts;
        if (json.auth === 'password') {
            accounts = json.accounts.map(
                account => Inbound.MixedSettings.SocksAccount.fromJson(account)
            )
        }
        return new Inbound.MixedSettings(
            Protocols.MIXED,
            json.auth,
            accounts,
            json.udp,
            json.ip,
        );
    }

    toJson() {
        return {
            auth: this.auth,
            accounts: this.auth === 'password' ? this.accounts.map(account => account.toJson()) : undefined,
            udp: this.udp,
            ip: this.ip,
        };
    }
};
Inbound.MixedSettings.SocksAccount = class extends XrayCommonClass {
    constructor(user = RandomUtil.randomSeq(10), pass = RandomUtil.randomSeq(10)) {
        super();
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json = {}) {
        return new Inbound.MixedSettings.SocksAccount(json.user, json.pass);
    }
};

Inbound.HttpSettings = class extends Inbound.Settings {
    constructor(
        protocol,
        accounts = [new Inbound.HttpSettings.HttpAccount()],
        allowTransparent = false,
    ) {
        super(protocol);
        this.accounts = accounts;
        this.allowTransparent = allowTransparent;
    }

    addAccount(account) {
        this.accounts.push(account);
    }

    delAccount(index) {
        this.accounts.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Inbound.HttpSettings(
            Protocols.HTTP,
            json.accounts.map(account => Inbound.HttpSettings.HttpAccount.fromJson(account)),
            json.allowTransparent,
        );
    }

    toJson() {
        return {
            accounts: Inbound.HttpSettings.toJsonArray(this.accounts),
            allowTransparent: this.allowTransparent,
        };
    }
};

Inbound.HttpSettings.HttpAccount = class extends XrayCommonClass {
    constructor(user = RandomUtil.randomSeq(10), pass = RandomUtil.randomSeq(10)) {
        super();
        this.user = user;
        this.pass = pass;
    }

    static fromJson(json = {}) {
        return new Inbound.HttpSettings.HttpAccount(json.user, json.pass);
    }
};

Inbound.WireguardSettings = class extends XrayCommonClass {
    constructor(
        protocol,
        mtu = 1420,
        secretKey = Wireguard.generateKeypair().privateKey,
        peers = [new Inbound.WireguardSettings.Peer()],
        noKernelTun = false
    ) {
        super(protocol);
        this.mtu = mtu;
        this.secretKey = secretKey;
        this.pubKey = secretKey.length > 0 ? Wireguard.generateKeypair(secretKey).publicKey : '';
        this.peers = peers;
        this.noKernelTun = noKernelTun;
    }

    addPeer() {
        this.peers.push(new Inbound.WireguardSettings.Peer(null, null, '', ['10.0.0.' + (this.peers.length + 2)]));
    }

    delPeer(index) {
        this.peers.splice(index, 1);
    }

    static fromJson(json = {}) {
        return new Inbound.WireguardSettings(
            Protocols.WIREGUARD,
            json.mtu,
            json.secretKey,
            json.peers.map(peer => Inbound.WireguardSettings.Peer.fromJson(peer)),
            json.noKernelTun,
        );
    }

    toJson() {
        return {
            mtu: this.mtu ?? undefined,
            secretKey: this.secretKey,
            peers: Inbound.WireguardSettings.Peer.toJsonArray(this.peers),
            noKernelTun: this.noKernelTun,
        };
    }
};

Inbound.WireguardSettings.Peer = class extends XrayCommonClass {
    constructor(privateKey, publicKey, psk = '', allowedIPs = ['10.0.0.2/32'], keepAlive = 0) {
        super();
        this.privateKey = privateKey
        this.publicKey = publicKey;
        if (!this.publicKey) {
            [this.publicKey, this.privateKey] = Object.values(Wireguard.generateKeypair())
        }
        this.psk = psk;
        allowedIPs.forEach((a, index) => {
            if (a.length > 0 && !a.includes('/')) allowedIPs[index] += '/32';
        })
        this.allowedIPs = allowedIPs;
        this.keepAlive = keepAlive;
    }

    static fromJson(json = {}) {
        return new Inbound.WireguardSettings.Peer(
            json.privateKey,
            json.publicKey,
            json.preSharedKey,
            json.allowedIPs,
            json.keepAlive
        );
    }

    toJson() {
        this.allowedIPs.forEach((a, index) => {
            if (a.length > 0 && !a.includes('/')) this.allowedIPs[index] += '/32';
        });
        return {
            privateKey: this.privateKey,
            publicKey: this.publicKey,
            preSharedKey: this.psk.length > 0 ? this.psk : undefined,
            allowedIPs: this.allowedIPs,
            keepAlive: this.keepAlive ?? undefined,
        };
    }
};

Inbound.TunSettings = class extends Inbound.Settings {
    constructor(
        protocol,
        name = 'xray0',
        mtu = [1500, 1280],
        gateway = [],
        dns = [],
        userLevel = 0,
        autoSystemRoutingTable = [],
        autoOutboundsInterface = 'auto'
    ) {
        super(protocol);
        this.name = name;
        this.mtu = this._normalizeMtu(mtu);
        this.gateway = Array.isArray(gateway) ? gateway : [];
        this.dns = Array.isArray(dns) ? dns : [];
        this.userLevel = userLevel;
        this.autoSystemRoutingTable = Array.isArray(autoSystemRoutingTable) ? autoSystemRoutingTable : [];
        this.autoOutboundsInterface = autoOutboundsInterface;
    }

    _normalizeMtu(mtu) {
        if (!Array.isArray(mtu)) {
            const single = Number(mtu) || 1500;
            return [single, single];
        }
        if (mtu.length === 0) {
            return [1500, 1280];
        }
        if (mtu.length === 1) {
            const single = Number(mtu[0]) || 1500;
            return [single, single];
        }
        return [Number(mtu[0]) || 1500, Number(mtu[1]) || 1280];
    }

    static fromJson(json = {}) {
        return new Inbound.TunSettings(
            Protocols.TUN,
            json.name ?? 'xray0',
            json.mtu ?? json.MTU ?? [1500, 1280],
            json.gateway ?? json.Gateway ?? [],
            json.dns ?? json.DNS ?? [],
            json.userLevel ?? 0,
            json.autoSystemRoutingTable ?? [],
            Object.prototype.hasOwnProperty.call(json, 'autoOutboundsInterface') ? json.autoOutboundsInterface : 'auto'
        );
    }

    toJson() {
        return {
            name: this.name || 'xray0',
            mtu: this._normalizeMtu(this.mtu),
            gateway: this.gateway,
            dns: this.dns,
            userLevel: this.userLevel || 0,
            autoSystemRoutingTable: this.autoSystemRoutingTable,
            autoOutboundsInterface: this.autoOutboundsInterface,
        };
    }
};
