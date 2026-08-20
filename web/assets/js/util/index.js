class Msg {
    constructor(success = false, msg = "", obj = null) {
        this.success = success;
        this.msg = msg;
        this.obj = obj;
    }
}

class HttpUtil {
    static _handleMsg(msg) {
        if (!(msg instanceof Msg) || msg.msg === "") {
            return;
        }
        const messageType = msg.success ? 'success' : 'error';
        Vue.prototype.$message[messageType](msg.msg);
    }

    static _respToMsg(resp) {
        if (!resp || !resp.data) {
            return new Msg(false, 'No response data');
        }
        const { data } = resp;
        if (data == null) {
            return new Msg(true);
        }
        if (typeof data === 'object' && 'success' in data) {
            return new Msg(data.success, data.msg, data.obj);
        }
        return typeof data === 'object' ? data : new Msg(false, 'unknown data:', data);
    }

    static async get(url, params, options = {}) {
        try {
            const resp = await axios.get(url, { params, ...options });
            const msg = this._respToMsg(resp);
            this._handleMsg(msg);
            return msg;
        } catch (error) {
            console.error('GET request failed:', error);
            const errorMsg = new Msg(false, error.response?.data?.msg || error.response?.data?.message || error.message || 'Request failed');
            this._handleMsg(errorMsg);
            return errorMsg;
        }
    }

    static async post(url, data, options = {}) {
        try {
            const resp = await axios.post(url, data, options);
            const msg = this._respToMsg(resp);
            this._handleMsg(msg);
            return msg;
        } catch (error) {
            console.error('POST request failed:', error);
            const errorMsg = new Msg(false, error.response?.data?.msg || error.response?.data?.message || error.message || 'Request failed');
            this._handleMsg(errorMsg);
            return errorMsg;
        }
    }

    static async postWithModal(url, data, modal) {
        if (modal) {
            modal.loading(true);
        }
        const msg = await this.post(url, data);
        if (modal) {
            modal.loading(false);
            if (msg instanceof Msg && msg.success) {
                modal.close();
            }
        }
        return msg;
    }
}

class PromiseUtil {
    static async sleep(timeout) {
        await new Promise(resolve => {
            setTimeout(resolve, timeout)
        });
    }
}

class RandomUtil {
    static getSeq({ type = "default", hasNumbers = true, hasLowercase = true, hasUppercase = true } = {}) {
        let seq = '';

        switch (type) {
            case "hex":
                seq += "0123456789abcdef";
                break;
            default:
                if (hasNumbers) seq += "0123456789";
                if (hasLowercase) seq += "abcdefghijklmnopqrstuvwxyz";
                if (hasUppercase) seq += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                break;
        }

        return seq;
    }

    static randomInteger(min, max) {
        const range = max - min + 1;
        const randomBuffer = new Uint32Array(1);
        window.crypto.getRandomValues(randomBuffer);
        return Math.floor((randomBuffer[0] / (0xFFFFFFFF + 1)) * range) + min;
    }

    static randomSeq(count, options = {}) {
        const seq = this.getSeq(options);
        const seqLength = seq.length;
        const randomValues = new Uint32Array(count);
        window.crypto.getRandomValues(randomValues);
        return Array.from(randomValues, v => seq[v % seqLength]).join('');
    }

    static randomShortIds() {
        const lengths = [2, 4, 6, 8, 10, 12, 14, 16].sort(() => Math.random() - 0.5);

        return lengths.map(len => this.randomSeq(len, { type: "hex" })).join(',');
    }

    static randomLowerAndNum(len) {
        return this.randomSeq(len, { hasUppercase: false });
    }

    static randomUUID() {
        if (window.location.protocol === "https:") {
            return window.crypto.randomUUID();
        } else {
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
                .replace(/[xy]/g, function (c) {
                    const randomValues = new Uint8Array(1);
                    window.crypto.getRandomValues(randomValues);
                    let randomValue = randomValues[0] % 16;
                    let calculatedValue = (c === 'x') ? randomValue : (randomValue & 0x3 | 0x8);
                    return calculatedValue.toString(16);
                });
        }
    }

    static randomShadowsocksPassword(method = SSMethods.BLAKE3_AES_256_GCM) {
        let length = 32;

        if ([SSMethods.BLAKE3_AES_128_GCM].includes(method)) {
            length = 16;
        }

        const array = new Uint8Array(length);

        window.crypto.getRandomValues(array);

        return Base64.alternativeEncode(String.fromCharCode(...array));
    }

    static randomBase64(length = 16) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return Base64.alternativeEncode(String.fromCharCode(...array));
    }

    static randomBase32String(length = 16) {
        const array = new Uint8Array(length);

        window.crypto.getRandomValues(array);

        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let result = '';
        let bits = 0;
        let buffer = 0;

        for (let i = 0; i < array.length; i++) {
            buffer = (buffer << 8) | array[i];
            bits += 8;

            while (bits >= 5) {
                bits -= 5;
                result += base32Chars[(buffer >>> bits) & 0x1F];
            }
        }

        if (bits > 0) {
            result += base32Chars[(buffer << (5 - bits)) & 0x1F];
        }

        return result;
    }
}

class ObjectUtil {
    static getPropIgnoreCase(obj, prop) {
        for (const name in obj) {
            if (!obj.hasOwnProperty(name)) {
                continue;
            }
            if (name.toLowerCase() === prop.toLowerCase()) {
                return obj[name];
            }
        }
        return undefined;
    }

    static deepSearch(obj, key) {
        if (obj instanceof Array) {
            for (let i = 0; i < obj.length; ++i) {
                if (this.deepSearch(obj[i], key)) {
                    return true;
                }
            }
        } else if (obj instanceof Object) {
            for (let name in obj) {
                if (!obj.hasOwnProperty(name)) {
                    continue;
                }
                if (this.deepSearch(obj[name], key)) {
                    return true;
                }
            }
        } else {
            return this.isEmpty(obj) ? false : obj.toString().toLowerCase().indexOf(key.toLowerCase()) >= 0;
        }
        return false;
    }

    static isEmpty(obj) {
        return obj === null || obj === undefined || obj === '';
    }

    static isArrEmpty(arr) {
        return !this.isEmpty(arr) && arr.length === 0;
    }

    static copyArr(dest, src) {
        dest.splice(0);
        for (const item of src) {
            dest.push(item);
        }
    }

    static clone(obj) {
        let newObj;
        if (obj instanceof Array) {
            newObj = [];
            this.copyArr(newObj, obj);
        } else if (obj instanceof Object) {
            newObj = {};
            for (const key of Object.keys(obj)) {
                newObj[key] = obj[key];
            }
        } else {
            newObj = obj;
        }
        return newObj;
    }

    static deepClone(obj) {
        let newObj;
        if (obj instanceof Array) {
            newObj = [];
            for (const item of obj) {
                newObj.push(this.deepClone(item));
            }
        } else if (obj instanceof Object) {
            newObj = {};
            for (const key of Object.keys(obj)) {
                newObj[key] = this.deepClone(obj[key]);
            }
        } else {
            newObj = obj;
        }
        return newObj;
    }

    static cloneProps(dest, src, ...ignoreProps) {
        if (dest == null || src == null) {
            return;
        }
        const ignoreEmpty = this.isArrEmpty(ignoreProps);
        for (const key of Object.keys(src)) {
            if (!src.hasOwnProperty(key)) {
                continue;
            } else if (!dest.hasOwnProperty(key)) {
                continue;
            } else if (src[key] === undefined) {
                continue;
            }
            if (ignoreEmpty) {
                dest[key] = src[key];
            } else {
                let ignore = false;
                for (let i = 0; i < ignoreProps.length; ++i) {
                    if (key === ignoreProps[i]) {
                        ignore = true;
                        break;
                    }
                }
                if (!ignore) {
                    dest[key] = src[key];
                }
            }
        }
    }

    static delProps(obj, ...props) {
        for (const prop of props) {
            if (prop in obj) {
                delete obj[prop];
            }
        }
    }

    static execute(func, ...args) {
        if (!this.isEmpty(func) && typeof func === 'function') {
            func(...args);
        }
    }

    static orDefault(obj, defaultValue) {
        if (obj == null) {
            return defaultValue;
        }
        return obj;
    }

    static equals(a, b) {
        // shallow, symmetric comparison so newly added fields also affect equality
        const aKeys = Object.keys(a);
        const bKeys = Object.keys(b);
        if (aKeys.length !== bKeys.length) return false;
        for (const key of aKeys) {
            if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
            if (a[key] !== b[key]) return false;
        }
        return true;
    }
}

class Wireguard {
    static gf(init) {
        var r = new Float64Array(16);
        if (init) {
            for (var i = 0; i < init.length; ++i)
                r[i] = init[i];
        }
        return r;
    }

    static pack(o, n) {
        var b, m = this.gf(), t = this.gf();
        for (var i = 0; i < 16; ++i)
            t[i] = n[i];
        this.carry(t);
        this.carry(t);
        this.carry(t);
        for (var j = 0; j < 2; ++j) {
            m[0] = t[0] - 0xffed;
            for (var i = 1; i < 15; ++i) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            this.cswap(t, m, 1 - b);
        }
        for (var i = 0; i < 16; ++i) {
            o[2 * i] = t[i] & 0xff;
            o[2 * i + 1] = t[i] >> 8;
        }
    }

    static carry(o) {
        var c;
        for (var i = 0; i < 16; ++i) {
            o[(i + 1) % 16] += (i < 15 ? 1 : 38) * Math.floor(o[i] / 65536);
            o[i] &= 0xffff;
        }
    }

    static cswap(p, q, b) {
        var t, c = ~(b - 1);
        for (var i = 0; i < 16; ++i) {
            t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    static add(o, a, b) {
        for (var i = 0; i < 16; ++i)
            o[i] = (a[i] + b[i]) | 0;
    }

    static subtract(o, a, b) {
        for (var i = 0; i < 16; ++i)
            o[i] = (a[i] - b[i]) | 0;
    }

    static multmod(o, a, b) {
        var t = new Float64Array(31);
        for (var i = 0; i < 16; ++i) {
            for (var j = 0; j < 16; ++j)
                t[i + j] += a[i] * b[j];
        }
        for (var i = 0; i < 15; ++i)
            t[i] += 38 * t[i + 16];
        for (var i = 0; i < 16; ++i)
            o[i] = t[i];
        this.carry(o);
        this.carry(o);
    }

    static invert(o, i) {
        var c = this.gf();
        for (var a = 0; a < 16; ++a)
            c[a] = i[a];
        for (var a = 253; a >= 0; --a) {
            this.multmod(c, c, c);
            if (a !== 2 && a !== 4)
                this.multmod(c, c, i);
        }
        for (var a = 0; a < 16; ++a)
            o[a] = c[a];
    }

    static clamp(z) {
        z[31] = (z[31] & 127) | 64;
        z[0] &= 248;
    }

    static generatePublicKey(privateKey) {
        var r, z = new Uint8Array(32);
        var a = this.gf([1]),
            b = this.gf([9]),
            c = this.gf(),
            d = this.gf([1]),
            e = this.gf(),
            f = this.gf(),
            _121665 = this.gf([0xdb41, 1]),
            _9 = this.gf([9]);
        for (var i = 0; i < 32; ++i)
            z[i] = privateKey[i];
        this.clamp(z);
        for (var i = 254; i >= 0; --i) {
            r = (z[i >>> 3] >>> (i & 7)) & 1;
            this.cswap(a, b, r);
            this.cswap(c, d, r);
            this.add(e, a, c);
            this.subtract(a, a, c);
            this.add(c, b, d);
            this.subtract(b, b, d);
            this.multmod(d, e, e);
            this.multmod(f, a, a);
            this.multmod(a, c, a);
            this.multmod(c, b, e);
            this.add(e, a, c);
            this.subtract(a, a, c);
            this.multmod(b, a, a);
            this.subtract(c, d, f);
            this.multmod(a, c, _121665);
            this.add(a, a, d);
            this.multmod(c, c, a);
            this.multmod(a, d, f);
            this.multmod(d, b, _9);
            this.multmod(b, e, e);
            this.cswap(a, b, r);
            this.cswap(c, d, r);
        }
        this.invert(c, c);
        this.multmod(a, a, c);
        this.pack(z, a);
        return z;
    }

    static generatePresharedKey() {
        var privateKey = new Uint8Array(32);
        window.crypto.getRandomValues(privateKey);
        return privateKey;
    }

    static generatePrivateKey() {
        var privateKey = this.generatePresharedKey();
        this.clamp(privateKey);
        return privateKey;
    }

    static encodeBase64(dest, src) {
        var input = Uint8Array.from([(src[0] >> 2) & 63, ((src[0] << 4) | (src[1] >> 4)) & 63, ((src[1] << 2) | (src[2] >> 6)) & 63, src[2] & 63]);
        for (var i = 0; i < 4; ++i)
            dest[i] = input[i] + 65 +
                (((25 - input[i]) >> 8) & 6) -
                (((51 - input[i]) >> 8) & 75) -
                (((61 - input[i]) >> 8) & 15) +
                (((62 - input[i]) >> 8) & 3);
    }

    static keyToBase64(key) {
        var i, base64 = new Uint8Array(44);
        for (i = 0; i < 32 / 3; ++i)
            this.encodeBase64(base64.subarray(i * 4), key.subarray(i * 3));
        this.encodeBase64(base64.subarray(i * 4), Uint8Array.from([key[i * 3 + 0], key[i * 3 + 1], 0]));
        base64[43] = 61;
        return String.fromCharCode.apply(null, base64);
    }

    static keyFromBase64(encoded) {
        const binaryStr = atob(encoded);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        return bytes;
    }

    static generateKeypair(secretKey = '') {
        var privateKey = secretKey.length > 0 ? this.keyFromBase64(secretKey) : this.generatePrivateKey();
        var publicKey = this.generatePublicKey(privateKey);
        return {
            publicKey: this.keyToBase64(publicKey),
            privateKey: secretKey.length > 0 ? secretKey : this.keyToBase64(privateKey)
        };
    }
}

class ClipboardManager {
    static copyText(content = "") {
        // !! here old way of copying is used because not everyone can afford https connection
        return new Promise((resolve) => {
            try {
                const textarea = window.document.createElement('textarea');

                textarea.style.fontSize = '12pt';
                textarea.style.border = '0';
                textarea.style.padding = '0';
                textarea.style.margin = '0';
                textarea.style.position = 'absolute';
                textarea.style.left = '-9999px';
                textarea.style.top = `${window.pageYOffset || document.documentElement.scrollTop}px`;
                textarea.setAttribute('readonly', '');
                textarea.value = content;

                window.document.body.appendChild(textarea);

                textarea.select();
                window.document.execCommand("copy");

                window.document.body.removeChild(textarea);

                resolve(true)
            } catch {
                resolve(false)
            }
        })
    }
}

class Base64 {
    static encode(content = "", safe = false) {
        if (safe) {
            return Base64.encode(content)
                .replace(/\+/g, '-')
                .replace(/=/g, '')
                .replace(/\//g, '_')
        }

        return window.btoa(
            String.fromCharCode(...new TextEncoder().encode(content))
        )
    }

    static alternativeEncode(content) {
        return window.btoa(
            content
        )
    }

    static decode(content = "") {
        return new TextDecoder()
            .decode(
                Uint8Array.from(window.atob(content), c => c.charCodeAt(0))
            )
    }
}

class SizeFormatter {
    static ONE_KB = 1024;
    static ONE_MB = this.ONE_KB * 1024;
    static ONE_GB = this.ONE_MB * 1024;
    static ONE_TB = this.ONE_GB * 1024;
    static ONE_PB = this.ONE_TB * 1024;

    static sizeFormat(size) {
        if (size <= 0) return "0 B";
        if (size < this.ONE_KB) return size.toFixed(0) + " B";
        if (size < this.ONE_MB) return (size / this.ONE_KB).toFixed(2) + " KB";
        if (size < this.ONE_GB) return (size / this.ONE_MB).toFixed(2) + " MB";
        if (size < this.ONE_TB) return (size / this.ONE_GB).toFixed(2) + " GB";
        if (size < this.ONE_PB) return (size / this.ONE_TB).toFixed(2) + " TB";
        return (size / this.ONE_PB).toFixed(2) + " PB";
    }
}

class CPUFormatter {
    static cpuSpeedFormat(speed) {
        return speed > 1000 ? (speed / 1000).toFixed(2) + " GHz" : speed.toFixed(2) + " MHz";
    }

    static cpuCoreFormat(cores) {
        return cores === 1 ? "1 Core" : cores + " Cores";
    }
}

class TimeFormatter {
    static formatSecond(second) {
        if (second < 60) return second.toFixed(0) + 's';
        if (second < 3600) return (second / 60).toFixed(0) + 'm';
        if (second < 3600 * 24) return (second / 3600).toFixed(0) + 'h';
        let day = Math.floor(second / 3600 / 24);
        let remain = ((second / 3600) - (day * 24)).toFixed(0);
        return day + 'd' + (remain > 0 ? ' ' + remain + 'h' : '');
    }

    // Full uptime breakdown: years and months appear only once actually reached,
    // then days, hours, minutes and seconds. Zero units are skipped entirely, so
    // a core restarted moments ago reads "12s" and a long-lived host reads
    // "1y 2mo 3d 4h 5m 6s" rather than padding either with meaningless zeros.
    //
    // formatSecond (above) collapses everything past a day into "Nd Nh"; it is
    // kept for the places that want the short form. This one is for the overview
    // and the Xray tile, where the exact figure is the point.
    static formatUptime(second) {
        second = Math.floor(Number(second) || 0);
        if (second <= 0) return '0s';
        // Mean Gregorian month and year, so "1mo" keeps meaning roughly a month
        // instead of drifting against the calendar the way a flat 30 days does.
        const UNITS = [
            ['y', 31557600],  // 365.25 days
            ['mo', 2629800],  // 30.4375 days
            ['d', 86400],
            ['h', 3600],
            ['m', 60],
            ['s', 1],
        ];
        const parts = [];
        let rest = second;
        for (const [label, size] of UNITS) {
            const n = Math.floor(rest / size);
            if (n > 0) {
                parts.push(n + label);
                rest -= n * size;
            }
        }
        return parts.join(' ');
    }
}

class NumberFormatter {
    static addZero(num) {
        return num < 10 ? "0" + num : num;
    }

    static toFixed(num, n) {
        n = Math.pow(10, n);
        return Math.floor(num * n) / n;
    }
}

class Utils {
    static debounce(fn, delay) {
        let timeoutID = null;
        return function () {
            clearTimeout(timeoutID);
            let args = arguments;
            let that = this;
            timeoutID = setTimeout(() => fn.apply(that, args), delay);
        };
    }
}

class CookieManager {
    static getCookie(cname) {
        let name = cname + '=';
        let ca = document.cookie.split(';');
        for (let c of ca) {
            c = c.trim();
            if (c.indexOf(name) === 0) {
                return decodeURIComponent(c.substring(name.length, c.length));
            }
        }
        return '';
    }

    static setCookie(cname, cvalue, exdays) {
        let expires = '';
        if (exdays) {
            const d = new Date();
            d.setTime(d.getTime() + exdays * 24 * 60 * 60 * 1000);
            expires = 'expires=' + d.toUTCString() + ';';
        }
        document.cookie = cname + '=' + encodeURIComponent(cvalue) + ';' + expires + 'path=/';
    }
}

// Permanent dismissal of the no-TLS security banner.
//
// The banner has two ways out and they are NOT the same. Its own close button
// (a-alert's `closable` X) hides it for this page view only, so the warning is
// back on the next navigation. This flag is the other one: "don't show this
// again" outlives the tab and is honoured by every page that renders the
// banner, so dismissing it once on the Overview also silences Inbounds and
// Xray.
//
// Storage follows the convention already set by the unsupported-distro warning
// on the dashboard: a `vpnui.`-namespaced localStorage key, written inside a
// try/catch because a browser with storage denied (private mode, blocked
// third-party context) throws on setItem and must not take the page with it.
class SecAlertDismissal {
    static KEY = 'vpnui.secAlertDismissed';

    static isDismissed() {
        try {
            return localStorage.getItem(SecAlertDismissal.KEY) === 'true';
        } catch (e) {
            return false;
        }
    }

    static dismiss() {
        try {
            localStorage.setItem(SecAlertDismissal.KEY, 'true');
        } catch (e) { /* ignore */ }
    }
}

class ColorUtils {
    static usageColor(data, threshold, total) {
        switch (true) {
            case data === null: return "purple";
            case total < 0: return "green";
            case total == 0: return "purple";
            case data < total - threshold: return "green";
            case data < total: return "orange";
            default: return "red";
        }
    }

    static clientUsageColor(clientStats, trafficDiff) {
        switch (true) {
            case !clientStats || clientStats.total == 0: return "#7a316f";
            case clientStats.up + clientStats.down < clientStats.total - trafficDiff: return "#008771";
            case clientStats.up + clientStats.down < clientStats.total: return "#f37b24";
            default: return "#cf3c3c";
        }
    }

    static userExpiryColor(threshold, client, isDark = false) {
        if (!client.enable) return isDark ? '#2c3950' : '#bcbcbc';
        let now = new Date().getTime(), expiry = client.expiryTime;
        switch (true) {
            case expiry === null: return "#7a316f";
            case expiry < 0: return "#008771";
            case expiry == 0: return "#7a316f";
            case now < expiry - threshold: return "#008771";
            case now < expiry: return "#f37b24";
            default: return "#cf3c3c";
        }
    }
}

class ArrayUtils {
    static doAllItemsExist(array1, array2) {
        return array1.every(item => array2.includes(item));
    }
}

class URLBuilder {
    static buildURL({ host, port, isTLS, base, path }) {
        if (!host || host.length === 0) host = window.location.hostname;
        if (!port || port.length === 0) port = window.location.port;
        if (isTLS === undefined) isTLS = window.location.protocol === "https:";

        const protocol = isTLS ? "https:" : "http:";
        port = String(port);
        if (port === "" || (isTLS && port === "443") || (!isTLS && port === "80")) {
            port = "";
        } else {
            port = `:${port}`;
        }

        return `${protocol}//${host}${port}${base}${path}`;
    }
}

class LanguageManager {
    static supportedLanguages = [
        {
            name: "العربية",
            value: "ar-EG",
            icon: "🇪🇬",
        },
        {
            name: "English",
            value: "en-US",
            icon: "🇺🇸",
        },
        {
            name: "فارسی",
            value: "fa-IR",
            icon: "🇮🇷",
        },
        {
            name: "简体中文",
            value: "zh-CN",
            icon: "🇨🇳",
        },
        {
            name: "繁體中文",
            value: "zh-TW",
            icon: "🇹🇼",
        },
        {
            name: "日本語",
            value: "ja-JP",
            icon: "🇯🇵",
        },
        {
            name: "Русский",
            value: "ru-RU",
            icon: "🇷🇺",
        },
        {
            name: "Tiếng Việt",
            value: "vi-VN",
            icon: "🇻🇳",
        },
        {
            name: "Español",
            value: "es-ES",
            icon: "🇪🇸",
        },
        {
            name: "Indonesian",
            value: "id-ID",
            icon: "🇮🇩",
        },
        {
            name: "Український",
            value: "uk-UA",
            icon: "🇺🇦",
        },
        {
            name: "Türkçe",
            value: "tr-TR",
            icon: "🇹🇷",
        },
        {
            name: "Português",
            value: "pt-BR",
            icon: "🇧🇷",
        }
    ]

    static getLanguage() {
        let lang = CookieManager.getCookie("lang");

        if (!lang) {
            if (window.navigator) {
                lang = window.navigator.language || window.navigator.userLanguage;

                const simularLangs = [
                    ["ar", this.supportedLanguages[0].value],
                    ["fa", this.supportedLanguages[2].value],
                    ["ja", this.supportedLanguages[5].value],
                    ["ru", this.supportedLanguages[6].value],
                    ["vi", this.supportedLanguages[7].value],
                    ["es", this.supportedLanguages[8].value],
                    ["id", this.supportedLanguages[9].value],
                    ["uk", this.supportedLanguages[10].value],
                    ["tr", this.supportedLanguages[11].value],
                    ["pt", this.supportedLanguages[12].value],
                ]

                simularLangs.forEach((pair) => {
                    if (lang === pair[0]) {
                        lang = pair[1];
                    }
                });

                if (LanguageManager.isSupportLanguage(lang)) {
                    CookieManager.setCookie("lang", lang);
                } else {
                    CookieManager.setCookie("lang", "en-US");
                    window.location.reload();
                }
            } else {
                CookieManager.setCookie("lang", "en-US");
                window.location.reload();
            }
        }

        return lang;
    }

    static setLanguage(language) {
        if (!LanguageManager.isSupportLanguage(language)) {
            language = "en-US";
        }

        CookieManager.setCookie("lang", language);
        window.location.reload();
    }

    static isSupportLanguage(language) {
        const languageFilter = LanguageManager.supportedLanguages.filter((lang) => {
            return lang.value === language
        })

        return languageFilter.length > 0;
    }
}

const MediaQueryMixin = {
    data() {
        return {
            isMobile: window.innerWidth <= 768,
        };
    },
    methods: {
        updateDeviceType() {
            this.isMobile = window.innerWidth <= 768;
        },
    },
    mounted() {
        window.addEventListener('resize', this.updateDeviceType);
    },
    beforeDestroy() {
        window.removeEventListener('resize', this.updateDeviceType);
    },
}

class FileManager {
    static downloadTextFile(content, filename = 'file.txt', options = { type: "text/plain" }) {
        // Tolerate a bare mime-type string (older/cached callers passed 'text/plain'
        // instead of { type: 'text/plain' }); a non-object here makes the Blob
        // constructor throw "not of type 'BlobPropertyBag'".
        if (typeof options === 'string') options = { type: options };
        if (!options || typeof options !== 'object') options = { type: 'text/plain' };
        let link = window.document.createElement('a');

        link.download = filename;
        link.style.border = '0';
        link.style.padding = '0';
        link.style.margin = '0';
        link.style.position = 'absolute';
        link.style.left = '-9999px';
        link.style.top = `${window.pageYOffset || window.document.documentElement.scrollTop}px`;
        link.href = URL.createObjectURL(new Blob([content], options));
        link.click();

        URL.revokeObjectURL(link.href);

        link.remove();
    }
}

// One renderer for every log the panel shows, so a daemon's output, Xray's and
// the panel's own all read the same way.
//
// Each core used to be dumped as raw escaped text under a heading, while the
// panel log alone got severity colours. That made the aggregated view a wall of
// undifferentiated text in which the only way to tell whose line you were
// reading was to scroll back to the nearest heading.
//
// Colour encodes SEVERITY only. The source is a neutral badge on purpose: the
// panel carries thirteen cores and hue cannot reliably distinguish that many,
// which is the same reason protocol tags elsewhere are neutral.
// Live tail for the panel's log views.
//
// There is no server-side log stream to subscribe to: the panel log is a ring
// buffer read on demand and each core's log is whatever its process manager has
// captured, so "live" here is a poll of the SAME endpoint the view already uses.
// That keeps every log view live-able without inventing a streaming protocol per
// core, and it means the live view and the manual one can never disagree.
//
// Timers are held here, keyed, rather than on the Vue instances, so closing a
// modal or navigating away cannot leave one running against a dead component.
class LiveLog {
    // Long enough not to hammer the box, short enough to feel live. The
    // aggregated view fans out to one request per selected core, which is why
    // it only ever polls the cores actually ticked in the filter.
    static get INTERVAL_MS() { return 3000; }

    static start(key, fn, intervalMs) {
        this.stop(key);
        LiveLog._timers[key] = setInterval(fn, intervalMs || this.INTERVAL_MS);
    }

    static stop(key) {
        if (LiveLog._timers[key]) {
            clearInterval(LiveLog._timers[key]);
            delete LiveLog._timers[key];
        }
    }

    static stopAll() {
        for (const k of Object.keys(LiveLog._timers)) this.stop(k);
    }

    // Whether the pane is scrolled to (or near) the bottom. A live refresh must
    // only auto-scroll when the reader is already following the tail; yanking
    // someone back down while they are reading scrollback is worse than useless.
    static atBottom(el, slack = 40) {
        if (!el) return true;
        return el.scrollHeight - el.scrollTop - el.clientHeight <= slack;
    }

    // Runs `update`, preserving "following the tail" across the re-render.
    static keepPinned(selector, update) {
        const el = document.querySelector(selector);
        const follow = this.atBottom(el);
        update();
        if (typeof Vue !== 'undefined' && Vue.nextTick) {
            Vue.nextTick(() => {
                const now = document.querySelector(selector);
                if (follow && now) now.scrollTop = now.scrollHeight;
            });
        }
    }
}
LiveLog._timers = {};

// Severity ranks. The log modal's level picker selects a FLOOR, so anything
// below it is dropped. A daemon line that carries no severity token at all
// (most of them: xl2tpd, ocserv and pppd just print sentences) is treated as
// INFO, which is what makes "Warning" and "Error" actually narrow the view
// instead of leaving every core's chatter on screen.
const LOG_RANKS = {
    DEBUG: 0, TRACE: 0,
    INFO: 1,
    NOTICE: 2,
    WARNING: 3, WARN: 3,
    ERROR: 4, ERR: 4, FATAL: 4, CRIT: 4, CRITICAL: 4, PANIC: 4, ALERT: 4, EMERG: 4,
};
// The values the level <select> binds, mapped onto the same scale.
const LOG_LEVEL_FLOOR = { debug: 0, info: 1, notice: 2, warning: 3, err: 4, error: 4 };
const LOG_UNKNOWN_RANK = LOG_RANKS.INFO;

// One renderer for every log the panel shows, so a daemon's output, Xray's and
// the panel's own all read the same way.
//
// Each core used to be dumped as raw escaped text under a heading, while the
// panel log alone got severity colours. That made the aggregated view a wall of
// undifferentiated text in which the only way to tell whose line you were
// reading was to scroll back to the nearest heading.
//
// Colour encodes SEVERITY only. The source is a neutral badge on purpose: the
// panel carries thirteen cores and hue cannot reliably distinguish that many,
// which is the same reason protocol tags elsewhere are neutral.
class LogFormatter {
    // Log text is NOT trusted: lines echo client-supplied names (VPN usernames,
    // remarks, SNI), and the pane renders with v-html. Everything is escaped
    // before any markup is added around it.
    static esc(s) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => map[c]);
    }

    // Splits one line into its timestamp, severity and message. Every part is
    // optional: a daemon may emit a bare sentence with none of them.
    static parse(text) {
        let rest = String(text == null ? '' : text);
        let time = '';
        let level = '';

        // Leading timestamp, in the shapes the panel and the daemons use:
        // "2026/07/22 14:12:40" and syslog's "Jul 22 14:12:40".
        const ts = rest.match(/^\s*(\d{4}[\/-]\d{2}[\/-]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?|[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})\s*/);
        if (ts) {
            time = ts[1];
            rest = rest.slice(ts[0].length);
        }

        // A severity token, bare ("INFO - ...") or bracketed ("[Warning]").
        const lvl = rest.match(/^\s*\[?([A-Za-z]{3,9})\]?(\s*[-:]\s*|\s+)/);
        if (lvl && Object.prototype.hasOwnProperty.call(LOG_RANKS, lvl[1].toUpperCase())) {
            level = lvl[1].toUpperCase();
            rest = rest.slice(lvl[0].length);
        }

        return { time, level, message: rest };
    }

    // 0 (debug) to 4 (error). Lines with no token rank as INFO; see LOG_RANKS.
    static rank(text) {
        const lvl = this.parse(text).level;
        return lvl ? LOG_RANKS[lvl] : LOG_UNKNOWN_RANK;
    }

    static levelClass(level) {
        const r = LOG_RANKS[level];
        if (r === 4) return 'log-error';
        if (r === 3) return 'log-warn';
        if (r === 2 || r === 1) return 'log-info';
        if (r === 0) return 'log-debug';
        return '';
    }

    // Renders one line: [source] timestamp LEVEL message. The badge is a flex
    // sibling of the body, not part of the same text flow, so a wrapped line
    // indents under its own message rather than restarting in the badge column.
    static line(text, source) {
        const { time, level, message } = this.parse(text);
        const badge = source ? `<span class="log-src">${this.esc(source)}</span>` : '';
        let out = '';
        if (time) out += `<span class="log-time">${this.esc(time)}</span> `;
        if (level) out += `<span class="log-lvl ${this.levelClass(level)}">${this.esc(level)}</span> `;
        out += `<span class="log-msg">${this.esc(message)}</span>`;
        return badge + `<span class="log-body">${out}</span>`;
    }

    // Flattens [{source, text}] into individual lines, applying the level floor
    // and the source allow-list. Shared by render() and plain() so the download
    // always matches exactly what is on screen.
    static select(entries, opts = {}) {
        const floor = opts.level == null ? -1 : (LOG_LEVEL_FLOOR[opts.level] ?? -1);
        const only = opts.sources && opts.sources.length ? new Set(opts.sources) : null;
        const out = [];
        for (const e of entries || []) {
            if (only && !only.has(e.source)) continue;
            const body = String(e.text == null ? '' : e.text).replace(/\s+$/, '');
            if (!body) continue;
            for (const l of body.split('\n')) {
                // Blank lines would render as a badge with nothing after it.
                if (!l.trim()) continue;
                if (floor >= 0 && this.rank(l) < floor) continue;
                out.push({ source: e.source, text: l });
            }
        }
        return out;
    }

    // The distinct sources present, in first-seen order, for the filter UI.
    static sourcesOf(entries) {
        const seen = [];
        for (const e of entries || []) {
            const body = String(e.text == null ? '' : e.text).trim();
            if (body && e.source && !seen.includes(e.source)) seen.push(e.source);
        }
        return seen;
    }

    static render(entries, opts = {}) {
        return this.select(entries, opts)
            .map((l) => `<div class="log-line">${this.line(l.text, l.source)}</div>`)
            .join('');
    }

    // The plain-text twin of render(), for the download button. Same prefixes and
    // the same filtering, so a downloaded log matches what was on screen.
    static plain(entries, opts = {}) {
        return this.select(entries, opts)
            .map((l) => (l.source ? `[${l.source}] ${l.text}` : l.text))
            .join('\n');
    }
}

class GeoUtil {
    // "US" -> the regional-indicator pair the platform renders as a flag.
    // Built from the letters rather than a lookup table: every ISO 3166-1
    // alpha-2 code maps to its flag by the same offset, so there is no list to
    // keep in sync and a code we have never seen still renders.
    static flag(code) {
        if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code)) return ''
        const base = 0x1F1E6 - 'A'.charCodeAt(0)
        return String.fromCodePoint(
            ...code.toUpperCase().split('').map(c => base + c.charCodeAt(0))
        )
    }

    // "US" -> "United States", in the panel's own language. Intl does the
    // translating, so no country-name table ships with (or is translated for)
    // the panel. Falls back to the raw code where the runtime has no name.
    static countryName(code) {
        if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code)) return ''
        const cc = code.toUpperCase()
        // Reserved non-countries: Cloudflare answers XX when it cannot place the
        // address and T1 for Tor. Both would otherwise render as a meaningless
        // two-letter "flag", so report them as unknown and let the caller hide.
        if (cc === 'XX' || cc === 'ZZ' || cc === 'T1') return ''
        try {
            const dn = new Intl.DisplayNames([LanguageManager.getLanguage()], { type: 'region' })
            return dn.of(cc) || cc
        } catch (e) {
            return cc
        }
    }

    // "United States <flag>", the form both the panel-location row and the
    // outbound test result use. Empty for an unusable code, so callers can hide
    // the whole row with a single falsy check.
    static label(code) {
        const name = GeoUtil.countryName(code)
        if (!name) return ''
        const f = GeoUtil.flag(code)
        return f ? name + ' ' + f : name
    }
}

class IntlUtil {
    static formatDate(date) {
        const language = LanguageManager.getLanguage()

        let intlOptions = {
            year: "numeric",
            month: "numeric",
            day: "numeric",
            hour: "numeric",
            minute: "numeric",
            second: "numeric"
        }

        const intl = new Intl.DateTimeFormat(
            language,
            intlOptions
        )

        return intl.format(new Date(date))
    }
    static formatRelativeTime(date) {
        const language = LanguageManager.getLanguage()
        const now = new Date()

        // Handle delayed start (negative expiryTime values)
        const diff = date < 0
            ? Math.round(date / (1000 * 60 * 60 * 24))
            : Math.round((date - now) / (1000 * 60 * 60 * 24))
        const formatter = new Intl.RelativeTimeFormat(language, { numeric: 'auto' })

        return formatter.format(diff, 'day');
    }
}