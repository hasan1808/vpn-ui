(function () {
  // Vue app for Subscription page
  const el = document.getElementById('subscription-data');
  if (!el) return;
  const textarea = document.getElementById('subscription-links');
  const rawLinks = (textarea?.value || '').split('\n').filter(Boolean);

  const data = {
    sId: el.getAttribute('data-sid') || '',
    subUrl: el.getAttribute('data-sub-url') || '',
    subJsonUrl: el.getAttribute('data-subjson-url') || '',
    subClashUrl: el.getAttribute('data-subclash-url') || '',
    download: el.getAttribute('data-download') || '',
    upload: el.getAttribute('data-upload') || '',
    used: el.getAttribute('data-used') || '',
    total: el.getAttribute('data-total') || '',
    remained: el.getAttribute('data-remained') || '',
    expireMs: (parseInt(el.getAttribute('data-expire') || '0', 10) || 0) * 1000,
    lastOnlineMs: (parseInt(el.getAttribute('data-lastonline') || '0', 10) || 0),
    downloadByte: parseInt(el.getAttribute('data-downloadbyte') || '0', 10) || 0,
    uploadByte: parseInt(el.getAttribute('data-uploadbyte') || '0', 10) || 0,
    totalByte: parseInt(el.getAttribute('data-totalbyte') || '0', 10) || 0,
    datepicker: el.getAttribute('data-datepicker') || 'gregorian',
    email: el.getAttribute('data-email') || '',
    password: el.getAttribute('data-password') || '',
  };

  // Normalize lastOnline to milliseconds if it looks like seconds
  if (data.lastOnlineMs && data.lastOnlineMs < 10_000_000_000) {
    data.lastOnlineMs *= 1000;
  }

  function renderLink(item) {
    return (
      Vue.h('a-list-item', {}, [
        Vue.h('a-space', { props: { size: 'small' } }, [
          Vue.h('a-button', { props: { size: 'small' }, on: { click: () => copy(item) } }, [Vue.h('a-icon', { props: { type: 'copy' } })]),
          Vue.h('span', { class: 'break-all' }, item)
        ])
      ])
    );
  }

  function copy(text) {
    ClipboardManager.copyText(text).then(ok => {
      const messageType = ok ? 'success' : 'error';
      Vue.prototype.$message[messageType](ok ? 'Copied' : 'Copy failed');
    });
  }

  function open(url) {
    window.location.href = url;
  }

  // Try to extract a human label (email/ps) from different link types
  function linkName(link, idx) {
    try {
      if (link.startsWith('vmess://')) {
        const json = JSON.parse(atob(link.replace('vmess://', '')));
        if (json.ps) return json.ps;
        if (json.add && json.id) return json.add; // fallback host
      } else if (link.startsWith('vless://') || link.startsWith('trojan://')) {
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
        const qIdx = link.indexOf('?');
        if (qIdx !== -1) {
          const qs = new URL('http://x/?' + link.substring(qIdx + 1, hashIdx !== -1 ? hashIdx : undefined)).searchParams;
          if (qs.get('remark')) return qs.get('remark');
          if (qs.get('email')) return qs.get('email');
        }
        const at = link.indexOf('@');
        const protSep = link.indexOf('://');
        if (at !== -1 && protSep !== -1) return link.substring(protSep + 3, at);
      } else if (link.startsWith('ss://')) {
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
      } else if (link.startsWith('tg://')) {
        // tg://proxy?server=HOST&port=..&secret=.. -> label with the server host.
        const qs = new URL('http://x/?' + link.substring(link.indexOf('?') + 1)).searchParams;
        const host = qs.get('server');
        return host ? 'MTProto (' + host + ')' : 'MTProto';
      } else if (link.startsWith('ssh://')) {
        // ssh://base64(user:pass@host:port)[#label] -> prefer the #label, else the host.
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
        const decoded = atob(link.substring('ssh://'.length));
        const at = decoded.lastIndexOf('@');
        return 'SSH' + (at !== -1 ? ' (' + decoded.substring(at + 1) + ')' : '');
      } else if (link.startsWith('wireguard://')) {
        // wg-c/awg: wireguard://<privkey>@host:port?..#remark -> the remark names the
        // device; fall back to the endpoint so a link without one still reads.
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
        const at = link.indexOf('@');
        const qIdx = link.indexOf('?');
        return at !== -1 ? 'WireGuard (' + link.substring(at + 1, qIdx === -1 ? undefined : qIdx) + ')'
                         : 'WireGuard';
      }
    } catch (e) { /* ignore and fallback */ }
    return 'Link ' + (idx + 1);
  }

  const app = new Vue({
    delimiters: ['[[', ']]'],
    el: '#app',
data: {
    themeSwitcher,
    app: data,
    links: rawLinks,
    lang: '',
    viewportWidth: (typeof window !== 'undefined' ? window.innerWidth : 1024),
    showPassword: false,
    pwModal: {
      open: false,
      busy: false,
      current: '',
      next: '',
      confirm: '',
    },
    // Server-rendered localized strings for the password dialog's messages.
    t: {
      pwChanged: '{{ i18n "subscription.pwChanged" }}',
      pwWrongCurrent: '{{ i18n "subscription.pwWrongCurrent" }}',
      pwTooShort: '{{ i18n "subscription.pwTooShort" }}',
      pwMismatch: '{{ i18n "subscription.pwMismatch" }}',
      pwMissing: '{{ i18n "subscription.pwMissing" }}',
      pwRateLimited: '{{ i18n "subscription.pwRateLimited" }}',
      pwFailed: '{{ i18n "subscription.pwFailed" }}',
    },
  },
    async mounted() {
      this.lang = LanguageManager.getLanguage();
      const tpl = document.getElementById('subscription-data');
      const sj = tpl ? tpl.getAttribute('data-subjson-url') : '';
      const sc = tpl ? tpl.getAttribute('data-subclash-url') : '';
      if (sj) this.app.subJsonUrl = sj;
      if (sc) this.app.subClashUrl = sc;
      this._onResize = () => { this.viewportWidth = window.innerWidth; };
      window.addEventListener('resize', this._onResize);
    },
    beforeDestroy() {
      if (this._onResize) window.removeEventListener('resize', this._onResize);
    },
    computed: {
      isMobile() {
        return this.viewportWidth < 576;
      },
      isUnlimited() {
        return !this.app.totalByte;
      },
      isActive() {
        const now = Date.now();
        const expiryOk = !this.app.expireMs || this.app.expireMs >= now;
        const trafficOk = !this.app.totalByte || (this.app.uploadByte + this.app.downloadByte) <= this.app.totalByte;
        return expiryOk && trafficOk;
      },
      usagePercent() {
        if (!this.app.totalByte) return 0;
        const used = this.app.downloadByte + this.app.uploadByte;
        return Math.min(100, Math.round((used / this.app.totalByte) * 100));
      },
      usageLevel() {
        const p = this.usagePercent;
        if (p >= 90) return 'error';
        if (p >= 70) return 'warn';
        return 'ok';
      },
      shadowrocketUrl() {
        const rawUrl = this.app.subUrl + '?flag=shadowrocket';
        const base64Url = btoa(rawUrl);
        const remark = encodeURIComponent(this.app.sId || 'Subscription');
        return `shadowrocket://add/sub/${base64Url}?remark=${remark}`;
      },
      v2boxUrl() {
        return `v2box://install-sub?url=${encodeURIComponent(this.app.subUrl)}&name=${encodeURIComponent(this.app.sId)}`;
      },
      streisandUrl() {
        return `streisand://import/${encodeURIComponent(this.app.subUrl)}`;
      },
      v2raytunUrl() {
        return this.app.subUrl;
      },
      npvtunUrl() {
        return this.app.subUrl;
      },
      happUrl() {
        return `happ://add/${this.app.subUrl}`;
      }
    },
    methods: {
      renderLink,
      copy,
      open,
      linkName,
      openPwModal() {
        this.pwModal.open = true;
        this.pwModal.current = '';
        this.pwModal.next = '';
        this.pwModal.confirm = '';
        this.pwModal.busy = false;
      },
      closePwModal() {
        if (this.pwModal.busy) return;
        this.pwModal.open = false;
      },
      pwError(code) {
        const map = {
          wrong: this.t.pwWrongCurrent,
          weak: this.t.pwTooShort,
          notfound: this.t.pwWrongCurrent,
          rate: this.t.pwRateLimited,
        };
        return map[code] || this.t.pwFailed;
      },
      submitPassword() {
        const f = this.pwModal;
        if (f.busy) return;
        if (!f.current || !f.next || !f.confirm) {
          Vue.prototype.$message.error(this.t.pwMissing);
          return;
        }
        if (f.next.length < 6) {
          Vue.prototype.$message.error(this.t.pwTooShort);
          return;
        }
        if (f.next !== f.confirm) {
          Vue.prototype.$message.error(this.t.pwMismatch);
          return;
        }
        f.busy = true;
        const url = window.location.pathname.replace(/\/+$/, '') + '/password';
        fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ current: f.current, new: f.next }),
        })
          .then(r => r.json())
          .then(res => {
            f.busy = false;
            if (res.success) {
              this.app.password = f.next;
              f.open = false;
              Vue.prototype.$message.success(this.t.pwChanged);
            } else {
              Vue.prototype.$message.error(this.pwError(res.code));
            }
          })
          .catch(() => {
            f.busy = false;
            Vue.prototype.$message.error(this.t.pwFailed);
          });
      },
    },
  });
})();
