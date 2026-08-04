// Account export helpers (TXT + PDF) for the inbounds page.
//
// Builds a "card" per selected account and renders it either as a styled plain-text
// file or as a PDF (via the vendored jsPDF UMD build). A QR code is drawn only for
// accounts whose credential is a scannable payload: xray share links, MTProto tg://
// links, the SSH ssh:// link, and the WireGuard-C .conf. The username/password VPN
// protocols (L2TP/PPTP/OpenVPN/OpenConnect/SSTP/IKEv2) have no importable payload, so
// they render server/port/user/pass without a QR.
const AccountExport = {
  // --- data ------------------------------------------------------------------

  // buildCards turns [{inboundId, email}] targets into renderable card objects,
  // reusing the page app for inbound lookup, stats and link generation. Async because
  // the key-based / relay protocols (WireGuard-C, SSH) fetch their real config or share
  // link from the backend (server-minted keys / panel-host endpoint).
  async buildCards(app, targets) {
    const cards = [];
    for (const t of targets) {
      // One malformed account must not abort the whole export — guard each card
      // and skip (with a console note) any that throws while being built.
      try {
        const dbInbound = app.dbInbounds.find(r => r.id === t.inboundId);
        if (!dbInbound) continue;
        const inbound = dbInbound.toInbound();
        const clients = app.getInboundClients(dbInbound) || [];
        const client = clients.find(c => c.email === t.email);
        if (!client) continue;

        const server = (inbound.listen && inbound.listen !== '0.0.0.0')
          ? inbound.listen : location.hostname;

        // xray protocols produce a share link; VPN protocols return ''.
        let link = '';
        try {
          const all = inbound.genAllLinks('', app.remarkModel || '-ieo', client);
          link = (all && all[0] && all[0].link) ? all[0].link : '';
        } catch (e) { link = ''; }

        let used = '';
        try { used = SizeFormatter.sizeFormat(app.getSumStats(dbInbound, client.email) || 0); }
        catch (e) { used = '0'; }

        // Pick the login identity by protocol family. The VPN username/password
        // protocols authenticate with client.id (the login username) + client.password;
        // client.email is only a tracking label, so it must NOT be shown as the username
        // and client.id must NOT be printed as a "UUID". Xray protocols use client.id as
        // a UUID with client.email as the label. WireGuard (C) is key-based (identity =
        // email, credential = the downloadable config), with no username/password/UUID.
        const proto = (dbInbound.protocol || '').toLowerCase();
        const vpnUserPass = (proto === Protocols.L2TP || proto === Protocols.PPTP
          || proto === Protocols.OPENVPN || proto === Protocols.OPENCONNECT
          || proto === Protocols.SSTP || proto === Protocols.IKEV2
          || proto === Protocols.SSH);
        const isWgc = (proto === Protocols.WGC);
        const isAwg = (proto === Protocols.AWG);
        const isGre = (proto === Protocols.GRE);
        const isMtproto = (proto === Protocols.MTPROTO);
        const isSsh = (proto === Protocols.SSH);
        const isNaive = (proto === Protocols.NAIVE);
        // MTProto has no username (identity = email, the wg-c model) and no UUID; its
        // credential is the secret, which is already embedded in each link.
        //
        // naive is the one Xray protocol whose username is not the email: it has its own
        // field, and an empty one falls back to the email. The exported row has to show
        // whichever the server will actually match, or the operator hands a subscriber a
        // credential that cannot log in.
        const username = vpnUserPass ? (client.id || client.email || '')
          : isNaive ? (client.username || client.email || '')
          : (client.email || '');
        const uuid = (!vpnUserPass && !isWgc && !isAwg && !isGre && !isMtproto && client.id
          && client.id !== client.password && client.id !== client.email) ? client.id : '';

        const base = {
          remark: dbInbound.remark || inbound.remark || '',
          protocol: AccountExport._protocolLabel(dbInbound, inbound),
          network: AccountExport._network(dbInbound, inbound),
          server: server,
          port: AccountExport._portText(dbInbound, inbound),
          username: username,
          email: client.email || '',
          password: client.password || '',
          uuid: uuid,
          psk: AccountExport._psk(dbInbound, inbound, client),
          expiry: AccountExport._expiryText(client.expiryTime),
          used: used,
          total: client.totalGB > 0 ? SizeFormatter.sizeFormat(client.totalGB) : '∞',
          enable: !!client.enable,
          link: link,
          qr: link,          // xray link -> QR; overridden per protocol below
          configText: '',    // multi-line config embedded in the TXT (WireGuard-C)
        };

        // MTProto: LINK-ONLY. Server/port/username/secret all live inside each tg://
        // link, so those rows are dropped. One account yields one link PER ENABLED MODE
        // (and per external-proxy endpoint); emit a card each so the PDF draws a QR per
        // mode and the TXT lists them individually. An account with every mode off
        // produces no links and so no card, it has nothing to hand out.
        if (isMtproto) {
          const mtAddr = (inbound.listen && inbound.listen !== '0.0.0.0') ? inbound.listen : location.hostname;
          let mtLinks = [];
          try { mtLinks = (typeof client.links === 'function') ? (client.links(mtAddr, inbound.port) || []) : []; }
          catch (e) { mtLinks = []; }
          const modeLabel = { classic: 'MTProto - Classic', secure: 'MTProto - DD(Secure)', tls: 'MTProto - FakeTLS(EE)' };
          for (const l of mtLinks) {
            cards.push(Object.assign({}, base, {
              protocol: modeLabel[l.mode] || 'MTProto',
              network: '',
              server: '', port: '', username: '', password: '', uuid: '', psk: '',
              link: l.link,
              qr: l.link,
            }));
          }
          continue;
        }

        // WireGuard (C): key-based. Fetch the server-minted .conf (one per endpoint,
        // Endpoint = the panel host) and use it as both the QR payload (WireGuard-
        // importable) and the TXT config block. No password/UUID.
        if (isWgc) {
          const devices = await AccountExport._fetchConfigs(dbInbound.id, client.email, 'wgc-configs');
          if (!devices.length) { cards.push(base); continue; }
          for (const dev of devices) {
            cards.push(Object.assign({}, base, {
              remark: base.remark + (dev.remark ? ' (' + dev.remark + ')' : ''),
              qr: dev.config || '',
              configText: dev.config || '',
            }));
          }
          continue;
        }

        // AmneziaWG: same key-based, server-rendered .conf as WireGuard (C), plus the
        // obfuscation params baked into the [Interface] block. Use the config as both
        // the QR payload and the TXT config block. No password/UUID.
        if (isAwg) {
          const devices = await AccountExport._fetchConfigs(dbInbound.id, client.email, 'awg-configs');
          if (!devices.length) { cards.push(base); continue; }
          for (const dev of devices) {
            cards.push(Object.assign({}, base, {
              remark: base.remark + (dev.remark ? ' (' + dev.remark + ')' : ''),
              qr: dev.config || '',
              configText: dev.config || '',
            }));
          }
          continue;
        }

        // GRE: there is no key, password or link at all, and no client app, and the router
        // setup is deliberately NOT embedded here: it is a multi-page recipe per peer that
        // buried every other account in a bulk export. It stays in the account's GRE Setup
        // modal (and its subscription .txt), which is also where it can be handed out per
        // platform. So the card is the account row alone, with nothing to put in a QR.
        if (isGre) {
          cards.push(base);
          continue;
        }

        // SSH: fetch the ssh:// share link (one per endpoint) for the QR while keeping
        // the server/port/user/pass rows. The backend builds the link so the modal QR
        // and this export stay identical.
        if (isSsh) {
          const cfgs = await AccountExport._fetchConfigs(dbInbound.id, client.email, 'ssh-configs');
          if (!cfgs.length) { cards.push(base); continue; }
          for (const cfg of cfgs) {
            cards.push(Object.assign({}, base, {
              server: cfg.host || base.server,
              port: cfg.port ? String(cfg.port) : base.port,
              remark: base.remark + (cfg.remark ? ' (' + cfg.remark + ')' : ''),
              link: cfg.link || '',
              qr: cfg.link || '',
            }));
          }
          continue;
        }

        // Connection-oriented VPNs (l2tp/pptp/ikev2/sstp/openconnect) have no config
        // file, but an external-proxy list advertises alternate server addresses. When
        // set, emit one card per endpoint so the exported credentials show the relay host
        // instead of the panel host.
        const connExtProxy = (proto === Protocols.L2TP || proto === Protocols.PPTP
          || proto === Protocols.OPENCONNECT || proto === Protocols.SSTP || proto === Protocols.IKEV2);
        if (connExtProxy) {
          const eps = (inbound.settings && Array.isArray(inbound.settings.externalProxy))
            ? inbound.settings.externalProxy.filter(e => e && String(e.dest || '').trim() !== '') : [];
          if (eps.length) {
            for (const ep of eps) {
              cards.push(Object.assign({}, base, {
                server: ep.dest,
                port: String(ep.port || inbound.port),
                remark: base.remark + (ep.remark ? ' (' + ep.remark + ')' : ''),
              }));
            }
            continue;
          }
        }

        cards.push(base);
      } catch (e) {
        if (typeof console !== 'undefined') console.warn('export: skipped account', t, e);
      }
    }
    return cards;
  },

  // _fetchConfigs pulls a protocol's server-rendered client configs for one account
  // (WireGuard-C .conf devices, or SSH endpoints with their ssh:// link).
  async _fetchConfigs(inboundId, email, endpoint) {
    try {
      // Respect the global axios baseURL: do NOT prefix with base_path here.
      const msg = await HttpUtil.get('/panel/api/inbounds/' + inboundId + '/' + endpoint, { email: email });
      return (msg && msg.success && Array.isArray(msg.obj)) ? msg.obj : [];
    } catch (e) {
      if (typeof console !== 'undefined') console.warn('export: config fetch failed', endpoint, inboundId, email, e);
      return [];
    }
  },

  // _isVpnProto reports whether the protocol is one of the non-xray VPN protocols,
  // whose display name is a single clean label (no "/ tcp" transport suffix).
  _isVpnProto(dbInbound) {
    const p = (dbInbound.protocol || '').toLowerCase();
    return p === Protocols.L2TP || p === Protocols.PPTP || p === Protocols.OPENVPN
      || p === Protocols.OPENCONNECT || p === Protocols.SSTP || p === Protocols.IKEV2
      || p === Protocols.WGC || p === Protocols.AWG || p === Protocols.GRE
      || p === Protocols.MTPROTO || p === Protocols.SSH;
  },

  // _protocolLabel is the human display name shown in the TXT/PDF. The VPN protocols
  // get a fixed, prettified name (WireGuard (C), IKEv2, OpenConnect, ...) instead of the
  // raw uppercase slug + a "/ tcp" suffix; xray protocols keep their uppercase slug
  // (the transport is appended separately via _network).
  _protocolLabel(dbInbound, inbound) {
    const proto = (dbInbound.protocol || '').toLowerCase();
    const s = inbound.settings || {};
    switch (proto) {
      case Protocols.L2TP: {
        const ipsecOn = s.ipsecEnable !== undefined ? !!s.ipsecEnable
          : (s.ipsec !== undefined ? !!s.ipsec : true);
        return ipsecOn ? 'L2TP/IPsec' : 'L2TP/RAW';
      }
      case Protocols.PPTP: return 'PPTP';
      case Protocols.OPENVPN: {
        const parts = [];
        if (s.tcpEnable) parts.push('TCP');
        if (s.udpEnable) parts.push('UDP');
        return 'OpenVPN' + (parts.length ? ' - ' + parts.join('/') : '');
      }
      case Protocols.OPENCONNECT: return 'OpenConnect';
      case Protocols.SSTP: return 'SSTP';
      case Protocols.IKEV2: return 'IKEv2';
      case Protocols.WGC: return 'WireGuard (C)';
      case Protocols.AWG: return 'AmneziaWG';
      case Protocols.GRE: {
        // Mirrors the L2TP label: the encryption mode is the thing an operator most needs
        // to see at a glance, because bare GRE is cleartext.
        if (!s.ipsecEnable) return 'GRE/RAW';
        return s.allowRaw ? 'GRE/IPsec (raw allowed)' : 'GRE/IPsec';
      }
      case Protocols.SSH: return 'SSH';
      case Protocols.MTPROTO: return 'MTProto'; // mode appended per-card in buildCards
      // Xray-native, so _isVpnProto is false and _network still appends the
      // transport suffix; these cases only replace the uppercased slug
      // (ANYTLS / TUIC / NAIVE) with the name the clients use.
      case Protocols.ANYTLS: return 'AnyTLS';
      case Protocols.TUIC: return 'TUIC';
      case Protocols.NAIVE: {
        // The transport is part of the protocol here, not of streamSettings, so it
        // belongs in the label: h2 over TLS, h3 over QUIC, or both.
        const net = s.network || 'tcp';
        if (net === 'udp') return 'NaiveProxy - h3';
        if (net === 'tcp') return 'NaiveProxy - h2';
        return 'NaiveProxy - h2/h3';
      }
      default: return (dbInbound.protocol || '').toUpperCase();
    }
  },

  _network(dbInbound, inbound) {
    // Only the xray protocols add a transport suffix; the VPN protocols fold everything
    // into the protocol label (see _protocolLabel).
    if (AccountExport._isVpnProto(dbInbound)) return '';
    if (inbound.stream) {
      const p = [inbound.stream.network];
      if (inbound.stream.isTls) p.push('TLS');
      if (inbound.stream.isReality) p.push('Reality');
      return p.filter(Boolean).join('/');
    }
    return '';
  },

  _portText(dbInbound, inbound) {
    // GRE is IP protocol 47 and has no ports at all, so printing the inbound's stored
    // number would be actively misleading: nothing listens on it.
    if ((dbInbound.protocol || '').toLowerCase() === Protocols.GRE) return 'n/a (IP proto 47)';
    if (dbInbound.isOpenvpn) {
      const s = inbound.settings || {};
      const parts = [];
      if (s.udpEnable) parts.push('UDP ' + (inbound.port));
      if (s.tcpEnable) parts.push('TCP ' + (s.separatePorts ? (s.tcpPort || 443) : inbound.port));
      return parts.join('  ') || String(inbound.port);
    }
    return String(inbound.port);
  },

  _psk(dbInbound, inbound, client) {
    if (dbInbound.isL2tp) {
      const s = inbound.settings || {};
      const ipsecOn = s.ipsecEnable !== undefined ? !!s.ipsecEnable
        : (s.ipsec !== undefined ? !!s.ipsec : true);
      return ipsecOn ? (s.ipsecPsk || s.psk || '') : '';
    }
    // GRE: the IPsec PSK is per INBOUND (shared by its accounts), like L2TP's.
    if ((dbInbound.protocol || '').toLowerCase() === Protocols.GRE) {
      const s = inbound.settings || {};
      return s.ipsecEnable ? (s.ipsecPsk || '') : '';
    }
    // WireGuard (C) / AmneziaWG: when preshared-key mode is on, each account has its own PSK.
    const wgLike = (dbInbound.protocol || '').toLowerCase();
    if ((wgLike === Protocols.WGC || wgLike === Protocols.AWG)
        && inbound.settings && inbound.settings.pskEnable) {
      return (client && client.psk) || '';
    }
    return '';
  },

  _expiryText(expiryTime) {
    if (!expiryTime || expiryTime === 0) return '∞';
    if (expiryTime < 0) {
      const days = Math.round(Math.abs(expiryTime) / 86400000);
      return 'delayed start (' + days + 'd)';
    }
    try { return IntlUtil.formatDate(expiryTime); }
    catch (e) { return new Date(expiryTime).toLocaleString(); }
  },

  // --- TXT -------------------------------------------------------------------

  txt(cards, filename) {
    const W = 52;
    const line = (label, val) =>
      val === '' || val === undefined || val === null
        ? null
        : '  ' + (label + ' :').padEnd(12, ' ') + ' ' + val;
    const bars = '═'.repeat(W);
    const dash = '─'.repeat(W);
    const blocks = cards.map(c => {
      const rows = [
        line('Server', c.server ? (c.server + ':' + c.port) : ''),
        line('Protocol', c.protocol + (c.network ? ' / ' + c.network : '')),
        line('Username', c.username),
        line('Password', c.password),
        line('UUID', c.uuid),
        line('PSK', c.psk),
        line('Expiry', c.expiry),
        line('Traffic', c.used + ' / ' + c.total),
        line('Status', c.enable ? 'Enabled' : 'Disabled'),
        line('Link', c.link),
      ].filter(Boolean);
      const title = ('  ' + (c.remark || c.email)).padEnd(W, ' ');
      let body = rows.join('\n');
      // WireGuard-C has no username/password; its usable credential is the full config,
      // so embed it (indented) under a divider. There is no QR in a .txt file.
      if (c.configText) {
        body += '\n' + dash + '\n' + c.configText.replace(/\n+$/, '').split('\n').map(l => '  ' + l).join('\n');
      }
      return [bars, title, dash, body, bars].join('\n');
    });
    const header = 'VPN Accounts — ' + cards.length + ' account(s)\nGenerated ' + new Date().toLocaleString() + '\n\n';
    FileManager.downloadTextFile(header + blocks.join('\n\n') + '\n', (filename || 'accounts') + '.txt', { type: 'text/plain' });
  },

  // --- PDF -------------------------------------------------------------------

  pdf(cards, filename) {
    if (!window.jspdf || !window.jspdf.jsPDF) {
      alert('PDF library not loaded');
      return;
    }
    const doc = new window.jspdf.jsPDF({ unit: 'pt', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 32;
    const cardW = pageW - margin * 2;
    const pad = 14;
    const lineH = 16;

    // Page title.
    let y = margin;
    doc.setFont('helvetica', 'bold'); doc.setFontSize(16);
    doc.setTextColor(40, 40, 40);
    doc.text('VPN Accounts', margin, y + 6);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9);
    doc.setTextColor(130, 130, 130);
    doc.text(cards.length + ' account(s) — ' + new Date().toLocaleString(), margin, y + 22);
    y += 44;

    for (const c of cards) {
      const rows = [
        c.server ? ['Server', c.server + ':' + c.port] : null,
        ['Protocol', c.protocol + (c.network ? '  /  ' + c.network : '')],
        c.username ? ['Username', c.username] : null,
        c.password ? ['Password', c.password] : null,
        c.uuid ? ['UUID', c.uuid] : null,
        c.psk ? ['PSK', c.psk] : null,
        ['Expiry', c.expiry],
        ['Traffic', c.used + '  /  ' + c.total],
        ['Status', c.enable ? 'Enabled' : 'Disabled'],
      ].filter(Boolean);

      const qr = c.qr ? AccountExport._qrDataUrl(c.qr) : '';
      const qrSize = qr ? 96 : 0;
      const bodyRows = rows.length + (c.link ? 1 : 0);
      const bodyH = Math.max(bodyRows * lineH, qrSize);
      const cardH = 30 /*header band*/ + pad + bodyH + pad;

      // New page if this card won't fit.
      if (y + cardH > pageH - margin) { doc.addPage(); y = margin; }

      // Card background + header band.
      doc.setDrawColor(224, 224, 224); doc.setFillColor(250, 250, 250);
      doc.roundedRect(margin, y, cardW, cardH, 6, 6, 'FD');
      doc.setFillColor(c.enable ? 124 : 176, c.enable ? 77 : 176, c.enable ? 255 : 176);
      doc.roundedRect(margin, y, cardW, 30, 6, 6, 'F');
      doc.rect(margin, y + 16, cardW, 14, 'F'); // square off the band's bottom corners
      doc.setTextColor(255, 255, 255); doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
      doc.text(AccountExport._clip(doc, c.remark || c.email, cardW - pad * 2 - 90), margin + pad, y + 20);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9);
      doc.text(c.protocol + (c.network ? ' · ' + c.network : ''), margin + cardW - pad, y + 20, { align: 'right' });

      // Body rows.
      let ry = y + 30 + pad + 4;
      const labelX = margin + pad;
      const valX = margin + pad + 78;
      const valMaxW = cardW - pad * 2 - 78 - (qr ? qrSize + 12 : 0);
      doc.setFontSize(10);
      for (const [label, val] of rows) {
        doc.setTextColor(140, 140, 140); doc.setFont('helvetica', 'normal');
        doc.text(label, labelX, ry);
        doc.setTextColor(40, 40, 40); doc.setFont('helvetica', 'bold');
        doc.text(AccountExport._clip(doc, String(val), valMaxW), valX, ry);
        ry += lineH;
      }
      if (c.link) {
        doc.setTextColor(140, 140, 140); doc.setFont('helvetica', 'normal');
        doc.text('Link', labelX, ry);
        doc.setTextColor(90, 90, 90); doc.setFontSize(7);
        doc.text(AccountExport._clip(doc, c.link, valMaxW), valX, ry);
        doc.setFontSize(10);
      }
      // QR on the right.
      if (qr) {
        doc.addImage(qr, 'PNG', margin + cardW - pad - qrSize, y + 30 + pad, qrSize, qrSize);
      }

      y += cardH + 16;
    }

    doc.save((filename || 'accounts') + '.pdf');
  },

  _qrDataUrl(text) {
    // level 'L' + a large source raster so a dense payload (a full WireGuard .conf,
    // ~300 chars) still fits and stays crisp when the PDF scales it down.
    try { return new QRious({ value: text, size: 512, level: 'L' }).toDataURL('image/png'); }
    catch (e) { return ''; }
  },

  _clip(doc, text, maxW) {
    if (!text) return '';
    if (doc.getTextWidth(text) <= maxW) return text;
    let t = text;
    while (t.length > 1 && doc.getTextWidth(t + '…') > maxW) t = t.slice(0, -1);
    return t + '…';
  },
};
