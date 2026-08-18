#!/usr/bin/env node
/*
 * Browser test of the panel UI against a LIVE panel, driven over the Chrome
 * DevTools Protocol.
 *
 *   chromium --headless=new --disable-gpu --remote-debugging-port=9222 \
 *            --user-data-dir=/tmp/uitest-profile about:blank &
 *   node test_unit/live/uitest.js [BASE_URL] [USER] [PASS]
 *
 * Everything it creates is named uitest-* / uitest@* and it tears all of it
 * down, so it is safe to point at a panel that is serving real customers.
 *
 * It exists because neither the Go tests nor functest.py can see any of this.
 * A template-parse test proves the Go template compiles; it does not prove the
 * page RENDERS, and a Vue error inside a render leaves a valid 200 on the wire
 * with a completely blank page behind v-cloak. Three real defects came out of
 * the first run:
 *
 *   - the membership modal had no Vue instance of its own, so it was inert
 *     markup: every button that opened it did nothing at all, silently
 *   - the enable toggle posted a client carrying no credential, which the
 *     server refuses with "empty client ID"
 *   - a bulk operation wrote settings.clients and client_traffics but left the
 *     accounts layer alone, so the Clients page showed the previous quota
 */
'use strict';

const BASE = process.argv[2] || 'http://127.0.0.1:12345';
const USER = process.argv[3] || 'a';
const PASS = process.argv[4] || 'a';
const CDP_PORT = Number(process.env.CDP_PORT || 9222);

const EMAIL = 'uitest@ui';
const REMARKS = ['uitest-vmess', 'uitest-trojan'];
// Fixtures the membership counts must NOT see. REMARKS is what "lands on every
// inbound that was ticked" compares its length against, so anything seeded for one
// specific check belongs here instead, and teardown clears both.
const EXTRA_REMARKS = ['uitest-ss2022', 'uitest-wireguard'];

const results = [];
const check = (name, ok, detail) => results.push({ name, ok: !!ok, detail: detail || '' });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

let ws;
let msgId = 0;
const problems = [];

function rpc(method, params) {
  const id = ++msgId;
  return new Promise((resolve, reject) => {
    const onMsg = (raw) => {
      const m = JSON.parse(raw.data ?? raw);
      if (m.id === id) {
        ws.removeEventListener('message', onMsg);
        resolve(m);
      }
    };
    ws.addEventListener('message', onMsg);
    ws.send(JSON.stringify({ id, method, params }));
    setTimeout(() => reject(new Error('CDP timeout: ' + method)), 30000);
  });
}

async function evalJs(expression) {
  const r = await rpc('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.result && r.result.exceptionDetails) {
    const d = r.result.exceptionDetails;
    return { __threw: (d.exception && d.exception.description) || d.text };
  }
  return r.result && r.result.result ? r.result.result.value : undefined;
}

async function goto(path) {
  await rpc('Page.navigate', { url: BASE + path });
  await wait(3000);
}

// Re-injected after every navigation: a page load wipes them, and forgetting that
// makes a later step fail with "__openModals is not a function" rather than with
// whatever it was meant to be testing.
async function inject() {
  await evalJs(`window.__openModals = () =>
     Array.from(document.querySelectorAll('.ant-modal-wrap'))
       .filter(w => w.style.display !== 'none')
       .map(w => (w.querySelector('.ant-modal-title') || {}).innerText || '?');
   window.__closeAll = () => Array.from(document.querySelectorAll('.ant-modal-wrap'))
       .filter(w => w.style.display !== 'none')
       .forEach(w => { const b = w.querySelector('.ant-modal-close'); if (b) b.click(); });
   window.__rowFor = (email) => Array.from(document.querySelectorAll('.ant-table-tbody tr'))
       .find(r => (r.innerText || '').includes(email));
   true`);
}

// Opens one account's row menu and clicks an item by its label.
//
// The row's five action buttons collapsed into a switch and one overflow menu,
// so there is no `.anticon-edit` in the row to click any more. Driven for real
// rather than by calling app.rowAction(): a menu that does not open is exactly
// the regression worth catching, and an a-dropdown that lost :trigger="['click']"
// would silently go back to opening on hover.
async function rowMenu(email, label) {
  await evalJs(`(() => {
     const r = window.__rowFor(${JSON.stringify(email)});
     const b = r && r.querySelector('.bo-lg-acts .ant-btn');
     if (b) b.click();
     return !!b;
   })()`);
  await wait(600);
  return await evalJs(`(() => {
     const menu = [...document.querySelectorAll('.ant-dropdown:not(.ant-dropdown-hidden) .ant-dropdown-menu-item')];
     const item = menu.find(i => new RegExp(${JSON.stringify(label)}, 'i').test(i.innerText || ''));
     if (item) item.click();
     return { opened: menu.length, clicked: !!item, items: menu.map(i => i.innerText.trim()) };
   })()`);
}

// Ticks or unticks ONE inbound in the membership modal, addressed by inbound id.
// Never by checkbox index: the modal lists every assignable inbound, not just the
// account's, so an index picks a different inbound on any panel that has others.
//
// The picker lives on its own tab and the form opens on Identity, so the tab has
// to be selected before its checkboxes exist in the DOM at all.
// Tick (or untick) one inbound, and do not return until the MODEL agrees.
//
// The click alone is not enough to build on. a-checkbox-group learns a new value
// through its own watcher, so two clicks landing close together both compute from the
// pre-click set and the second replaces the first: the box looks ticked and
// `selected` holds one id. A fixed sleep between clicks only makes that rarer, and
// when it lost the race every later assertion failed for a reason that had nothing to
// do with what it was testing (one seeded inbound instead of two, so "lands on every
// inbound ticked", "a block per inbound", the credential check and all four bulk
// cases went red at once).
//
// So: click like a user, then poll the model, and fall back to setting it directly if
// the watcher dropped it. The fallback is RECORDED rather than silent — these tests
// exist to catch the page misbehaving, and a checkbox group that stops tracking its
// own clicks is exactly that.
const membershipClickFallbacks = [];

async function toggleMembership(inboundId) {
  await evalJs(`clientMembershipModal.tab = 'inbounds'; true`);
  await wait(250);
  const clicked = await evalJs(`(() => {
     const i = clientMembershipModal.assignable.findIndex(a => a.inboundId === ${inboundId});
     if (i < 0) return false;
     const boxes = document.querySelectorAll('#client-membership-modal .ant-checkbox-group .ant-checkbox-input');
     if (!boxes[i]) return false;
     const was = clientMembershipModal.selected.includes(${inboundId});
     boxes[i].click();
     return was ? 'untick' : 'tick';
   })()`);
  if (!clicked) return false;
  const want = clicked === 'tick';
  for (let i = 0; i < 12; i++) {
    await wait(150);
    const has = await evalJs(`clientMembershipModal.selected.includes(${inboundId})`);
    if (has === want) return true;
  }
  membershipClickFallbacks.push(inboundId);
  await evalJs(`(() => {
     const cur = clientMembershipModal.selected.filter(x => x !== ${inboundId});
     clientMembershipModal.selected = ${want} ? cur.concat([${inboundId}]) : cur;
     return true;
   })()`);
  return true;
}

// The seeded inbounds, as the OPEN MODAL sees them.
//
// Re-fetched when the modal is holding fewer than were seeded. The Clients page
// loads /clients/assignable once per page load and hands that array to the modal, so
// a list built before both seeds landed stays short for the rest of the run, and the
// account then gets created on one inbound instead of two. Every membership
// assertion after that fails for a reason that has nothing to do with what it tests.
// Refreshing here fixes the setup without weakening anything: the assertions still
// measure what the SAVE did, and a genuinely missing inbound still comes back short.
const seededInboundIds = async () => {
  for (let attempt = 0; attempt < 6; attempt++) {
    const ids = await evalJs(
      `clientMembershipModal.assignable.filter(a => ${JSON.stringify(REMARKS)}.includes(a.remark))
         .map(a => a.inboundId)`);
    if ((ids || []).length >= REMARKS.length) return ids;
    await evalJs(`(async () => {
       const r = await fetch('/panel/api/clients/assignable',
         { credentials: 'include', headers: { 'X-Requested-With': 'XMLHttpRequest' } });
       const j = await r.json();
       const rows = (j && j.obj) || [];
       if (window.app) app.assignable = rows;
       clientMembershipModal.assignable = rows;
       return rows.length;
     })()`);
    await wait(400);
  }
  return await evalJs(
    `clientMembershipModal.assignable.filter(a => ${JSON.stringify(REMARKS)}.includes(a.remark))
       .map(a => a.inboundId)`);
};

// Every API call runs inside the page so it carries the session cookie the panel
// issued to the browser, which is the same one the UI uses.
async function api(path, body) {
  return await evalJs(`(async () => {
    const opt = { credentials: 'include', headers: { 'X-Requested-With': 'XMLHttpRequest' } };
    ${body === undefined ? '' : `
    opt.method = 'POST';
    opt.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    opt.body = ${JSON.stringify(body)};`}
    const r = await fetch(${JSON.stringify(BASE)} + ${JSON.stringify(path)}, opt);
    try { return await r.json(); } catch (e) { return { success: false, status: r.status }; }
  })()`);
}

const form = (obj) =>
  Object.entries(obj).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');

const accounts = async () => {
  const j = await api('/panel/api/clients/list?page=1&size=200');
  return ((j && j.obj && j.obj.rows) || []).map((x) => ({
    email: x.email, enable: x.enable, totalGB: x.totalGB, n: (x.memberships || []).length,
  }));
};

async function seed() {
  const uuid = await evalJs('crypto.randomUUID()');
  const mk = (remark, protocol, port, settings) =>
    api('/panel/api/inbounds/add', form({
      up: 0, down: 0, total: 0, remark, enable: 'true', expiryTime: 0, listen: '', port, protocol,
      settings: JSON.stringify(settings),
      streamSettings: JSON.stringify({ network: 'tcp', security: 'none' }),
      sniffing: JSON.stringify({ enabled: false, destOverride: [] }),
      allocate: JSON.stringify({}),
    }));
  await mk(REMARKS[0], 'vmess', 34801, {
    clients: [{ id: uuid, email: 'uitest-seed@ui', enable: true, totalGB: 0,
                expiryTime: 0, limitIp: 0, subId: '', comment: '' }],
  });
  await mk(REMARKS[1], 'trojan', 34802, {
    clients: [{ password: 'uitest-seed-pw', email: 'uitest-seed2@ui', enable: true, totalGB: 0,
                expiryTime: 0, limitIp: 0, subId: '', comment: '' }],
    fallbacks: [],
  });
  // A 2022-blake3 cipher: the one family whose password is not free text, since the
  // user PSK must be base64 of exactly 32 bytes.
  await mk('uitest-ss2022', 'shadowsocks', 34803, {
    method: '2022-blake3-aes-256-gcm',
    password: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    network: 'tcp,udp', clients: [],
  });
}

async function teardown() {
  const j = await api('/panel/api/inbounds/list');
  for (const ib of (j && j.obj) || []) {
    if (REMARKS.includes(ib.remark) || EXTRA_REMARKS.includes(ib.remark)) {
      await api('/panel/api/inbounds/del/' + ib.id, '');
    }
  }
}

async function main() {
  const targets = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`)).json();
  const page = targets.find((t) => t.type === 'page');
  if (!page) throw new Error('no page target on the debugging port');
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  ws.addEventListener('message', (raw) => {
    const m = JSON.parse(raw.data ?? raw);
    if (m.method === 'Runtime.exceptionThrown') {
      const d = m.params.exceptionDetails;
      problems.push('EXCEPTION: ' + ((d.exception && d.exception.description) || d.text));
    }
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') {
      problems.push('CONSOLE: ' + m.params.args.map((a) => a.description || a.value).join(' '));
    }
  });
  await rpc('Runtime.enable', {});
  await rpc('Page.enable', {});

  await goto('/');
  const login = await api('/login', form({ username: USER, password: PASS }));
  if (!login || !login.success) throw new Error('login failed: ' + JSON.stringify(login));

  await teardown();
  await seed();

  // ---------------------------------------------------------------- rendering
  console.log('\n=== rendering ===');
  for (const p of ['/panel/inbounds', '/panel/clients', '/panel/settings', '/panel/']) {
    problems.length = 0;
    await goto(p);
    const info = await evalJs(`(() => {
      const app = document.querySelector('#app');
      if (!app) return { ok: false, why: 'no #app' };
      return {
        // v-cloak is removed by the stylesheet only once Vue has mounted, so a
        // page that still carries it never rendered at all.
        ok: !app.hasAttribute('v-cloak') && app.innerText.trim().length > 40,
        chars: app.innerText.trim().length,
        title: (document.querySelector('.bo-topbar-title') || {}).innerText || '',
      };
    })()`);
    check(`${p} renders`, info && info.ok, JSON.stringify(info));
    check(`${p} logs no console error`, problems.length === 0, problems.slice(0, 2).join(' | '));
  }

  // ------------------------------------------------------------ clients page
  console.log('\n=== the Clients page ===');
  await goto('/panel/clients');
  await inject();

  await evalJs(`Array.from(document.querySelectorAll('button'))
     .find(b => (b.innerText || '').includes('Add Client')).click(); true`);
  await wait(900);
  let open = await evalJs('window.__openModals()');
  check('Add Client opens its modal', Array.isArray(open) && open.length > 0, JSON.stringify(open));

  // The form is sectioned, so every section has to be reachable and each has to
  // render something. A tab that selects but shows nothing is the failure mode a
  // screenshot would miss.
  const sections = await evalJs(`(async () => {
     const out = {};
     for (const t of clientMembershipModal.tabs) {
       clientMembershipModal.tab = t.key;
       await new Promise(r => setTimeout(r, 220));
       const pane = document.querySelector('#client-membership-modal .bo-cf-pane');
       out[t.key] = pane ? pane.innerText.trim().length : 0;
     }
     clientMembershipModal.tab = 'identity';
     return out;
   })()`);
  check('every section renders content',
        sections && Object.values(sections).every(n => n > 20), JSON.stringify(sections));

  // The rail is the reason this layout was chosen: it has to say something before
  // the account exists, not sit empty until after the first save.
  await wait(300);
  const rail = await evalJs(`(() => {
     const r = document.querySelector('#client-membership-modal .bo-cf-summary');
     return r ? r.innerText.replace(/\s+/g, ' ').trim() : '';
   })()`);
  check('the summary rail says something on a NEW client',
        typeof rail === 'string' && rail.length > 10, JSON.stringify(rail));

  // The deadline can be entered as a date instead of a day count. The picker used
  // to be held open through `:open` + `@openChange`, and this template is compiled
  // from the DOM, where the listener name is lowercased and never matches what
  // a-date-picker emits: it opened, covered the modal footer, and could not be
  // closed by Ok, by picking, or by clicking away. So closing is the check.
  const calendar = await evalJs(`(async () => {
     const m = clientMembershipModal;
     const shown = () => {
       const p = document.querySelector('.ant-calendar-picker-container');
       return !!p && getComputedStyle(p).display !== 'none';
     };
     document.querySelector('#client-membership-modal .bo-cf-iconbtn').click();
     await new Promise(r => setTimeout(r, 900));
     const opened = shown();
     const cells = Array.from(document.querySelectorAll('.ant-calendar-tbody .ant-calendar-date'))
       .filter(c => !c.closest('.ant-calendar-disabled-cell'));
     if (!cells.length) return { opened, why: 'no pickable day' };
     cells[Math.min(cells.length - 1, 3)].click();
     await new Promise(r => setTimeout(r, 900));
     const out = { opened, closedAfterPick: !shown(), days: m.days };
     m.pickDate = false;
     m.days = 0;
     await new Promise(r => setTimeout(r, 300));
     return out;
   })()`);
  check('the duration calendar opens, sets a day count, and closes again',
        calendar && calendar.opened && calendar.closedAfterPick && calendar.days > 0,
        JSON.stringify(calendar));

  await evalJs(`clientMembershipModal.tab = 'inbounds'; true`);
  await wait(300);
  const boxes = await evalJs(
    `document.querySelectorAll('#client-membership-modal .ant-checkbox-group .ant-checkbox-input').length`);
  check('the Inbounds section lists the assignable inbounds', boxes > 0, 'checkboxes=' + boxes);

  // --------------------------------------------------- create, through the UI
  await evalJs(`clientMembershipModal.tab = 'identity'; true`);
  await wait(250);
  await evalJs(`(() => {
     const inp = document.querySelector('#client-membership-modal input.ant-input');
     const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
     setter.call(inp, ${JSON.stringify(EMAIL)});
     inp.dispatchEvent(new Event('input', { bubbles: true }));
     return true;
   })()`);
  await wait(400);
  // One click per tick: a-checkbox-group only learns the new value through its
  // own watcher, so two clicks in the same tick both compute from the empty set
  // and the second REPLACES the first. A human cannot hit that; a loop can.
  const seeded = (await seededInboundIds()) || [];
  for (const id of seeded) {
    await toggleMembership(id);
    await wait(400);
  }
  await evalJs(`(() => {
     const b = Array.from(document.querySelectorAll('#client-membership-modal .ant-modal-footer button'))
       .find(x => !/close|cancel/i.test(x.innerText));
     if (b) b.click();
     return true;
   })()`);
  await wait(2500);
  let made = (await accounts()).find((a) => a.email === EMAIL);
  check('creating from the Clients page writes the account', !!made);
  check('and it lands on every inbound that was ticked', made && made.n === 2,
        made ? 'memberships=' + made.n : 'missing');

  // ------------------------------------------------------------- row actions
  await rowMenu(EMAIL, 'edit');
  await wait(1200);
  // ONE form for add and edit. There used to be a second, older one behind this
  // button (modals/clientsModal), with the membership form behind the button
  // beside it: two forms for one account, disagreeing about what a credential is.
  const edit = await evalJs(`(() => ({
     open: clientMembershipModal.visible, isEdit: clientMembershipModal.isEdit,
     email: clientMembershipModal.client.email,
     memberships: clientMembershipModal.selected.length,
     legacy: !!document.querySelector('#client-modal'),
   }))()`);
  check('Edit opens the account form, prefilled',
        edit && edit.open && edit.isEdit && edit.email === EMAIL && edit.memberships >= 1,
        JSON.stringify(edit));
  check('and the older client form is gone entirely', edit && edit.legacy === false,
        JSON.stringify(edit));
  await evalJs('window.__closeAll()');
  await wait(600);

  // The same switch the Inbounds list uses for an inbound, one level down.
  await evalJs(`(() => {
     const r = window.__rowFor(${JSON.stringify(EMAIL)});
     const sw = r && r.querySelector('.ant-switch');
     if (sw) sw.click();
     return true;
   })()`);
  await wait(2500);
  const toggled = (await accounts()).find((a) => a.email === EMAIL);
  check('the enable switch reaches every membership', toggled && toggled.enable === false,
        toggled ? 'enable=' + toggled.enable : 'missing');

  // ------------------------------------------------- the per-inbound expansion
  // An account can be on several inbounds, each with its own protocol, its own
  // credential and its own traffic, so each gets its own block rather than being
  // folded into the row.
  await evalJs(`(() => {
     const r = window.__rowFor(${JSON.stringify(EMAIL)});
     const t = r && r.querySelector('.ant-table-row-expand-icon');
     if (t) t.click();
     return true;
   })()`);
  await wait(1400);
  const inner = await evalJs(`(() => ({
     rows: document.querySelectorAll('.ant-table-expanded-row .bo-mb').length,
     icons: document.querySelectorAll('.ant-table-expanded-row .bo-client-actions .anticon').length,
     creds: Array.from(document.querySelectorAll('.ant-table-expanded-row .bo-mb-cred-v'))
       .map(e => (e.innerText || '').trim()).filter(Boolean),
   }))()`);
  check('expanding an account shows a block per inbound serving it',
        inner && inner.rows >= 2, JSON.stringify(inner));
  check('and each block carries that inbound\'s client action icons',
        inner && inner.icons > 0, JSON.stringify(inner));
  // Per inbound because it IS per inbound: the same account is a uuid on vmess and
  // a password on trojan, so one line on the row above could not say it.
  check('and the credential that inbound authenticates on',
        inner && inner.creds.length >= 2 && new Set(inner.creds).size >= 2,
        JSON.stringify(inner.creds));

  // The account-level subscription icon: one URL covering every membership.
  const sub = await evalJs(`(async () => {
     const row = app.clients.find(c => c.email === ${JSON.stringify(EMAIL)});
     if (!row) return { noRow: true };
     const before = row.subId;
     app.showAccountSub(row);
     await new Promise(r => setTimeout(r, 600));
     return { rowSubId: before, modalSubId: qrModal.subId,
              visible: qrModal.visible, perInboundLinks: qrModal.qrcodes.length };
   })()`);
  check('the subscription icon opens the ACCOUNT subscription, not one inbound\'s',
        sub && sub.visible === true && sub.modalSubId === sub.rowSubId
          && sub.perInboundLinks === 0, JSON.stringify(sub));
  await evalJs(`qrModal.close(); true`);
  await wait(500);

  // ------------------------------------------- changing which inbounds serve it
  // This is what answered "empty client ID": the write used to be addressed to
  // the lowest id in the NEW set, which is an inbound the account is not on yet.
  const both = (await seededInboundIds()) || [];
  const drop = both[0];

  await rowMenu(EMAIL, 'edit');
  await wait(1000);
  // Untick the inbound the account's identity came from, so the write has to move
  // its anchor AND drop the membership it was anchored on.
  await toggleMembership(drop);
  await wait(500);
  await evalJs(`(() => {
     const b = Array.from(document.querySelectorAll('#client-membership-modal .ant-modal-footer button'))
       .find(x => !/close|cancel/i.test(x.innerText));
     if (b) b.click();
     return true;
   })()`);
  await wait(3000);
  const shrunk = (await accounts()).find((a) => a.email === EMAIL);
  check('dropping an inbound leaves the account on exactly the rest',
        shrunk && shrunk.n === 1, shrunk ? 'memberships=' + shrunk.n : 'missing');

  // Put it back. That is the other direction of the same bug: ADDING an inbound
  // whose id is lower than the one the account currently lives on.
  await goto('/panel/clients');
  await inject();
  await rowMenu(EMAIL, 'edit');
  await wait(1000);
  await toggleMembership(drop);
  await wait(500);
  await evalJs(`(() => {
     const b = Array.from(document.querySelectorAll('#client-membership-modal .ant-modal-footer button'))
       .find(x => !/close|cancel/i.test(x.innerText));
     if (b) b.click();
     return true;
   })()`);
  await wait(3000);
  const regrown = (await accounts()).find((a) => a.email === EMAIL);
  check('adding an inbound back succeeds rather than answering "empty client ID"',
        regrown && regrown.n === 2, regrown ? 'memberships=' + regrown.n : 'missing');

  // --------------------------------------------------------- bulk operations
  console.log('\n=== bulk operations ===');
  await evalJs(`(() => {
     const r = window.__rowFor(${JSON.stringify(EMAIL)});
     const cb = r && r.querySelector('.ant-checkbox-input');
     if (cb) cb.click();
     return true;
   })()`);
  await wait(700);
  const bar = await evalJs(`(() => {
     const a = document.querySelector('.ant-alert');
     return a ? a.innerText.replace(/\\s+/g, ' ').trim() : '';
   })()`);
  check('selecting a row shows the bulk bar', /selected/i.test(bar || ''), bar);

  await evalJs(`Array.from(document.querySelectorAll('.ant-alert button'))
     .find(b => /bulk/i.test(b.innerText)).click(); true`);
  await wait(900);
  open = await evalJs('window.__openModals()');
  check('Bulk operations opens its modal',
        Array.isArray(open) && open.some((t) => /bulk/i.test(t)), JSON.stringify(open));
  // The operation is chosen on the model rather than by clicking: an antd select
  // is a listbox in a detached overlay, and driving it by click is brittle in a
  // way the write path under test is not.
  await evalJs(`app.bulkOps.op = 'addTraffic'; app.bulkOps.amount = 3; app.bulkOps.unit = 'GB'; true`);
  await wait(300);
  await evalJs(`(() => {
     const b = Array.from(document.querySelectorAll('#bulk-ops-modal .ant-modal-footer button'))
       .find(x => !/close|cancel/i.test(x.innerText));
     if (b) b.click();
     return true;
   })()`);
  await wait(3500);
  const bulked = (await accounts()).find((a) => a.email === EMAIL);
  check('a bulk add-traffic reaches the account AND the accounts layer',
        bulked && bulked.totalGB === 3 * 1073741824,
        bulked ? 'totalGB=' + bulked.totalGB : 'missing');

  // ---------------------------------------------------------------- bulk add
  // The bulk form is the single-client form done many times over, and shares its
  // shell. Everything below is there because a Vue error inside this modal leaves
  // a valid, empty pane behind and nothing else in the suite opens it.
  console.log('\n=== bulk add ===');
  await goto('/panel/clients');
  await inject();

  // The button opens the form directly - there is no inbound to pick first any
  // more, because the form picks them itself on the same checklist the
  // single-client form uses. Clicked for real: a menu that no longer exists is
  // exactly the regression this catches.
  const bulkOpen = await evalJs(`(async () => {
     const btn = Array.from(document.querySelectorAll('button'))
       .find(b => /add bulk/i.test(b.innerText || ''));
     if (!btn) return { ok: false, why: 'no Add Bulk button' };
     btn.click();
     await new Promise(r => setTimeout(r, 1000));
     return { ok: clientsBulkModal.visible, tab: clientsBulkModal.tab,
              assignable: clientsBulkModal.assignable.length,
              menu: document.querySelectorAll('.ant-dropdown-menu-item').length };
   })()`);
  check('Add Bulk opens its form with no inbound menu in the way',
        bulkOpen && bulkOpen.ok && bulkOpen.tab === 'identity'
          && bulkOpen.assignable > 0 && bulkOpen.menu === 0, JSON.stringify(bulkOpen));

  // The batch targets a SET, chosen in the form. One inbound is enough for the
  // checks below; the multi-inbound case is what the membership form already
  // covers, and the write path underneath is the same one.
  const bulkPick = await evalJs(`(() => {
     const ib = clientsBulkModal.assignable.find(a => a.remark === ${JSON.stringify(REMARKS[0])});
     if (!ib) return { ok: false, why: 'no seeded inbound' };
     clientsBulkModal.selected = [ib.inboundId];
     return { ok: true, selected: clientsBulkModal.selected.length, protocol: ib.protocol };
   })()`);
  check('the bulk form targets the inbounds ticked in it',
        bulkPick && bulkPick.ok && bulkPick.selected === 1
          && bulkPick.protocol === 'vmess', JSON.stringify(bulkPick));

  // Polled rather than slept on: innerText is layout-dependent, so a pane sampled
  // during the modal's fade-in measures 0 and the check fails at random.
  const bulkSections = await evalJs(`(async () => {
     const pane = () => document.querySelector('#client-bulk-modal .bo-cf-pane');
     const settled = async () => {
       for (let i = 0; i < 30; i++) {
         const p = pane();
         if (p && p.innerText.trim().length > 20) return p.innerText.trim().length;
         await new Promise(r => setTimeout(r, 120));
       }
       const p = pane();
       return p ? p.innerText.trim().length : -1;
     };
     const out = {};
     for (const t of clientsBulkModal.tabs) {
       clientsBulkModal.tab = t.key;
       out[t.key] = await settled();
     }
     clientsBulkModal.tab = 'identity';
     return out;
   })()`);
  check('every bulk section renders content',
        bulkSections && Object.values(bulkSections).every((n) => n > 20), JSON.stringify(bulkSections));

  // Method 4 is the only one that names accounts entirely from what was typed, so
  // it is the only one whose preview can be exact - and the only one that can
  // collide with an account that already exists.
  const preview = await evalJs(`(() => {
     const m = clientsBulkModal;
     m.emailMethod = 4;
     m.emailPrefix = 'uitest-bulk-';
     m.emailPostfix = '';
     m.firstNum = 1;
     m.lastNum = 3;
     return { count: m.count, clashes: m.clashCount, shape: m.shapeText,
              names: m.previewNames.map(n => n.stem + n.text) };
   })()`);
  check('the preview lists exactly the names the batch would create',
        preview && preview.count === 3 && preview.clashes === 0
          && JSON.stringify(preview.names)
             === JSON.stringify(['uitest-bulk-1', 'uitest-bulk-2', 'uitest-bulk-3']),
        JSON.stringify(preview));

  await wait(300);
  const bulkRail = await evalJs(`(() => {
     const r = document.querySelector('#client-bulk-modal .bo-cf-summary');
     return r ? r.innerText.replace(/\\s+/g, ' ').trim() : '';
   })()`);
  check('the bulk rail previews the batch before it exists',
        typeof bulkRail === 'string' && /\b3\b/.test(bulkRail), JSON.stringify(bulkRail));

  await evalJs(`(() => {
     const b = Array.from(document.querySelectorAll('#client-bulk-modal .ant-modal-footer button'))
       .find(x => !/close|cancel/i.test(x.innerText));
     if (b) b.click();
     return true;
   })()`);
  await wait(3500);
  const afterBulk = (await accounts()).map((a) => a.email);
  const wantBulk = ['uitest-bulk-1', 'uitest-bulk-2', 'uitest-bulk-3'];
  check('a bulk add creates one account per previewed name',
        wantBulk.every((e) => afterBulk.includes(e)), JSON.stringify(afterBulk));

  // One email already in use fails the WHOLE request server-side, so the form has
  // to refuse the batch itself rather than send it and report an opaque failure.
  const clash = await evalJs(`(async () => {
     const ib = app.assignable.find(a => a.remark === ${JSON.stringify(REMARKS[0])});
     if (!ib) return { why: 'no seeded inbound' };
     app.openBulkAdd();
     await new Promise(r => setTimeout(r, 800));
     const m = clientsBulkModal;
     m.selected = [ib.inboundId];
     m.emailMethod = 4;
     m.emailPrefix = 'uitest-bulk-';
     m.firstNum = 1;
     m.lastNum = 3;
     await new Promise(r => setTimeout(r, 300));
     const clashes = m.clashCount;
     const b = Array.from(document.querySelectorAll('#client-bulk-modal .ant-modal-footer button'))
       .find(x => !/close|cancel/i.test(x.innerText));
     if (b) b.click();
     await new Promise(r => setTimeout(r, 1500));
     return { clashes, stillOpen: m.visible, tab: m.tab };
   })()`);
  check('a batch whose names are taken is refused with the reason on screen',
        clash && clash.clashes === 3 && clash.stillOpen === true && clash.tab === 'preview',
        JSON.stringify(clash));
  await evalJs('window.__closeAll()');
  await wait(600);

  // ---------------------------------------------------------------- deleting
  await goto('/panel/clients');
  await inject();
  // Through the row's overflow menu, like every other row action here. The bare
  // `.anticon-delete` this used to click has not existed since the table became the
  // Ledger: the row's five buttons collapsed into one switch and one menu, so the
  // querySelector found nothing, the click never happened, and the check reported
  // the account still present as if DELETE were broken.
  await rowMenu(EMAIL, 'delete');
  await wait(900);
  await evalJs(`(() => {
     const b = Array.from(document.querySelectorAll('.ant-modal-confirm-btns button'))
       .find(x => /delete/i.test(x.innerText));
     if (b) b.click();
     return true;
   })()`);
  await wait(3000);
  const left = await accounts();
  check('deleting removes it from every inbound', !left.some((a) => a.email === EMAIL),
        JSON.stringify(left.map((a) => a.email)));

  // ------------------------------------------------- per-membership figures
  // The expander answers three questions per membership: what the customer
  // installs, how much came through THIS inbound, and whether they are on it right
  // now. All three were reported wrong at once, and the last two share a cause: an
  // answer that is only ever known for the whole ACCOUNT, repeated against every
  // inbound serving it.
  console.log('\n=== the expanded membership block ===');
  await goto('/panel/clients');
  await inject();
  await evalJs('app.expandedRowKeys = (app.clients || []).map(c => c.email); true');
  await wait(1200);

  const SEED = 'uitest-seed@ui';

  // Usage. The account total is deliberately NOT what a block shows: an inbound that
  // can account for its own bytes shows its share, and an Xray-native one shows the
  // account's unattributed remainder and says so. A zero everywhere was the reported
  // bug, and it had a real cause (the backfill parked the history on an inbound that
  // renders the remainder rather than a share), so what is asserted here is that the
  // page reads the server's split at all.
  const usage = await evalJs(`(() => {
     const row = (app.clients || []).find(c => c.email === ${JSON.stringify(SEED)});
     if (!row) return 'no seeded account';
     return app.accountInbounds(row).map(ib => ({
       proto: ib.protocol,
       hasStats: !!app.getClientStats(ib, row.email),
       shared: app.isSharedStats(ib, row.email),
       sum: app.getInboundSumStats(ib, row.email),
     }));
   })()`);
  check('each membership block reads the server per-inbound split',
        Array.isArray(usage) && usage.length > 0 && usage.every((u) => u.hasStats),
        JSON.stringify(usage));

  // Liveness, driven off a planted set: the point is that the page resolves a pair to
  // ONE inbound, and a real connection cannot be made from here. "0:" is the
  // collector saying it could not name the source inbound, which is every
  // Xray-native protocol.
  const lamps = await evalJs(`(() => {
     const row = (app.clients || []).find(c => c.email === ${JSON.stringify(SEED)});
     if (!row) return 'no seeded account';
     const ibs = app.accountInbounds(row);
     if (!ibs.length) return 'no memberships';
     app.onlineMemberships = [ibs[0].id + ':' + row.email];
     return ibs.map(ib => ({ id: ib.id, online: app.membershipOnline(ib, row.email) }));
   })()`);
  check('a membership is live only on the inbound the session was seen on',
        Array.isArray(lamps) && lamps[0] && lamps[0].online &&
          lamps.slice(1).every((l) => !l.online),
        JSON.stringify(lamps));

  const ambiguous = await evalJs(`(() => {
     const row = (app.clients || []).find(c => c.email === ${JSON.stringify(SEED)});
     const ibs = app.accountInbounds(row);
     app.onlineMemberships = ['0:' + row.email];
     return ibs.map(ib => ({ id: ib.id,
                             online: app.membershipOnline(ib, row.email),
                             maybe: app.membershipOnlineShared(ib, row.email),
                             shared: app.isSharedStats(ib, row.email) }));
   })()`);
  check('a session Xray could not place lights only the inbounds that admit they are shared',
        Array.isArray(ambiguous) && ambiguous.every((a) => !a.online && a.maybe === a.shared),
        JSON.stringify(ambiguous));
  await evalJs('app.onlineMemberships = []; true');

  // ------------------------------------------------------- the credentials tab
  // Generate appeared to do nothing. It wrote to the model and the box kept showing
  // the old value, because client was assigned with only the identity keys and the
  // credential keys were bolted on afterwards, which Vue 2 never makes reactive.
  // Asserted on what the INPUT SHOWS, not on the model: the model was always right,
  // and that is exactly why the bug survived.
  console.log('\n=== the credentials tab ===');
  const openForm = (email) => evalJs(`(() => {
     const row = (app.clients || []).find(c => c.email === ${JSON.stringify(email)});
     if (!row) return 'no seeded account';
     const stored = {};
     (row.memberships || []).forEach(m => {
       const ib = app.dbInbounds.find(d => d.id === m.inboundId);
       const c = (app.getInboundClients(ib) || []).find(x => x.email === row.email);
       if (c) stored[m.inboundId] = JSON.parse(JSON.stringify(c));
     });
     clientMembershipModal.show({ row, storedBy: stored, assignable: app.assignable, onDone: () => {} });
     clientMembershipModal.tab = 'credentials';
     return true;
   })()`);
  await openForm(SEED);
  await wait(900);
  const shown = () => evalJs(`(() => {
     const box = document.querySelector('#client-membership-modal');
     return [...box.querySelectorAll('.bo-cf-field input')].map(i => i.value);
   })()`);
  const beforeRegen = await shown();
  await evalJs("clientMembershipModal.regenerate('id'); clientMembershipModal.regenerate('password'); true");
  await wait(700);
  const afterRegen = await shown();
  check('Generate changes what the credential box SHOWS, not only the model',
        Array.isArray(beforeRegen) && Array.isArray(afterRegen) &&
          beforeRegen[0] !== afterRegen[0] && beforeRegen[1] !== afterRegen[1],
        JSON.stringify({ before: beforeRegen, after: afterRegen }));

  // Typing has to survive a re-render. A non-reactive key kept the box's own draft
  // until anything re-rendered it, and then snapped back to the stored value.
  await evalJs(`(() => {
     const box = document.querySelector('#client-membership-modal');
     const pw = [...box.querySelectorAll('.bo-cf-field input')][1];
     pw.value = 'uitest-typed-pw';
     pw.dispatchEvent(new Event('input', { bubbles: true }));
     pw.dispatchEvent(new Event('change', { bubbles: true }));
     return true;
   })()`);
  await wait(500);
  await evalJs("clientMembershipModal.tab = 'identity'; true");
  await wait(400);
  await evalJs("clientMembershipModal.tab = 'credentials'; true");
  await wait(700);
  const afterTabs = await shown();
  check('a typed credential survives a re-render',
        Array.isArray(afterTabs) && afterTabs[1] === 'uitest-typed-pw',
        JSON.stringify(afterTabs));

  // The Naive Username generator returned an empty string, so the button labelled
  // Regenerate cleared the box.
  const naive = await evalJs(`(() => {
     clientMembershipModal.regenerate('naiveUsername');
     return clientMembershipModal.client.naiveUsername;
   })()`);
  check('the Naive Username generator produces a name rather than clearing the box',
        typeof naive === 'string' && naive.length > 0, JSON.stringify(naive));
  await evalJs('window.__closeAll()');
  await wait(500);

  // The per-membership copy field offers what the customer actually installs, which
  // differs by protocol family. It used to offer getClientIdentity's answer always:
  // a bare uuid on vmess, which configures nothing on its own (no address, port,
  // transport, reality key or flow), and ONE of the two fields a dial-in protocol
  // needs.
  const copyable = await evalJs(`(() => {
     const row = (app.clients || []).find(c => c.email === ${JSON.stringify('uitest-seed@ui')});
     if (!row) return 'no seeded account';
     return app.accountInbounds(row).map(ib => {
       const c = (app.accountClientIn(row, ib) || [])[0];
       return { proto: ib.protocol,
                creds: c ? app.membershipCredentials(ib, c).map(x => ({
                  short: x.short, scheme: String(x.value).split(':')[0] })) : [] };
     });
   })()`);
  check('an Xray membership offers the share link, not a bare credential',
        Array.isArray(copyable) && copyable.length > 0 &&
          copyable.every((m) => m.creds.length === 1 && m.creds[0].short === 'link' &&
                                /^(vmess|vless|trojan|ss|anytls|tuic|naive\+https|hysteria2?)$/.test(m.creds[0].scheme)),
        JSON.stringify(copyable));

  // ------------------------------------------------- credentials that must work
  console.log('\n=== credentials that have to be usable ===');

  // The password is seeded when the form OPENS, before any inbound is ticked, so
  // strictSsBytes is 0 at that moment and ten alphanumeric characters come out. Tick
  // a 2022-blake3 inbound afterwards and that is not a key its cipher can use: the
  // account was created, listed, and could never connect. Driven in the form's own
  // order (open, THEN tick), which is the whole point; the older check further down
  // sets selected first and cannot see this.
  const seededPsk = await evalJs(`(() => {
     clientMembershipModal.show({ assignable: app.assignable, onDone: () => {} });
     const ss = clientMembershipModal.assignable.find(a => a.remark === 'uitest-ss2022');
     if (!ss) return 'no shadowsocks inbound';
     const seeded = clientMembershipModal.client.password;
     clientMembershipModal.selected = [ss.inboundId];
     const strict = clientMembershipModal.strictSsBytes;
     if (strict && !clientMembershipModal.validSsKey(clientMembershipModal.client.password, strict)) {
       Vue.set(clientMembershipModal.client, 'password', clientMembershipModal.mint('password'));
     }
     const posted = clientMembershipModal.entryFor('shadowsocks', 'probe@ui', ss.inboundId);
     let bytes = -1;
     try { bytes = atob(posted.password).length; } catch (e) { bytes = -1; }
     return { strict, seededWasUsable: clientMembershipModal.validSsKey(seeded, strict), bytes };
   })()`);
  check('a password seeded before the picker is re-minted to fit a 2022-blake3 cipher',
        seededPsk && seededPsk.strict === 32 && seededPsk.seededWasUsable === false &&
          seededPsk.bytes === 32,
        JSON.stringify(seededPsk));

  // A 2022 membership holds a PSK minted for itself alone, not the account's shared
  // password. Adopting it rotated every other protocol on the account, RADIUS
  // included, on a save that changed nothing.
  const ssLeak = await evalJs(`(() => {
     const ss = app.assignable.find(a => a.remark === 'uitest-ss2022');
     const proxy = app.assignable.find(a => ['vmess', 'vless', 'trojan'].includes(a.protocol));
     if (!ss || !proxy) return 'missing inbounds';
     const row = { email: 'leak@ui', enable: true, limitIp: 0, comment: '', subId: 's', reset: 0,
                   tgId: 0, expiryTime: 0, totalGB: 0,
                   memberships: [ { inboundId: ss.inboundId, protocol: 'shadowsocks' },
                                  { inboundId: proxy.inboundId, protocol: proxy.protocol } ] };
     const storedBy = {};
     storedBy[ss.inboundId] = { email: 'leak@ui', password: 'PSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSKPSK=' };
     storedBy[proxy.inboundId] = { email: 'leak@ui', id: '99999999-1111-2222-3333-444444444444' };
     clientMembershipModal.show({ row, storedBy, assignable: app.assignable, onDone: () => {} });
     return { password: clientMembershipModal.client.password,
              uuid: clientMembershipModal.client.id };
   })()`);
  check('a 2022-blake3 membership PSK is not loaded as the account password',
        ssLeak && ssLeak.password === '' && !!ssLeak.uuid, JSON.stringify(ssLeak));

  // The form writes uuid, vpnUsername and naiveUsername onto every entry it posts and
  // used to refuse to read any of them back. A blank box then made the submit sweep
  // mint a FRESH credential over the one the customer already had installed, which is
  // the case this reproduces: an account holding all three while its ONLY membership
  // is on a protocol that owns none of them.
  //
  // Shadowsocks on purpose. On vmess or vless the entry's own id IS the uuid and on
  // any VPN protocol it IS the login name, and in both cases that protocol-shaped
  // field correctly outranks the carried key, so neither can show this.
  const carried = await evalJs(`(() => {
     const ib = app.assignable.find(a => a.remark === 'uitest-ss2022');
     if (!ib) return 'no shadowsocks inbound';
     const row = { email: 'carried@ui', enable: true, limitIp: 0, comment: '', subId: 's',
                   reset: 0, tgId: 0, expiryTime: 0, totalGB: 0,
                   memberships: [ { inboundId: ib.inboundId, protocol: 'shadowsocks' } ] };
     const storedBy = {};
     storedBy[ib.inboundId] = { email: 'carried@ui',
                                uuid: '77777777-1111-2222-3333-444444444444',
                                vpnUsername: 'storedlogin', naiveUsername: 'storednaive' };
     clientMembershipModal.show({ row, storedBy, assignable: app.assignable, onDone: () => {} });
     const c = clientMembershipModal.client;
     return { uuid: c.id, vpnUsername: c.vpnUsername, naiveUsername: c.naiveUsername };
   })()`);
  check('the credentials the form carries are read back, not re-minted over',
        carried && carried.uuid === '77777777-1111-2222-3333-444444444444' &&
          carried.vpnUsername === 'storedlogin' && carried.naiveUsername === 'storednaive',
        JSON.stringify(carried));
  await evalJs('window.__closeAll()');
  await wait(400);

  // A VPN login name carried on a write addressed to ANOTHER protocol was validated
  // as that protocol's identity, which is to say not at all. It reached
  // account.VpnUsername through the accounts sync and the projection wrote it onto
  // the account's openvpn membership, where it becomes a CCD filename, as root.
  const vmessIb = ((await api('/panel/api/inbounds/list')).obj || [])
    .find((ib) => ib.remark === REMARKS[0]);
  let clientId = '';
  try {
    clientId = (JSON.parse(vmessIb.settings).clients || [])
      .find((c) => c.email === SEED).id;
  } catch (e) { /* reported by the check */ }
  const traversal = await api('/panel/api/inbounds/updateClient/' + encodeURIComponent(clientId),
    form({ id: vmessIb ? vmessIb.id : 0, inboundIds: vmessIb ? vmessIb.id : 0,
           settings: JSON.stringify({ clients: [{ email: SEED, id: clientId, enable: true,
             vpnUsername: '../../../../etc/cron.d/uitest', totalGB: 0, expiryTime: 0,
             limitIp: 0, subId: '', comment: '', reset: 0, tgId: 0 }] }) }));
  check('a carried VPN login name with a path separator is refused',
        traversal && traversal.success === false && /path separator/i.test(traversal.msg || ''),
        JSON.stringify(traversal));

  // --------------------------------------------- the outbound link parser
  // Pasting a share link into an outbound is a client-side transform
  // (Outbound.fromLink), and outbound.js is only loaded by the Xray Configs page.
  //
  // The bug: an IPv6 literal is bracketed in a URL authority and must not be in the
  // config field, where the address is a bare host. Xray reads "[2001:db8::1]" as a
  // DOMAIN, fails to resolve it, and the outbound is dead with nothing in the log
  // naming the brackets. parseShareLink stripped them (so tuic and naive were fine)
  // while the four schemes going through fromParamLink kept them.
  console.log('\n=== the outbound link parser ===');
  await goto('/panel/xray');
  const parsed = await evalJs(`(() => {
     if (typeof Outbound === 'undefined') return 'outbound.js not loaded';
     const at = (link) => {
       try { const o = Outbound.fromLink(link); return o ? o.settings.address : null; }
       catch (e) { return 'THREW ' + e.message; }
     };
     return {
       anytls6: at('anytls://secret@[2001:db8::1]:443?security=tls&type=tcp#v6'),
       vless6:  at('vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@[2001:db8::1]:443?security=tls&type=tcp#v6'),
       trojan6: at('trojan://pw@[2001:db8::1]:443?security=tls&type=tcp#v6'),
       tuic6:   at('tuic://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:pw@[2001:db8::1]:443?alpn=h3#v6'),
       naive6:  at('naive+https://u:p@[2001:db8::1]:443#v6'),
       anytls4: at('anytls://secret@203.0.113.9:443?security=tls&type=tcp#v4'),
     };
   })()`);
  check('an IPv6 share link imports as a bare address on every scheme',
        parsed && typeof parsed === 'object' &&
          ['anytls6','vless6','trojan6','tuic6','naive6'].every(k => parsed[k] === '2001:db8::1') &&
          parsed.anytls4 === '203.0.113.9',
        JSON.stringify(parsed));

  // The three the user asked about are already routed by fromLink, and each has to
  // land on its own settings class rather than falling through to null.
  const schemes = await evalJs(`(() => {
     if (typeof Outbound === 'undefined') return 'outbound.js not loaded';
     const proto = (link) => {
       try { const o = Outbound.fromLink(link); return o ? o.protocol : null; }
       catch (e) { return 'THREW ' + e.message; }
     };
     return {
       anytls: proto('anytls://secret@203.0.113.9:443?security=tls&type=tcp#a'),
       tuic:   proto('tuic://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:pw@203.0.113.9:443?alpn=h3&congestion_control=bbr#t'),
       naiveH: proto('naive+https://u:p@203.0.113.9:443#n'),
       naiveQ: proto('naive+quic://u:p@203.0.113.9:443#n'),
       junk:   proto('not-a-link'),
     };
   })()`);
  check('anytls, tuic and naive links import as their own outbound',
        schemes && schemes.anytls === 'anytls' && schemes.tuic === 'tuic' &&
          schemes.naiveH === 'naive' && schemes.naiveQ === 'naive' && schemes.junk === null,
        JSON.stringify(schemes));

  // Back to the Clients page. outbound.js is only on the Xray Configs page, but
  // clientMembershipModal is only on this one, and every later check reaches for it.
  await goto('/panel/clients');
  await inject();

  // ------------------------------------------------ Xray-native WireGuard
  // Reported as "we add the inbound but we cannot assign any client to it". Its
  // settings carry peers, not clients, so the picker filtered it out and the accounts
  // layer had nothing to splice into.
  console.log('\n=== Xray-native WireGuard ===');
  const wgEmail = 'uitest-wg@ui';
  await api('/panel/api/inbounds/add', form({
    up: 0, down: 0, total: 0, remark: 'uitest-wireguard', enable: 'true', expiryTime: 0,
    listen: '', port: 34899, protocol: 'wireguard',
    settings: JSON.stringify({ mtu: 1420, secretKey: '', peers: [], noKernelTun: false,
                               clients: [], clientNetwork: '10.99.0.0/24', userLimit: 2,
                               startEmpty: true }),
    streamSettings: JSON.stringify({}),
    sniffing: JSON.stringify({ enabled: false, destOverride: [] }),
    allocate: JSON.stringify({}),
  }));
  const wgList = await api('/panel/api/inbounds/list');
  const wgInbound = ((wgList && wgList.obj) || []).find((ib) => ib.remark === 'uitest-wireguard');
  const assignable = await api('/panel/api/clients/assignable');
  check('a wireguard inbound is offered as somewhere to put an account',
        !!wgInbound && ((assignable && assignable.obj) || []).some((a) => a.inboundId === wgInbound.id),
        JSON.stringify(((assignable && assignable.obj) || []).map((a) => a.protocol)));

  if (wgInbound) {
    // Identity is the email, like wg-c and mtproto: a peer is authorised by its
    // public key, so there is no credential to post and the server mints the key
    // material and the tunnel address per membership.
    await api('/panel/api/inbounds/addClient', form({
      id: wgInbound.id, inboundIds: wgInbound.id,
      settings: JSON.stringify({ clients: [{ email: wgEmail, id: wgEmail, enable: true,
        totalGB: 0, expiryTime: 0, limitIp: 0, subId: '', comment: '', reset: 0, tgId: 0 }] }),
    }));
    const after = await api('/panel/api/inbounds/list');
    const storedWg = ((after && after.obj) || []).find((ib) => ib.id === wgInbound.id);
    let entry = null;
    try {
      entry = (JSON.parse(storedWg.settings).clients || []).find((c) => c.email === wgEmail);
    } catch (e) { /* reported by the check below */ }
    check('the account lands on the wireguard inbound',
          !!entry, storedWg ? String(storedWg.settings).slice(0, 200) : 'no inbound');
    check('and the server minted one keypair and one tunnel address per device slot',
          !!entry && (entry.devices || []).length === 2 && (entry.addresses || []).length === 2 &&
            entry.addresses[0] !== entry.addresses[1] &&
            (entry.devices || []).every((d) => d.privKey && d.pubKey),
          JSON.stringify(entry && { devices: (entry.devices || []).length, addresses: entry.addresses }));

    const cfgs = await api('/panel/api/inbounds/' + wgInbound.id +
                           '/wgxray-configs?email=' + encodeURIComponent(wgEmail));
    const list = (cfgs && cfgs.obj) || [];
    check('and a .conf comes back for each of them',
          list.length === 2 && list.every((c) => /\[Interface\]/.test(c.config) &&
                                                 c.config.includes('Address = ' + c.ip)),
          JSON.stringify(list.map((c) => c.ip)));

    await api('/panel/api/inbounds/del/' + wgInbound.id, '');
  }

  // ------------------------------------------ the field-first form's mapping
  // The form holds ONE set of credentials, the way the account stores them, and
  // maps them onto whichever protocol a write is addressed to. Every protocol
  // must come out with a non-empty identity, and it must be the RIGHT field:
  // the uuid for vmess, the password for trojan, the login name for ssh, the
  // email for the four that are addressed by it.
  const mapped = await evalJs(`(() => {
     const m = clientMembershipModal;
     m.client = { email: 'probe@x', enable: true,
                  id: '11111111-1111-1111-1111-111111111111', password: 'pw',
                  vpnUsername: 'vuser', auth: 'au', secret: 'se', naiveUsername: 'nu' };
     const out = {};
     for (const p of ['vmess','vless','tuic','trojan','shadowsocks','anytls','naive',
                      'hysteria2','l2tp','pptp','openvpn','ikev2','ssh',
                      'wg-c','awg','gre','mtproto']) {
       out[p] = getClientIdentity(p, m.entryFor(p, 'probe@x', 0));
     }
     return out;
   })()`);
  const wantIdentity = {
    vmess: '11111111-1111-1111-1111-111111111111',
    vless: '11111111-1111-1111-1111-111111111111',
    tuic: '11111111-1111-1111-1111-111111111111',
    trojan: 'pw', anytls: 'pw', naive: 'pw', l2tp: 'pw', pptp: 'pw',
    openvpn: 'pw', ikev2: 'pw',
    shadowsocks: 'probe@x',
    hysteria2: 'au',
    ssh: 'vuser',
    'wg-c': 'probe@x', awg: 'probe@x', gre: 'probe@x', mtproto: 'probe@x',
  };
  const wrong = Object.keys(wantIdentity).filter(p => !mapped || mapped[p] !== wantIdentity[p]);
  check('every protocol gets its own identity field out of the one credential set',
        wrong.length === 0, 'wrong: ' + JSON.stringify(wrong.map(p => [p, mapped && mapped[p]])));

  // A 2022-blake3 cipher refuses anything but base64 of its exact key length, and
  // the account has ONE password column, so the generator has to produce the
  // strict shape whenever such an inbound is in the set. Every other protocol
  // takes any string, which is what lets one value serve both.
  const ssKey = await evalJs(`(() => {
     const m = clientMembershipModal;
     const saved = m.assignable, savedSel = m.selected;
     m.assignable = [{ inboundId: 901, protocol: 'shadowsocks', method: '2022-blake3-aes-256-gcm' },
                     { inboundId: 902, protocol: 'shadowsocks', method: '2022-blake3-aes-128-gcm' },
                     { inboundId: 903, protocol: 'trojan' }];
     const probe = (sel) => { m.selected = sel; return { bytes: m.strictSsBytes, pw: m.mint('password') }; };
     const r = { s256: probe([901]), s128: probe([902]), plain: probe([903]) };
     m.assignable = saved; m.selected = savedSel;
     return r;
   })()`);
  const decodes = (v) => { try { return atob(v).length; } catch (e) { return -1; } };
  check('the shared password is generated to fit a shadowsocks-2022 cipher',
        ssKey && ssKey.s256.bytes === 32 && ssKey.s128.bytes === 16
          && decodes(ssKey.s256.pw) === 32 && decodes(ssKey.s128.pw) === 16
          && ssKey.plain.bytes === 0,
        JSON.stringify(ssKey));

  // storedClient serializes through toJson(). Stringifying the instance drops a
  // class getter, and wg-c, awg, gre and mtproto expose `id` as exactly that, so
  // every write built from one arrived with no identity.
  const keepsId = await evalJs(`(() => {
     const bad = [];
     for (const row of app.clients) {
       for (const m of (row.memberships || [])) {
         const stored = app.storedClient(row, m.inboundId);
         if (!stored) continue;
         if (!getClientIdentity(m.protocol, stored)) bad.push(row.email + '@' + m.protocol);
       }
     }
     return { checked: app.clients.length, bad };
   })()`);
  check('storedClient keeps each membership\'s identity field',
        keepsId && keepsId.bad && keepsId.bad.length === 0, JSON.stringify(keepsId));

  // ------------------------------------------------- inbounds has no clients
  console.log('\n=== the Inbounds page holds no clients ===');
  await goto('/panel/inbounds');
  const inb = await evalJs(`(() => ({
     expandIcons: document.querySelectorAll('.ant-table-row-expand-icon').length,
     clientTables: document.querySelectorAll('.bo-client-actions').length,
     rows: document.querySelectorAll('.ant-table-tbody tr').length,
   }))()`);
  check('it still lists inbounds', inb && inb.rows > 0, JSON.stringify(inb));
  check('it has no expandable client rows', inb && inb.expandIcons === 0, JSON.stringify(inb));
  check('it renders no client action table', inb && inb.clientTables === 0, JSON.stringify(inb));

  const menu = await evalJs(`(async () => {
     const t = document.querySelector('.ant-table-tbody tr .ant-dropdown-trigger');
     if (t) t.click();
     await new Promise(r => setTimeout(r, 800));
     return Array.from(document.querySelectorAll('.ant-dropdown-menu-item'))
       .map(i => (i.innerText || '').trim()).filter(Boolean);
   })()`);
  const clientish = (menu || []).filter((t) => /add client|bulk|copy client|reset client|depleted/i.test(t));
  check('and its row menu offers no client entries', clientish.length === 0,
        'offending=' + JSON.stringify(clientish));

  // Reported as its own line rather than folded into the checks above, because the
  // two failure modes need telling apart. A checkbox group that no longer tracks its
  // own clicks is a real page defect; every OTHER assertion here would still pass,
  // because toggleMembership sets the model directly once the click is seen to have
  // been dropped. Without this line that defect is invisible.
  check('the inbound checkboxes track their own clicks',
        membershipClickFallbacks.length === 0,
        'the model had to be set directly for inbound(s) ' +
          JSON.stringify(membershipClickFallbacks));

  await teardown();

  console.log('');
  let bad = 0;
  for (const r of results) {
    console.log(`  [${r.ok ? 'PASS' : 'FAIL'}] ${r.name}${r.ok ? '' : '  <- ' + r.detail}`);
    if (!r.ok) bad++;
  }
  console.log(`\n  ${results.length - bad} passed, ${bad} failed`);
  ws.close();
  process.exit(bad ? 1 : 0);
}

main().catch((e) => {
  console.error('uitest failed to run:', e.message);
  process.exit(2);
});
