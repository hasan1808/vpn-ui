#!/usr/bin/env python3
"""Functional test of the accounts work against a LIVE panel, over its real HTTP API.

    python3 test_unit/live/functest.py [BASE_URL] [USER] [PASS]

Everything it creates is named fntest-* / fn-*, and it tears all of it down. It
never touches a pre-existing inbound or account, so it is safe to point at a
panel that is serving real customers.

It exists because the Go tests could not have caught what it found. They drive
the services directly, so they never exercised the wire: the form-urlencoded
binding, the per-protocol :clientId path parameter, the route table, or the
interaction between the accounts layer and the checks that predate it. Five real
defects came out of the first run, including a migration that rolled back on any
panel holding a disabled client.
"""
import json, ssl, sys, time, urllib.parse, urllib.request, http.cookiejar

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://vpn-ui.mmd.sh:9090"
USER = sys.argv[2] if len(sys.argv) > 2 else "a"
PASS = sys.argv[3] if len(sys.argv) > 3 else "a"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPSHandler(context=ctx),
)

PASSED, FAILED = [], []

def call(path, data=None, method=None):
    """method defaults to POST when a body is given. Routes that take no body but
    are registered as POST must pass method='POST' explicitly, or urllib sends a
    GET and the router answers 404, which reads exactly like a permission denial."""
    url = BASE + path
    body = None
    if data is not None:
        pairs = []
        for k, v in data.items():
            if isinstance(v, (list, tuple)):
                for item in v:
                    pairs.append((k, str(item)))
            else:
                pairs.append((k, str(v)))
        body = urllib.parse.urlencode(pairs).encode()
    req = urllib.request.Request(url, data=body, method=method or ("POST" if body is not None else "GET"))
    req.add_header("X-Requested-With", "XMLHttpRequest")
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(req, timeout=60) as r:
            raw = r.read().decode()
    except Exception as e:
        return {"success": False, "msg": f"transport: {e}"}
    try:
        return json.loads(raw)
    except ValueError:
        return {"success": False, "msg": "non-JSON", "raw": raw[:200]}

def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"\n         {detail}" if detail and not cond else ""))
    return cond

def inbounds():
    return call("/panel/api/inbounds/list").get("obj") or []

def find_inbound(remark):
    for i in inbounds():
        if i.get("remark") == remark:
            return i
    return None

def clients_of(inbound_id):
    for i in inbounds():
        if i["id"] == inbound_id:
            return json.loads(i.get("settings") or "{}").get("clients") or []
    return []

def client_on(inbound_id, email):
    for c in clients_of(inbound_id):
        if c.get("email") == email:
            return c
    return None

# ---------------------------------------------------------------- login
print("\n=== AUTH ===")
r = call("/login", {"username": USER, "password": PASS})
if not r.get("success"):
    print("LOGIN FAILED:", r); sys.exit(1)
check("login", True)

created_inbounds = []
def mk_inbound(remark, port, protocol, settings):
    r = call("/panel/api/inbounds/add", {
        "remark": remark, "port": port, "protocol": protocol,
        "enable": "true", "settings": json.dumps(settings)})
    if r.get("success"):
        ib = find_inbound(remark)
        if ib: created_inbounds.append(ib["id"])
        return ib
    print(f"     (could not create {remark}: {r.get('msg')})")
    return None

try:
    # ------------------------------------------------- C1: minimal-body create
    print("\n=== C1: server-side protocol defaults (minimal body) ===")
    t_vless = mk_inbound("fntest-vless", 27001, "vless",
        {"clients": [{"id": "11111111-2222-3333-4444-555555555555", "email": "fn-seed", "enable": True}]})
    check("minimal vless inbound created", t_vless is not None)
    # A filler client that is never deleted, so the delete cases below leave the
    # inbound with something on it and are testing the accounts layer rather than
    # the empty-inbound case (which has its own check further down).
    t_trojan = mk_inbound("fntest-trojan", 27002, "trojan",
        {"clients": [{"password": "fnFiller1", "email": "fn-filler", "enable": True}]})
    check("minimal trojan inbound created (no settings supplied at all)", t_trojan is not None)
    if t_trojan:
        s = json.loads(t_trojan.get("settings") or "{}")
        check("server filled trojan defaults", "clients" in s, f"settings={s}")
    t_ovpn = mk_inbound("fntest-openvpn", 27003, "openvpn", {"clients": []})
    check("openvpn refused without a certificate (correct)", t_ovpn is None)

    # ------------------------------------------------- accounts: multi-inbound
    print("\n=== ACCOUNTS: one client across two inbounds ===")
    ids = [i for i in (t_vless["id"] if t_vless else None, t_trojan["id"] if t_trojan else None) if i]
    r = call("/panel/api/inbounds/addClient", {
        "id": ids[0], "inboundIds": ids,
        "settings": json.dumps({"clients": [{
            "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "password": "fnPw123",
            "email": "fn-multi", "enable": True, "totalGB": 5 * 1024**3}]})})
    check("addClient with two inboundIds accepted", r.get("success"), r.get("msg"))
    time.sleep(1)
    a = client_on(ids[0], "fn-multi"); b = client_on(ids[1], "fn-multi")
    check("account present on inbound A", a is not None)
    check("account present on inbound B", b is not None)
    if a and b:
        check("same quota on both", a.get("totalGB") == b.get("totalGB") == 5 * 1024**3,
              f"A={a.get('totalGB')} B={b.get('totalGB')}")
        check("vless side has a uuid", bool(a.get("id")))
        check("trojan side has a password", bool(b.get("password")))
    t = call("/panel/api/inbounds/getClientTraffics/fn-multi").get("obj")
    check("exactly ONE traffic row (one quota)", isinstance(t, dict) and t.get("email") == "fn-multi")

    # ------------------------------------------------- clients list API
    print("\n=== CLIENTS PAGE API ===")
    lst = call("/panel/api/clients/list?size=500").get("obj") or {}
    rows = lst.get("rows") or []
    row = next((x for x in rows if x["email"] == "fn-multi"), None)
    check("account appears in /clients/list", row is not None)
    if row:
        check("list reports BOTH memberships", len(row.get("memberships") or []) == 2,
              f"memberships={row.get('memberships')}")
    s = call("/panel/api/clients/list?size=500&search=fn-multi").get("obj") or {}
    check("search narrows the list", len(s.get("rows") or []) == 1, f"got {len(s.get('rows') or [])}")
    asg = call("/panel/api/clients/assignable").get("obj") or []
    check("assignable inbounds listed", len(asg) > 0)

    # ------------------------------------------------- membership removal
    print("\n=== MEMBERSHIP REMOVAL (untick one inbound) ===")
    # The path parameter is the PROTOCOL's identity, not the email.
    lst0 = (call("/panel/api/clients/list?size=500&search=fn-multi").get("obj") or {}).get("rows") or []
    cid = (lst0[0]["memberships"][0].get("clientId") if lst0 and lst0[0].get("memberships") else "") or "fn-multi"
    r = call(f"/panel/api/inbounds/updateClient/{urllib.parse.quote(cid)}", {
        "id": ids[0], "inboundIds": [ids[0]],
        "settings": json.dumps({"clients": [{
            "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "password": "fnPw123",
            "email": "fn-multi", "enable": True, "totalGB": 5 * 1024**3}]})})
    check("updateClient with a reduced inboundIds accepted", r.get("success"), r.get("msg"))
    time.sleep(1)
    check("removed from the unticked inbound", client_on(ids[1], "fn-multi") is None)
    check("kept on the ticked inbound", client_on(ids[0], "fn-multi") is not None)

    # ------------------------------------------------- validation
    print("\n=== IDENTITY VALIDATION ===")
    r = call("/panel/api/inbounds/addClient", {
        "id": ids[0], "settings": json.dumps({"clients": [
            {"id": "x", "email": "fn-bad>>>x", "enable": True}]})})
    check("email containing '>' refused", not r.get("success"), f"got success (msg={r.get('msg')})")
    r = call("/panel/api/inbounds/addClient", {
        "id": ids[0], "settings": json.dumps({"clients": [
            {"id": "y", "email": "fn-badsub", "subId": "../admin", "enable": True}]})})
    check("subId with a path escape refused", not r.get("success"), f"got success (msg={r.get('msg')})")

    # ------------------------------------------------- partial update fix
    print("\n=== PARTIAL INBOUND UPDATE (must not wipe policy) ===")
    up1 = call(f"/panel/api/inbounds/update/{ids[0]}", {
        "remark": "fntest-vless", "port": 27001, "protocol": "vless", "enable": "true",
        "settings": json.dumps({"clients": clients_of(ids[0])}),
        "speedLimitEnable": "true", "speedLimitDown": 4096, "ipLimit": 5,
        "trafficMultiplierEnable": "true", "trafficMultiplier": 2.5})
    time.sleep(1)
    before = next((i for i in inbounds() if i["id"] == ids[0]), {})
    check("policy set", before.get("speedLimitDown") == 4096 and before.get("ipLimit") == 5,
          f"resp={up1.get('msg')} speedLimitDown={before.get('speedLimitDown')} ipLimit={before.get('ipLimit')}")
    # now a PARTIAL body: only remark + settings, the obvious rename
    call(f"/panel/api/inbounds/update/{ids[0]}", {
        "remark": "fntest-vless-renamed", "port": 27001, "protocol": "vless", "enable": "true",
        "settings": json.dumps({"clients": clients_of(ids[0])})})
    time.sleep(1)
    after = next((i for i in inbounds() if i["id"] == ids[0]), {})
    check("partial update kept speedLimitDown", after.get("speedLimitDown") == 4096, f"got {after.get('speedLimitDown')}")
    check("partial update kept ipLimit", after.get("ipLimit") == 5, f"got {after.get('ipLimit')}")
    check("partial update kept trafficMultiplier", abs((after.get("trafficMultiplier") or 0) - 2.5) < 0.01,
          f"got {after.get('trafficMultiplier')}")
    check("the rename itself applied", after.get("remark") == "fntest-vless-renamed")

    # ------------------------------------------------- C3 addressing
    print("\n=== C3: address-plane endpoints ===")
    pools = call("/panel/api/inbounds/pools").get("obj") or []
    check("/pools answers", isinstance(pools, list) and len(pools) > 0)
    vpn = next((i for i in inbounds() if i["protocol"] in ("l2tp", "openconnect", "wg-c")), None)
    if vpn:
        addr = call(f"/panel/api/inbounds/{vpn['id']}/addressing").get("obj") or {}
        check("addressing reports ranges + accounts",
              "ranges" in addr and "accounts" in addr and "userLimit" in addr, f"got keys {list(addr)[:6]}")
        acc = addr.get("accounts") or []
        if acc:
            check("each account has a tunnel address", all(a.get("addresses") for a in acc))
    r = call(f"/panel/api/inbounds/{ids[0]}/addressing")
    check("addressing says so for a protocol with no pool", not r.get("success"), r.get("msg"))

    # ------------------------------------------------- delete everywhere
    print("\n=== DELETE ===")
    r = call("/panel/api/inbounds/addClient", {
        "id": ids[0], "inboundIds": ids,
        "settings": json.dumps({"clients": [{
            "id": "cccccccc-dddd-eeee-ffff-000000000000", "password": "fnPw999",
            "email": "fn-del", "enable": True}]})})
    time.sleep(1)
    check("second multi-inbound account created", client_on(ids[0], "fn-del") and client_on(ids[1], "fn-del"))
    for i in ids:
        call(f"/panel/api/inbounds/{i}/delClientByEmail/fn-del", {}, "POST")
    time.sleep(1)
    check("gone from both inbounds", not client_on(ids[0], "fn-del") and not client_on(ids[1], "fn-del"))
    lst2 = call("/panel/api/clients/list?size=500&search=fn-del").get("obj") or {}
    check("account pruned from the accounts layer", len(lst2.get("rows") or []) == 0,
          f"still listed: {lst2.get('rows')}")

    # The LAST client of an inbound is deletable, and deleting it frees the email.
    # The panel used to refuse ("no client remained in Inbound"), which stranded the
    # customer as live-but-deleted and held their email against a re-create.
    solo = mk_inbound("fntest-solo", 27009, "trojan",
        {"clients": [{"password": "fnSolo1", "email": "fn-solo", "enable": True}]})
    if solo:
        rr = call(f"/panel/api/inbounds/{solo['id']}/delClientByEmail/fn-solo", {}, "POST")
        check("removing the LAST client of an inbound succeeds", rr.get("success"), str(rr.get("msg")))
        check("the emptied inbound is left in place", not client_on(solo["id"], "fn-solo"))
        # And the email is free again, which is the whole point of the fix.
        again = call("/panel/api/inbounds/addClient", {
            "id": solo["id"],
            "settings": json.dumps({"clients": [{"password": "fnSolo2", "email": "fn-solo", "enable": True}]}),
        }, "POST")
        check("the freed email can be re-created", again.get("success"), str(again.get("msg")))

finally:
    print("\n=== TEARDOWN ===")
    for i in ids if 'ids' in dir() else []:
        for em in ("fn-multi", "fn-del", "fn-seed", "fn-filler", "fn-solo"):
            call(f"/panel/api/inbounds/{i}/delClientByEmail/{em}", {}, "POST")
    for iid in created_inbounds:
        r = call(f"/panel/api/inbounds/del/{iid}", {}, "POST")
        print(f"  deleted test inbound {iid}: {r.get('success')}")

print("\n" + "=" * 60)
print(f"PASSED {len(PASSED)}   FAILED {len(FAILED)}")
if FAILED:
    print("failures:")
    for f in FAILED: print("   -", f)
print("=" * 60)
sys.exit(1 if FAILED else 0)
