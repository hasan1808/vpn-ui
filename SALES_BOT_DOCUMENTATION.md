# راهنمای جامع ربات فروش VPN (PHP)

## فهرست مطالب

1. [نمای کلی](#1-نمای-کلی)
2. [ساختار پروژه](#2-ساختار-پروژه)
3. [اتصال به پنل (Authentication)](#3-اتصال-به-پنل)
4. [مدیریت اکانت‌ها](#4-مدیریت-اکانت‌ها)
5. [مشاهده وضعیت سرور](#5-مشاهده-وضعیت-سرور)
6. [مدیریت Inboundها](#6-مدیریت-این‌بانت‌ها)
7. [سیستم اشتراک (Subscription)](#7-سیستم-اشتراک)
8. [镨توکل‌ها و تنظیمات](#8-پروتوکل‌ها)
9. [ساختار دیتابیس](#9-ساختار-دیتابیس)
10. [نمونه کد PHP](#10-نمونه-کد)
11. [مدیریت خطاها](#11-مدیریت-خطاها)

---

## 1. نمای کلی

ربات فروش یک اپلیکیشن PHP است که از طریق HTTP API با پنل PRO-UI ارتباط برقرار می‌کند. این ربات قابلیت‌های زیر را ارائه می‌دهد:

- **فروش خودکار اکانت VPN** (ایجاد، تمدید، غیرفعال‌سازی)
- **مشاهده وضعیت اکانت‌ها** (ترافیک، انقضا، آنلاین/آفلاین)
- **اتصال به درگاه پرداخت** (اختیاری)
- **پشتیبانی کاربران** از طریق ربات تلگرام
- **مدیریت پلن‌ها و قیمت‌ها**

---

## 2. ساختار پروژه

```
vpn-sales-bot/
├── config/
│   └── config.php              # تنظیمات اتصال به پنل
├── src/
│   ├── Api/
│   │   ├── PanelClient.php     # کلاینت اصلی API پنل
│   │   ├── Auth.php            # مدیریت احراز هویت
│   │   └── Exception.php       # کلاس‌های خطا
│   ├── Bot/
│   │   ├── TelegramBot.php     # ربات تلگرام
│   │   ├── Commands.php        # دستورات ربات
│   │   └── Keyboards.php       # کیبوردهای تلگرام
│   ├── Models/
│   │   ├── Account.php         # مدل اکانت
│   │   ├── Plan.php            # مدل پلن فروش
│   │   ├── Order.php           # مدل سفارش
│   │   └── Inbound.php         # مدل این‌بانت
│   ├── Services/
│   │   ├── AccountService.php  # سرویس مدیریت اکانت
│   │   ├── PlanService.php     # سرویس مدیریت پلن‌ها
│   │   ├── OrderService.php    # سرویس مدیریت سفارشات
│   │   └── PaymentService.php  # سرویس پرداخت
│   └── Utils/
│       ├── Logger.php          # لاگر
│       └── Helpers.php         # توابع کمکی
├── database/
│   └── schema.sql              # ساختار دیتابیس ربات
├── public/
│   └── index.php               # نقطه ورود
├── composer.json
└── README.md
```

---

## 3. اتصال به پنل (Authentication)

### 3.1 نکات حیاتی احراز هویت

پنل PRO-UI از **Session Cookie** برای احراز هویت استفاده می‌کند. **هیچ API Key وجود ندارد.**

```php
// 1. لاگین کنید و کوکی را ذخیره کنید
POST /<basePath>/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret
// اختیاری: twoFactorCode=123456

// 2. درخواست‌های بعدی با کوکی ارسال شود
GET /<basePath>/panel/api/inbounds/list
Cookie: vpn-ui=<session-cookie>
```

### 3.2 نکات مهم

| موضوع | توضیح |
|--------|--------|
| **نام کوکی** | `vpn-ui` |
| **نوع کوکی** | Signed (رمزگذاری نشده) - فقط `admin_id` ذخیره می‌شود |
| **نوع درخواست‌ها** | همه POSTها `application/x-www-form-urlencoded` هستند (نه JSON) |
| **پاسخ خطا** | HTTP 200 با `{"success": false, "msg": "..."}` (نه 403) |
| **عدم احراز هویت** | در `checkAPIAuth` -> 404 (نه 401) |
| **Header الزامی** | `X-Requested-With: XMLHttpRequest` برای دریافت خطای JSON |

### 3.3 نمونه کد اتصال

```php
class PanelClient {
    private string $baseUrl;
    private string $cookieFile;
    private string $basePath;

    public function __construct(string $host, int $port, string $basePath) {
        $this->basePath = rtrim($basePath, '/');
        $this->baseUrl = "https://{$host}:{$port}/{$this->basePath}";
        $this->cookieFile = tempnam(sys_get_temp_dir(), 'vpn_panel_');
    }

    public function login(string $username, string $password): bool {
        $ch = curl_init("{$this->baseUrl}/login");

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'username' => $username,
                'password' => $password,
            ]),
            CURLOPT_COOKIEJAR => $this->cookieFile,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false, // در production فعال کنید
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        $data = json_decode($response, true);
        return $data['success'] ?? false;
    }

    public function request(string $method, string $endpoint, array $data = []): array {
        $ch = curl_init("{$this->baseUrl}/{$endpoint}");

        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIEFILE => $this->cookieFile,
            CURLOPT_HTTPHEADER => [
                'X-Requested-With: XMLHttpRequest',
            ],
            CURLOPT_SSL_VERIFYPEER => false,
        ];

        if ($method === 'POST') {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = http_build_query($data);
        }

        curl_setopt_array($ch, $options);

        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response, true) ?? ['success' => false, 'msg' => 'Invalid response'];
    }
}
```

---

## 4. مدیریت اکانت‌ها

### 4.1 ایجاد اکانت جدید

**مهم:** هر پروتوکل ساختار Settings متفاوتی دارد. ابتدا پروتوکل مورد نظر را بشناسید.

```
POST /<basePath>/panel/api/inbounds/addClient
Content-Type: application/x-www-form-urlencoded

id=<inbound_id>&settings=<JSON_string>&inboundIds=<id1>&inboundIds=<id2>
```

**ساختار Settings برای VLESS:**
```json
{
    "clients": [{
        "id": "<uuid>",
        "flow": "",
        "email": "user@example.com",
        "enable": true,
        "limitIp": 0,
        "totalGB": 1073741824,
        "expiryTime": 0,
        "tgId": 0,
        "subId": "usersub",
        "comment": "",
        "reset": 0
    }]
}
```

**ساختار Settings برای Trojan:**
```json
{
    "clients": [{
        "password": "securePassword123",
        "email": "user@example.com",
        "enable": true,
        "limitIp": 0,
        "totalGB": 1073741824,
        "expiryTime": 0,
        "tgId": 0,
        "subId": "usersub",
        "comment": "",
        "reset": 0
    }]
}
```

**ساختار Settings برای VMess:**
```json
{
    "clients": [{
        "id": "<uuid>",
        "security": "auto",
        "email": "user@example.com",
        "enable": true,
        "limitIp": 0,
        "totalGB": 1073741824,
        "expiryTime": 0,
        "tgId": 0,
        "subId": "usersub",
        "comment": "",
        "reset": 0
    }]
}
```

**ساختار Settings برای Shadowsocks:**
```json
{
    "method": "2022-blake3-aes-256-gcm",
    "password": "<server_password_base64>",
    "network": "tcp,udp",
    "ivCheck": false,
    "clients": [{
        "method": "",
        "password": "<client_password_base64>",
        "email": "user@example.com",
        "enable": true,
        "limitIp": 0,
        "totalGB": 1073741824,
        "expiryTime": 0,
        "tgId": 0,
        "subId": "usersub",
        "comment": "",
        "reset": 0
    }]
}
```

**ساختار Settings برای L2TP:**
```json
{
    "ipsecEnable": true,
    "ipsecPsk": "sharedsecret1234",
    "clients": [{
        "id": "username",
        "password": "userPassword",
        "email": "user@example.com",
        "enable": true,
        "limitIp": 0,
        "totalGB": 1073741824,
        "expiryTime": 0,
        "tgId": 0,
        "subId": "usersub",
        "comment": "",
        "reset": 0
    }]
}
```

**ساختار Settings برای WireGuard (wg-c):**
```json
{
    "clients": [{
        "id": "user@example.com",
        "email": "user@example.com",
        "enable": true,
        "limitIp": 0,
        "totalGB": 1073741824,
        "expiryTime": 0,
        "tgId": 0,
        "subId": "usersub",
        "comment": "",
        "reset": 0
    }]
}
```

### 4.2 ویرایش اکانت

```
POST /<basePath>/panel/api/inbounds/updateClient/:clientId
Content-Type: application/x-www-form-urlencoded

id=<inbound_id>&settings=<JSON_string>
```

**نکته:** `:clientId` بسته به پروتوکل متفاوت است:
- VLESS/VMess/TUIC: UUID اکانت
- Trojan/L2TP/PPTP/OpenVPN/SSTP/IKEv2: رمز عبور
- Shadowsocks: ایمیل
- Hysteria: auth password
- SSH: نام کاربری
- WireGuard/AmneziaWG/GRE/MTProto: ایمیل

### 4.3 حذف اکانت

```
POST /<basePath>/panel/api/inbounds/:inboundId/delClientByEmail/:email
```

### 4.4 دریافت لیست اکانت‌ها

```
GET /<basePath>/panel/api/inbounds/list
```

**پاسخ:**
```json
{
    "success": true,
    "obj": [
        {
            "id": 1,
            "remark": "vless-main",
            "protocol": "vless",
            "port": 10001,
            "enable": true,
            "clientStats": [
                {
                    "email": "user@example.com",
                    "up": 1024000,
                    "down": 5120000,
                    "total": 1073741824,
                    "expiryTime": 0,
                    "enable": true,
                    "lastOnline": 1690000000000
                }
            ]
        }
    ]
}
```

### 4.5 دریافت ترافیک یک اکانت

```
GET /<basePath>/panel/api/inbounds/getClientTraffics/:email
```

---

## 5. مشاهده وضعیت سرور

### 5.1 وضعیت کلی سرور

```
POST /<basePath>/panel/server/status
X-Requested-With: XMLHttpRequest
```

### 5.2 آمار کاربران

```
GET /<basePath>/panel/server/userStats
```

### 5.3 کنترل Xray

```
POST /<basePath>/panel/server/restartXrayService
POST /<basePath>/panel/server/stopXrayService
```

---

## 6. مدیریت این‌بانت‌ها

### 6.1 لیست این‌بانت‌ها

```
GET /<basePath>/panel/api/inbounds/list
```

### 6.2 ایجاد این‌بانت جدید

```
POST /<basePath>/panel/api/inbounds/add
Content-Type: application/x-www-form-urlencoded

remark=vless-main&enable=true&port=10001&protocol=vless&settings=<JSON>&streamSettings=<JSON>&sniffing=<JSON>
```

### 6.3 ویرایش این‌بانت

```
POST /<basePath>/panel/api/inbounds/update/:id
Content-Type: application/x-www-form-urlencoded

remark=new-name&settings=<JSON>
```

**نکته مهم:** ویرایش جزئی ایمن است - فیلدهایی که ارسال نشوند، تغییر نمی‌کنند.

### 6.4 حذف این‌بانت

```
POST /<basePath>/panel/api/inbounds/del/:id
```

### 6.5 ریست ترافیک

```
POST /<basePath>/panel/api/inbounds/resetClientTraffic/:email?id=<inbound_id>
POST /<basePath>/panel/api/inbounds/resetAllClientTraffics/:id
```

---

## 7. سیستم اشتراک

### 7.1 لینک اشتراک

هر اکانت یک `subId` دارد که لینک اشتراک آن است:

```
GET https://<panel-host>:<port>/<basePath>/sub/<subId>
```

### 7.2 فرمت‌های خروجی

| فرمت | مسیر | توضیح |
|--------|--------|--------|
| لینک‌ها | `/sub/<subId>` | لینک‌های اتصال برای همه پروتوکل‌ها |
| JSON | `/sub/json/<subId>` | برای v2rayN و مشابه |
| Clash | `/sub/clash/<subId>` | برای Clash/Mihomo |

### 7.3 دانلود کانفیگ

```
GET /<basePath>/sub/<subId>/configs/<key>
```

پروتوکل‌های پشتیبانی شده:
- OpenVPN: `.ovpn`
- WireGuard: `.conf`
- AmneziaWG: `.conf`
- SSH: لینک‌ها و singbox config

---

## 8. پروتوکل‌ها

### 8.1 پروتوکل‌های پشتیبانی شده

| پروتوکل | نوع | نیاز به TLS | نیاز به گواهی |
|-----------|------|--------------|----------------|
| vmess | Xray-native | اختیاری | خیر |
| vless | Xray-native | اختیاری | خیر |
| trojan | Xray-native | بله | خیر |
| shadowsocks | Xray-native | خیر | خیر |
| hysteria | Xray-native | بله | خیر |
| anytls | Xray-native | بله | خیر |
| tuic | Xray-native | بله | خیر |
| naive | Xray-native | بله | خیر |
| l2tp | VPN | خیر | خیر |
| pptp | VPN | خیر | خیر |
| openvpn | VPN | اختیاری | بله |
| openconnect | VPN | بله | بله |
| sstp | VPN | بله | بله |
| ikev2 | VPN | بله | بله |
| wg-c | VPN | خیر | خیر |
| awg | VPN | خیر | خیر |
| gre | VPN | خیر | خیر |
| mtproto | Relay | خیر | خیر |
| ssh | Relay | خیر | خیر |

### 8.2 نکات مهم پروتوکل‌ها

1. **totalGB بر حسب بایت است** (نه گیگابایت!)
   - 1 گیگابایت = 1073741824 بایت
   - 10 گیگابایت = 10737418240 بایت

2. **expiryTime بر حسب میلی‌ثانیه Unix است**
   - منفی = تاخیر شروع (مدت زمان از اولین اتصال)
   - 0 = بدون انقضا

3. **enable=true را همیشه ارسال کنید** - بدون آن اکانت غیرفعال ایجاد می‌شود

4. **ایمیل باید یکتا باشد** - در تمام پنل

5. **subId نباید شامل کاراکترهای خاص باشد:** `/ \ ? # %`

---

## 9. ساختار دیتابیس

### 9.1 جداول اصلی پنل

```sql
-- کاربران (ادمین‌ها)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- Bcrypt hash
    nickname TEXT,
    is_super_admin BOOLEAN DEFAULT 0,
    permissions INTEGER DEFAULT 0,
    is_reseller BOOLEAN DEFAULT 0,
    enable BOOLEAN DEFAULT 1,
    two_factor_enable BOOLEAN DEFAULT 0,
    two_factor_token TEXT
);

-- این‌بانت‌ها (سرویس‌ها)
CREATE TABLE inbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    up INTEGER DEFAULT 0,
    down INTEGER DEFAULT 0,
    total INTEGER DEFAULT 0,
    all_time INTEGER DEFAULT 0,
    remark TEXT,
    enable BOOLEAN,
    expiry_time INTEGER DEFAULT 0,
    traffic_reset TEXT DEFAULT 'never',
    port INTEGER,
    protocol TEXT,
    settings TEXT,  -- JSON
    stream_settings TEXT,  -- JSON
    tag TEXT UNIQUE,
    sniffing TEXT  -- JSON
);

-- اکانت‌ها
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    sub_id TEXT,
    uuid TEXT,          -- vmess/vless/tuic
    vpn_username TEXT,  -- l2tp/pptp/openvpn/openconnect/sstp/ikev2/ssh
    password TEXT,      -- trojan/shadowsocks/anytls + credential VPNs
    auth TEXT,          -- hysteria
    security TEXT,      -- vmess
    secret TEXT,        -- mtproto
    naive_username TEXT, -- naive
    total_gb INTEGER DEFAULT 0,
    expiry_time INTEGER DEFAULT 0,
    enable BOOLEAN DEFAULT 1,
    reset INTEGER DEFAULT 0,
    limit_ip INTEGER DEFAULT 0,
    tg_id INTEGER DEFAULT 0,
    comment TEXT,
    created_at INTEGER,
    updated_at INTEGER
);

-- عضویت اکانت در این‌بانت‌ها
CREATE TABLE account_inbounds (
    account_id INTEGER,
    inbound_id INTEGER,
    slot INTEGER,
    flow TEXT,
    enable BOOLEAN,
    extra TEXT,
    created_at INTEGER,
    PRIMARY KEY (account_id, inbound_id)
);

-- ترافیک کلاینت‌ها
CREATE TABLE client_traffics (
    email TEXT UNIQUE,
    inbound_id INTEGER,
    up INTEGER DEFAULT 0,
    down INTEGER DEFAULT 0,
    all_time INTEGER DEFAULT 0,
    total INTEGER DEFAULT 0,
    expiry_time INTEGER DEFAULT 0,
    enable BOOLEAN DEFAULT 1,
    reset INTEGER DEFAULT 0,
    last_online INTEGER DEFAULT 0
);
```

### 9.2 جداول ربات فروش

```sql
-- پلن‌های فروش
CREATE TABLE plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    inbound_id INTEGER NOT NULL,
    duration_days INTEGER NOT NULL,
    traffic_gb INTEGER NOT NULL,
    price INTEGER NOT NULL,  -- به تومان
    currency TEXT DEFAULT 'IRR',
    enable BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- سفارشات
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL,  -- Telegram user ID
    plan_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    status TEXT DEFAULT 'pending',  -- pending, paid, active, expired
    payment_id TEXT,
    amount INTEGER NOT NULL,
    paid_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES plans(id)
);

-- کاربران ربات
CREATE TABLE bot_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id BIGINT UNIQUE NOT NULL,
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    phone TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP
);
```

---

## 10. نمونه کد

### 10.1 کلاس اصلی PanelClient

```php
<?php

class PanelClient {
    private string $baseUrl;
    private string $cookieFile;
    private bool $loggedIn = false;

    public function __construct(
        private string $host,
        private int $port,
        private string $basePath,
        private string $username,
        private string $password
    ) {
        $this->basePath = rtrim($basePath, '/');
        $this->baseUrl = "https://{$host}:{$port}/{$this->basePath}";
        $this->cookieFile = tempnam(sys_get_temp_dir(), 'vpn_');
    }

    public function login(): bool {
        $ch = curl_init("{$this->baseUrl}/login");

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'username' => $this->username,
                'password' => $this->password,
            ]),
            CURLOPT_COOKIEJAR => $this->cookieFile,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $data = json_decode($response, true);
        $this->loggedIn = $data['success'] ?? false;

        return $this->loggedIn;
    }

    public function get(string $endpoint): array {
        return $this->request('GET', $endpoint);
    }

    public function post(string $endpoint, array $data = []): array {
        return $this->request('POST', $endpoint, $data);
    }

    private function request(string $method, string $endpoint, array $data = []): array {
        if (!$this->loggedIn) {
            throw new \RuntimeException('Not logged in. Call login() first.');
        }

        $ch = curl_init("{$this->baseUrl}/{$endpoint}");

        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIEFILE => $this->cookieFile,
            CURLOPT_HTTPHEADER => [
                'X-Requested-With: XMLHttpRequest',
            ],
            CURLOPT_SSL_VERIFYPEER => false,
        ];

        if ($method === 'POST') {
            $options[CURLOPT_POST] = true;
            if (!empty($data)) {
                $options[CURLOPT_POSTFIELDS] = http_build_query($data);
            }
        }

        curl_setopt_array($ch, $options);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $result = json_decode($response, true);

        if ($result === null) {
            throw new \RuntimeException("Invalid JSON response: {$response}");
        }

        return $result;
    }

    public function __destruct() {
        if (file_exists($this->cookieFile)) {
            @unlink($this->cookieFile);
        }
    }
}
```

### 10.2 سرویس مدیریت اکانت

```php
<?php

class AccountService {
    private PanelClient $client;

    public function __construct(PanelClient $client) {
        $this->client = $client;
    }

    /**
     * ایجاد اکانت جدید
     */
    public function create(array $params): array {
        $inboundId = $params['inbound_id'];
        $email = $params['email'];
        $protocol = $params['protocol'];

        // ساخت تنظیمات بر اساس پروتوکل
        $settings = $this->buildSettings($protocol, $params);

        $data = [
            'id' => $inboundId,
            'settings' => json_encode($settings),
        ];

        // اضافه کردن inboundIds اختیاری
        if (!empty($params['inbound_ids'])) {
            foreach ($params['inbound_ids'] as $id) {
                $data['inboundIds'][] = $id;
            }
        }

        $result = $this->client->post('panel/api/inbounds/addClient', $data);

        if (!$result['success']) {
            throw new \RuntimeException("Failed to create account: {$result['msg']}");
        }

        return $result;
    }

    /**
     * ساخت تنظیمات بر اساس پروتوکل
     */
    private function buildSettings(string $protocol, array $params): array {
        $email = $params['email'];
        $totalGB = $this->gbToBytes($params['traffic_gb'] ?? 0);
        $expiryTime = $this->calculateExpiry($params['duration_days'] ?? 0);

        $client = [
            'email' => $email,
            'enable' => true,
            'limitIp' => $params['limit_ip'] ?? 0,
            'totalGB' => $totalGB,
            'expiryTime' => $expiryTime,
            'tgId' => $params['tg_id'] ?? 0,
            'subId' => $params['sub_id'] ?? $this->generateSubId(),
            'comment' => $params['comment'] ?? '',
            'reset' => $params['reset'] ?? 0,
        ];

        switch ($protocol) {
            case 'vless':
                $client['id'] = $params['uuid'] ?? $this->generateUUID();
                $client['flow'] = $params['flow'] ?? '';
                return ['clients' => [$client]];

            case 'vmess':
                $client['id'] = $params['uuid'] ?? $this->generateUUID();
                $client['security'] = $params['security'] ?? 'auto';
                return ['clients' => [$client]];

            case 'trojan':
                $client['password'] = $params['password'] ?? $this->generatePassword(16);
                return ['clients' => [$client]];

            case 'shadowsocks':
                $client['method'] = $params['method'] ?? '';
                $client['password'] = $params['password'] ?? $this->generatePassword(32);
                return [
                    'method' => $params['inbound_method'] ?? '2022-blake3-aes-256-gcm',
                    'password' => $params['inbound_password'] ?? '',
                    'network' => 'tcp,udp',
                    'ivCheck' => false,
                    'clients' => [$client],
                ];

            case 'l2tp':
                $client['id'] = $params['vpn_username'] ?? $this->generateUsername();
                $client['password'] = $params['password'] ?? $this->generatePassword(12);
                return [
                    'ipsecEnable' => true,
                    'ipsecPsk' => $params['ipsec_psk'] ?? $this->generatePassword(16),
                    'clients' => [$client],
                ];

            case 'wg-c':
                $client['id'] = $email;
                return ['clients' => [$client]];

            default:
                throw new \InvalidArgumentException("Unsupported protocol: {$protocol}");
        }
    }

    /**
     * تبدیل گیگابایت به بایت
     */
    private function gbToBytes(int $gb): int {
        return $gb * 1024 * 1024 * 1024;
    }

    /**
     * محاسبه زمان انقضا
     */
    private function calculateExpiry(int $days): int {
        if ($days <= 0) {
            return 0;
        }
        return (time() + ($days * 86400)) * 1000; // میلی‌ثانیه
    }

    /**
     * تولید UUID
     */
    private function generateUUID(): string {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    /**
     * تولید رمز عبور
     */
    private function generatePassword(int $length = 16): string {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        return substr(str_shuffle(str_repeat($chars, ceil($length / strlen($chars)))), 0, $length);
    }

    /**
     * تولید نام کاربری
     */
    private function generateUsername(): string {
        return 'vpn_' . bin2hex(random_bytes(4));
    }

    /**
     * تولید subId
     */
    private function generateSubId(): string {
        return bin2hex(random_bytes(16));
    }

    /**
     * حذف اکانت
     */
    public function delete(int $inboundId, string $email): bool {
        $result = $this->client->post(
            "panel/api/inbounds/{$inboundId}/delClientByEmail/{$email}"
        );
        return $result['success'] ?? false;
    }

    /**
     * ویرایش اکانت
     */
    public function update(int $inboundId, string $clientId, array $params): array {
        $protocol = $params['protocol'];
        $settings = $this->buildSettings($protocol, $params);

        $result = $this->client->post(
            "panel/api/inbounds/updateClient/{$clientId}",
            [
                'id' => $inboundId,
                'settings' => json_encode($settings),
            ]
        );

        if (!$result['success']) {
            throw new \RuntimeException("Failed to update account: {$result['msg']}");
        }

        return $result;
    }

    /**
     * دریافت لیست اکانت‌ها
     */
    public function list(): array {
        $result = $this->client->get('panel/api/inbounds/list');

        if (!$result['success']) {
            throw new \RuntimeException("Failed to list inbounds: {$result['msg']}");
        }

        return $result['obj'] ?? [];
    }

    /**
     * دریافت ترافیک یک اکانت
     */
    public function getTraffic(string $email): array {
        $result = $this->client->get("panel/api/inbounds/getClientTraffics/{$email}");

        if (!$result['success']) {
            throw new \RuntimeException("Failed to get traffic: {$result['msg']}");
        }

        return $result['obj'] ?? [];
    }

    /**
     * ریست ترافیک
     */
    public function resetTraffic(string $email, int $inboundId): bool {
        $result = $this->client->post(
            "panel/api/inbounds/resetClientTraffic/{$email}",
            ['id' => $inboundId]
        );
        return $result['success'] ?? false;
    }
}
```

### 10.3 ربات تلگرام (ساده)

```php
<?php

class TelegramBot {
    private string $token;
    private string $apiUrl;
    private PanelClient $panelClient;
    private AccountService $accountService;

    public function __construct(string $token, PanelClient $panelClient) {
        $this->token = $token;
        $this->apiUrl = "https://api.telegram.org/bot{$token}";
        $this->panelClient = $panelClient;
        $this->accountService = new AccountService($panelClient);
    }

    public function handleUpdate(array $update): void {
        if (isset($update['message'])) {
            $this->handleMessage($update['message']);
        } elseif (isset($update['callback_query'])) {
            $this->handleCallbackQuery($update['callback_query']);
        }
    }

    private function handleMessage(array $message): void {
        $chatId = $message['chat']['id'];
        $text = $message['text'] ?? '';

        switch (true) {
            case $text === '/start':
                $this->sendWelcome($chatId);
                break;
            case $text === '/plans':
                $this->sendPlans($chatId);
                break;
            case $text === '/myaccount':
                $this->sendMyAccount($chatId);
                break;
            case str_starts_with($text, '/buy '):
                $planId = substr($text, 5);
                $this->startPurchase($chatId, (int)$planId);
                break;
            default:
                $this->sendMessage($chatId, "دستور ناشناخته. از /start استفاده کنید.");
        }
    }

    private function sendWelcome(int $chatId): void {
        $text = "🔐 *به ربات فروش VPN خوش آمدید*\n\n"
            . "📋 برای مشاهده پلن‌ها: /plans\n"
            . "👤 اطلاعات اکانت: /myaccount\n"
            . "💰 خرید اشتراک: /buy [شماره پلن]";

        $this->sendMessage($chatId, $text, 'Markdown');
    }

    private function sendPlans(int $chatId): void {
        // دریافت پلن‌ها از دیتابیس ربات
        $plans = $this->getPlansFromDatabase();

        $text = "📋 *پلن‌های موجود:*\n\n";

        foreach ($plans as $plan) {
            $text .= "🔹 *{$plan['name']}*\n";
            $text .= "   📡 پروتوکل: {$plan['protocol']}\n";
            $text .= "   ⏱ مدت: {$plan['duration_days']} روز\n";
            $text .= "   📊 ترافیک: {$plan['traffic_gb']} گیگابایت\n";
            $text .= "   💰 قیمت: " . number_format($plan['price']) . " تومان\n";
            $text .= "   🛒 خرید: /buy {$plan['id']}\n\n";
        }

        $this->sendMessage($chatId, $text, 'Markdown');
    }

    private function startPurchase(int $chatId, int $planId): void {
        // بررسی موجودی پلن
        $plan = $this->getPlan($planId);

        if (!$plan) {
            $this->sendMessage($chatId, "❌ پلن مورد نظر یافت نشد.");
            return;
        }

        // ایجاد سفارش
        $orderId = $this->createOrder($chatId, $planId);

        // نمایش اطلاعات پرداخت
        $text = "💰 *اطلاعات خرید:*\n\n"
            . "📋 پلن: {$plan['name']}\n"
            . "💵 مبلغ: " . number_format($plan['price']) . " تومان\n"
            . "🔢 شماره سفارش: {$orderId}\n\n"
            . "لطفا مبلغ را به کارت زیر واریز کنید:\n"
            . "💳 6104-3378-xxxx-xxxx\n"
            . "👤 به نام: ...\n\n"
            . "پس از واریز، رسید را ارسال کنید.";

        $this->sendMessage($chatId, $text, 'Markdown');
    }

    private function sendMessage(int $chatId, string $text, string $parseMode = ''): void {
        $params = [
            'chat_id' => $chatId,
            'text' => $text,
        ];

        if ($parseMode) {
            $params['parse_mode'] = $parseMode;
        }

        $this->callApi('sendMessage', $params);
    }

    private function callApi(string $method, array $params = []): array {
        $ch = curl_init("{$this->apiUrl}/{$method}");

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($params),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response, true) ?? [];
    }

    // متدهای کمکی (پیاده‌سازی دیتابیس)
    private function getPlansFromDatabase(): array { /* ... */ }
    private function getPlan(int $id): ?array { /* ... */ }
    private function createOrder(int $userId, int $planId): int { /* ... */ }
}
```

### 10.4 نقطه ورود

```php
<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// بارگذاری تنظیمات
$config = require __DIR__ . '/../config/config.php';

// ایجاد لاگر
$logger = new Logger('vpn-bot');
$logger->pushHandler(new StreamHandler(__DIR__ . '/../logs/bot.log', Logger::INFO));

try {
    // اتصال به پنل
    $panelClient = new PanelClient(
        $config['panel']['host'],
        $config['panel']['port'],
        $config['panel']['base_path'],
        $config['panel']['username'],
        $config['panel']['password']
    );

    if (!$panelClient->login()) {
        throw new \RuntimeException('Failed to login to panel');
    }

    $logger->info('Successfully logged in to panel');

    // بررسی webhook تلگرام
    if (php_sapi_name() === 'cli') {
        // حالت CLI - دریافت آپدیت‌ها با polling
        $bot = new TelegramBot($config['telegram']['token'], $panelClient);
        // TODO: پیاده‌سازی polling
    } else {
        // حالت webhook
        $update = json_decode(file_get_contents('php://input'), true);
        if ($update) {
            $bot = new TelegramBot($config['telegram']['token'], $panelClient);
            $bot->handleUpdate($update);
        }
    }

} catch (\Exception $e) {
    $logger->error($e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}
```

### 10.5 فایل تنظیمات

```php
<?php

// config/config.php

return [
    'panel' => [
        'host' => 'vpn.example.com',
        'port' => 2083,
        'base_path' => '/aX9k2m', // مسیر پنل
        'username' => 'admin',
        'password' => 'your_password',
    ],

    'telegram' => [
        'token' => '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
        'webhook_url' => 'https://your-domain.com/webhook.php',
    ],

    'database' => [
        'host' => 'localhost',
        'name' => 'vpn_bot',
        'user' => 'root',
        'pass' => '',
    ],

    'payment' => [
        'merchant_id' => 'YOUR_MERCHANT_ID',
        'callback_url' => 'https://your-domain.com/callback.php',
    ],
];
```

---

## 11. مدیریت خطاها

### 11.1 خطاهای رایج

| خطا | دلیل | راه حل |
|------|--------|--------|
| `success: false, msg: "Port already exists"` | پورت تکراری | پورت دیگری انتخاب کنید |
| `success: false, msg: "Duplicate email"` | ایمیل تکراری | ایمیل یکتای دیگری استفاده کنید |
| `success: false, msg: "Invalid port"` | پورت نامعتبر | پورت بین 1-65535 باشد |
| `HTTP 404` | عدم احراز هویت | دوباره لاگین کنید |
| `success: false, msg: "twoFactorRequired"` | نیاز به 2FA | کد 2FA ارسال کنید |

### 11.2 لاگ کردن خطاها

```php
<?php

class Logger {
    private string $logFile;

    public function __construct(string $logFile = 'bot.log') {
        $this->logFile = $logFile;
    }

    public function error(string $message, array $context = []): void {
        $this->log('ERROR', $message, $context);
    }

    public function info(string $message, array $context = []): void {
        $this->log('INFO', $message, $context);
    }

    private function log(string $level, string $message, array $context = []): void {
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = !empty($context) ? ' ' . json_encode($context) : '';
        $logMessage = "[{$timestamp}] [{$level}] {$message}{$contextStr}" . PHP_EOL;

        file_put_contents($this->logFile, $logMessage, FILE_APPEND | LOCK_EX);
    }
}
```

---

## نکات نهایی

### 1. امنیت
- هرگز رمزهای عبور را در کد هاردکد نکنید
- از متغیرهای محیطی استفاده کنید
- SSL verification را در production فعال کنید
- Rate limiting را فراموش نکنید

### 2. بهینه‌سازی
- Connection pooling برای درخواست‌های HTTP
- Caching برای اطلاعات تغییر ناپذیر
- Queue برای پردازش همزمان

### 3. پشتیبانی
- Backup منظم دیتابیس
- Monitoring برای سلامت سرویس
- Alert برای خطاهای بحرانی

### 4. مقیاس‌پذیری
- استفاده از Redis برای Session Management
- Load balancing برای ترافیک بالا
- Database replication برای خواندن
