# Authentication Hardening Middleware Proxy

Reverse proxy đứng trước một backend có lỗ hổng, phát hiện và chặn ba loại tấn công:
- **Brute Force** — nhiều password thử vào một tài khoản
- **Credential Stuffing** — nhiều cặp user:pass từ một IP
- **Account Enumeration** — khai thác error message khác nhau để tìm username hợp lệ

---

## Kiến trúc

```
Client
  │
  ▼
Port 4000  ─── Auth Middleware Proxy ──────────────────────
  │              ├── rateLimiter.js   (sliding window / IP)
  │              ├── accountLock.js   (per-account lockout)
  │              └── forwardLogin()   (rewrite 401 body — TC-03)
  │
  ▼
Port 3000  ─── Vulnerable Target App (intentionally insecure)
```

---

## Cấu trúc thư mục

```
Auth-Hardening/
├── proxy/
│   ├── index.js                 ← Entry point + /admin/* endpoints
│   ├── store.js                 ← In-memory state (counters, blacklist)
│   ├── package.json
│   ├── middleware/
│   │   ├── rateLimiter.js       ← IP-based sliding window (TC-01, TC-02, TC-05)
│   │   ├── accountLock.js       ← Per-account failure counter (TC-04)
│   │   ├── normalizeResp.js     ← Flag middleware (normalization inline trong index.js)
│   │   └── logger.js            ← Ghi log ra console + attack.log
│   └── public/
│       ├── index.html           ← Live Monitor dashboard
│       ├── index.js             ← Dashboard logic (TC buttons, polling)
│       └── index.css            ← Dashboard styles
├── target-app/
│   ├── server.js                ← Backend cố ý có lỗ hổng
│   ├── users.json               ← Database user test
│   └── package.json
├── attack-scripts/
│   ├── brute_force.py           ← Demo TC-01
│   ├── credential_stuff.py      ← Demo TC-02
│   ├── enumerate.py             ← Demo TC-03
│   └── timing_attack.py         ← Demo TC-06 (CLI only)
├── attack.log                   ← Tạo tự động khi proxy chạy
└── README.md
```

---

## Yêu cầu cài đặt

| Thứ cần có | Phiên bản tối thiểu |
|---|---|
| Node.js | 18+ |
| npm | đi kèm Node.js |
| Python | 3.8+ (chỉ cho attack scripts) |
| pip package `requests` | `pip install requests` |

---

## Hướng dẫn chạy

### Bước 1 — Khởi động Backend (Terminal 1)

```bash
cd Auth-Hardening/target-app
npm run dev
```

Kết quả mong đợi:
```
[Backend] Vulnerable target app on http://localhost:3000
```

### Bước 2 — Khởi động Proxy (Terminal 2)

```bash
cd Auth-Hardening/proxy
npm run dev
```

Kết quả mong đợi:
```
[Proxy] Auth Hardening Middleware on http://localhost:4000
[Proxy] Forwarding to backend at http://localhost:3000
[Proxy] Protection: IP rate-limit | Account lockout | Response normalization
```

> Từ đây, **mọi request** gửi đến `:4000` sẽ đi qua middleware rồi mới vào `:3000`.

### Bước 3 — Mở Live Monitor Dashboard (Browser)

Sau khi proxy đã chạy, mở trình duyệt và truy cập:

```
http://localhost:4000/dashboard
```

Dashboard gồm hai cột:
- **Trái** — nút bấm cho từng Test Case (TC-01 đến TC-05), nút Reset, và output console
- **Phải** — trạng thái proxy (IP bị block, account bị lock, fail count) và live log, tự refresh mỗi 2 giây

> **Quan trọng:** Phải mở đúng `http://localhost:4000/dashboard`, **không** dùng VS Code Live Server hay bất kỳ port nào khác. Nếu mở qua Live Server (port 5500), các API call sẽ gửi sai địa chỉ và nhận 404.

---

## Reset state giữa các Test Case

Proxy dùng **in-memory store** — state (IP blacklist, fail counters) tích lũy qua các TC. Nếu không reset, TC sau sẽ bị ảnh hưởng bởi state của TC trước (ví dụ IP đang bị lock từ TC-01 sẽ block luôn TC-02).

**Cách 1 — Nhấn nút trong dashboard:**

Nhấn nút **⟳ Reset All State** ở cột trái của dashboard.

**Cách 2 — Curl:**
```bash
curl -s -X POST http://localhost:4000/admin/reset
```

Kết quả: `{"message":"State reset. All counters and blacklists cleared."}`

> Reset **trước mỗi TC** (trừ TC-05 — phải chạy ngay sau TC-01, không reset giữa chừng).

---

## Demo 5 Test Case

### TC-01 — Brute Force (IP Rate Limit)

```bash
# Reset trước
curl -s -X POST http://localhost:4000/admin/reset

# Chạy qua PROXY (bị chặn sau 5 lần)
python attack-scripts/brute_force.py http://localhost:4000/login

# Chạy thẳng vào backend để so sánh (không có bảo vệ)
python attack-scripts/brute_force.py http://localhost:3000/login
```

**Kết quả qua proxy:**
```
Attempt  1: pass='123456'    status=401  [FAIL]
Attempt  2: pass='password'  status=401  [FAIL]
Attempt  3: pass='admin'     status=401  [FAIL]
Attempt  4: pass='qwerty'    status=401  [FAIL]
Attempt  5: pass='letmein'   status=401  [FAIL]
Attempt  6: pass='secret123' status=429  [BLOCKED]

>>> ATTACK BLOCKED by proxy at attempt 6. Correct password never reached backend.
```

**Kết quả thẳng backend:**
```
Attempt  6: pass='secret123' status=200  [SUCCESS]
>>> ATTACK SUCCEEDED — found valid credentials!
```

---

### TC-02 — Credential Stuffing (Username Diversity Detection)

Credential stuffing khác brute force ở chỗ: mỗi tài khoản chỉ bị thử **1 lần** với 1 password từ breach database. IP rate limit đơn thuần không đủ — cần phát hiện thêm tín hiệu "1 IP thử quá nhiều username khác nhau".

Proxy track số **unique username** mỗi IP thử trong 1 phút. Khi vượt ngưỡng `UNIQUE_USERNAME_THRESHOLD = 3`, ghi log riêng `CREDENTIAL_STUFFING_DETECTED` và block IP — **trước khi** IP rate limit (5 request) kịp trigger.

```bash
# Reset trước (xóa lock IP từ TC-01)
curl -s -X POST http://localhost:4000/admin/reset

python attack-scripts/credential_stuff.py http://localhost:4000/login
```

**Kết quả:**
```
[01] alice@mail.com     status=401  [miss]    ← unique usernames từ IP này: 1
[02] bob@mail.com       status=401  [miss]    ← unique usernames từ IP này: 2
[03] carol@mail.com     status=429  [BLOCKED] ← unique usernames = 3 → CREDENTIAL_STUFFING_DETECTED

>>> IP rate-limit triggered at request 3. Backend only saw 2 request(s).
```

**Proxy log (`attack.log`):**
```json
{"type":"CREDENTIAL_STUFFING_DETECTED","ip":"::1","uniqueUsers":3,"accounts":["alice@mail.com","bob@mail.com","carol@mail.com"]}
```

**So sánh với TC-01 (Brute Force):**

| | Brute Force (TC-01) | Credential Stuffing (TC-02) |
|---|---|---|
| Pattern | 1 user, nhiều password | Nhiều user, 1 password/user |
| Bị block bởi | IP rate limit (5 request) | Username diversity (3 unique user) |
| Log type | `RATE_LIMIT_EXCEEDED` | `CREDENTIAL_STUFFING_DETECTED` |
| Block tại attempt | 6 | 3 |

---

### TC-03 — Account Enumeration (Response Normalization)

```bash
# Reset trước
curl -s -X POST http://localhost:4000/admin/reset

python attack-scripts/enumerate.py
```

**Kết quả:**
```
--- DIRECT to backend (http://localhost:3000/login) ---
  username='ghost'  (non-existent user)       -> 'User not found'
  username='admin'  (valid user, wrong pass)   -> 'Incorrect password'

  RESULT (direct): 2 DIFFERENT responses → username enumeration POSSIBLE

--- THROUGH proxy (http://localhost:4000/login) ---
  username='ghost'  (non-existent user)       -> 'Invalid credentials.'
  username='admin'  (valid user, wrong pass)   -> 'Invalid credentials.'

  RESULT (proxy):  ALL responses identical → enumeration PREVENTED
```

---

### TC-04 — Distributed Brute Force (Account Lockout)

Mô phỏng 12 IP khác nhau, mỗi IP thử 1 password vào account `admin`.
Proxy trust header `X-Real-IP` để giả lập nhiều upstream IP trong demo local.

```bash
# Reset trước
curl -s -X POST http://localhost:4000/admin/reset

# 12 "IP khác nhau" thử vào cùng 1 account
for i in $(seq 1 12); do
  curl -s -X POST http://localhost:4000/login \
    -H "Content-Type: application/json" \
    -H "X-Real-IP: 10.0.0.$i" \
    -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}"
  echo "  <- IP 10.0.0.$i"
done
```

**Kết quả:**
```
{"error":"Invalid credentials."}  <- IP 10.0.0.1
{"error":"Invalid credentials."}  <- IP 10.0.0.2
...
{"error":"Invalid credentials."}  <- IP 10.0.0.10
{"error":"Account temporarily locked...","retryAfter":"30 minutes"}  <- IP 10.0.0.11
{"error":"Account temporarily locked...","retryAfter":"30 minutes"}  <- IP 10.0.0.12
```

Mỗi IP chỉ gửi 1 request → không bị IP rate-limit. Nhưng sau 10 lần sai tích lũy cho `admin`, account bị lock.

Kiểm tra bằng đúng password trong lúc bị lock:
```bash
curl -s -X POST http://localhost:4000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret123"}'
```

```json
{"error":"Account temporarily locked due to too many failed attempts.","retryAfter":"30 minutes"}
```

HTTP Status: **423 Locked**

---

### TC-05 — Header Spoofing (X-Forwarded-For Bypass)

**Mục tiêu:** chứng minh attacker không thể bypass IP block bằng cách giả mạo `X-Forwarded-For`.

> **Lưu ý phân biệt:**
> - `X-Real-IP` — được proxy trust (dùng cho demo TC-04, giả lập nhiều upstream IP)
> - `X-Forwarded-For` — **không** được trust, attacker có thể tự set header này

**Bước 1** — Chạy TC-01 để blacklist IP thật (không reset):
```bash
curl -s -X POST http://localhost:4000/admin/reset
python attack-scripts/brute_force.py http://localhost:4000/login
```

**Bước 2** — Attacker cố giả mạo IP bằng `X-Forwarded-For` sau khi bị block:
```bash
for i in $(seq 1 5); do
  curl -s -X POST http://localhost:4000/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 9.9.9.$i" \
    -d '{"username":"admin","password":"tryagain"}'
  echo "  <- spoofed X-Forwarded-For: 9.9.9.$i"
done
```

**Kết quả:**
```
{"error":"Too many requests. Locked for 15 minutes."}  <- spoofed 9.9.9.1
{"error":"Too many requests. Locked for 15 minutes."}  <- spoofed 9.9.9.2
{"error":"Too many requests. Locked for 15 minutes."}  <- spoofed 9.9.9.3
...
```

`X-Forwarded-For` bị bỏ qua hoàn toàn — proxy vẫn đọc real socket IP đang bị lock.

---

### TC-06 — Timing Attack (crypto.timingSafeEqual)

**Vấn đề:** JavaScript's `===` so sánh chuỗi bằng cách exit sớm ngay khi tìm thấy ký tự khác nhau đầu tiên. Password càng có nhiều ký tự đầu khớp với password thật → backend mất thời gian xử lý lâu hơn một chút → attacker đo được sự chênh lệch này qua hàng trăm request và đoán password từng ký tự một.

**Fix:** `crypto.timingSafeEqual()` so sánh **toàn bộ** buffer bất kể kết quả — thời gian xử lý luôn bằng nhau dù password sai từ ký tự đầu hay ký tự cuối.

```
VULNERABLE:  if (user.password !== password)          ← early exit leak
FIXED:       crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(input))
```

Script đo trực tiếp vào backend `:3000` (bypass proxy để loại bỏ overhead):

```bash
python attack-scripts/timing_attack.py http://localhost:3000/login
```

**Kết quả mong đợi (sau fix):**
```
  Password type                          Avg (ms)    Stdev
  -------------------------------------- ---------  -------
  no overlap    'xxxxxxxx'                   2.41     0.31
  2-char match  'sexxxxxx'                   2.38     0.28
  5-char match  'secrexxx'                   2.40     0.35
  8-char match  'secret12'                   2.39     0.29
  9-char match  'secret123x'                 2.43     0.33

  Timing spread across wrong passwords: 0.05 ms

  RESULT: Timing is UNIFORM across all wrong passwords.
          crypto.timingSafeEqual() is working correctly.
          Timing-based password enumeration is NOT viable.
```

Spread < 1ms và không có xu hướng tăng dần theo prefix length → timing attack không khả thi.

> **Lưu ý:** Variance nhỏ từ network/OS jitter là bình thường. Chạy script nhiều lần để xác nhận không có pattern tăng dần theo prefix length.

---

## Xem log tấn công

File `attack.log` được tạo tự động trong thư mục gốc khi proxy phát hiện tấn công:

```bash
cat attack.log
```

Ví dụ:
```json
{"type":"RATE_LIMIT_EXCEEDED","ip":"::1","count":5,"time":"2025-05-20T10:23:11.000Z"}
{"type":"BLOCKED_BLACKLIST","ip":"::1","time":"2025-05-20T10:23:11.100Z"}
{"type":"ACCOUNT_LOCK_TRIGGERED","username":"admin","fails":10,"time":"2025-05-20T10:25:00.000Z"}
```

Xóa log trước mỗi demo:
```bash
# Bash / Git Bash
rm -f attack.log

# PowerShell
Remove-Item attack.log -ErrorAction SilentlyContinue
```

---

## Tài khoản test có sẵn

| Username | Email | Password |
|---|---|---|
| admin | admin@example.com | secret123 |
| alice | alice@mail.com | alice2024 |
| bob | bob@mail.com | bob@secure |
| carol | carol@mail.com | carolpass |
| dave | dave@mail.com | dave1234 |

---

## Thông số bảo vệ (có thể chỉnh trong code)

| Tham số | Giá trị mặc định | File |
|---|---|---|
| Max login/IP/phút | 5 | `proxy/middleware/rateLimiter.js` |
| Thời gian lock IP | 15 phút | `proxy/middleware/rateLimiter.js` |
| Max fails/account | 10 | `proxy/middleware/accountLock.js` |
| Thời gian lock account | 30 phút | `proxy/middleware/accountLock.js` |

---

## Lưu ý quan trọng

- **Reset state trước mỗi TC** bằng `POST /admin/reset` — trừ TC-05 phải chạy ngay sau TC-01.
- **Proxy dùng in-memory store** — restart proxy cũng reset toàn bộ state.
- **`X-Real-IP` được trust** trong demo để giả lập nhiều IP (TC-04). Trong production thực tế chỉ trust header này nếu đến từ upstream proxy tin cậy (nginx/load balancer).
- **`X-Forwarded-For` không được trust** — TC-05 chứng minh attacker không thể bypass bằng header này.
- Backend `:3000` **cố ý có lỗ hổng** để demo, không dùng trong production.
- Script Python cần package `requests`: `pip install requests`
