# Apache Confusion Attack Scanner 🔥

### 🛠️ 介紹
這是一款專為 **Apache HTTP Server** 設計的安全性測試工具，可檢測 **Confusion Attack、SSRF、LFI、RCE、ACL 繞過** 等漏洞。

### 📌 功能
✅ 測試 CVE-2024-38472、CVE-2024-39573、CVE-2024-38477  
✅ 測試 Apache RewriteRule, ProxyPass, TypeMap 攻擊  
✅ 支援 **每類 20 組** Payload 測試  
✅ 自動分析結果並輸出報告  

### 🚀 安裝 & 使用
```bash
git clone https://github.com/YOUR_USERNAME/apache-confusion-scanner.git
cd apache-confusion-scanner
pip install requests
python apache_scanner.py
```