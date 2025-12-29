# 開源威脅情報 EDL 整併專案

自動化整併多個開源威脅情報來源的 External Dynamic Lists (EDL)，適用於防火牆、IDS/IPS 等安全設備。

## 📋 功能特色

- ✅ 每日自動更新
- ✅ 整合多個知名威脅情報來源
- ✅ 自動去重與驗證
- ✅ 提供標準化 EDL 格式
- ✅ GitHub Pages 託管，可直接作為 EDL URL
- ✅ 完整的變更歷史追蹤

## 🎯 威脅情報來源

### IP 清單來源
- **Feodo Tracker** (abuse.ch) - C&C 伺服器 IP
- **Spamhaus DROP** - 垃圾郵件與惡意 IP
- **Emerging Threats** - 已被入侵的 IP
- **Tor Exit Nodes** - Tor 出口節點
- **Blocklist.de** - SSH/FTP 攻擊者

### Domain 清單來源
- **URLhaus** (abuse.ch) - 惡意 URL/Domain
- **Ransomware Tracker** - 勒索軟體域名
- **Phishing Army** - 釣魚網站域名

## 📁 專案結構

```
.
├── .github/
│   └── workflows/
│       └── update-edl.yml          # GitHub Actions workflow
├── scripts/
│   └── update_edl.py               # 主要更新腳本
├── edl/
│   ├── malicious_ips.txt           # 惡意 IP 清單
│   └── malicious_domains.txt       # 惡意域名清單
├── stats/
│   └── latest.json                 # 統計資訊
└── README.md
```

## 🚀 使用方式

### 1. Fork 此專案

點擊右上角的 Fork 按鈕

### 2. 啟用 GitHub Actions

1. 進入你的 repository
2. 點擊 "Actions" 標籤
3. 啟用 workflows

### 3. 啟用 GitHub Pages

1. 進入 Settings → Pages
2. Source 選擇 `gh-pages` 分支
3. 保存設定

### 4. 手動觸發第一次執行（可選）

1. 進入 Actions 標籤
2. 選擇 "Update Threat Intelligence EDL"
3. 點擊 "Run workflow"

## 📡 EDL URL

啟用 GitHub Pages 後，可透過以下 URL 存取：

```
https://<your-username>.github.io/<repo-name>/malicious_ips.txt
https://<your-username>.github.io/<repo-name>/malicious_domains.txt
```

## 🔧 防火牆設定範例

### Palo Alto Networks

```
Objects → External Dynamic Lists

Name: Malicious-IPs
Type: IP List
Source: https://your-username.github.io/repo-name/malicious_ips.txt
Repeat: Daily
```

### Fortinet FortiGate

```
Security Fabric → External Connectors → Threat Feeds

Name: GitHub-EDL-IPs
URI: https://your-username.github.io/repo-name/malicious_ips.txt
Refresh Rate: 1440 (daily)
```

## 📊 統計資訊

查看 `stats/latest.json` 獲取：
- 更新時間戳
- 各來源收集數量
- 總 IP/Domain 數量

## ⚙️ 自訂設定

### 修改更新頻率

編輯 `.github/workflows/update-edl.yml`：

```yaml
schedule:
  - cron: '0 */6 * * *'  # 每 6 小時執行一次
```

### 新增威脅情報來源

在 `scripts/update_edl.py` 中新增方法：

```python
def fetch_custom_source(self):
    try:
        url = "https://example.com/threat-feed.txt"
        response = requests.get(url, timeout=30)
        # 處理邏輯...
    except Exception as e:
        print(f"✗ Custom Source 失敗: {e}")
```

然後在 `main()` 函數中呼叫。

## ⚠️ 注意事項

1. **誤報處理**：某些來源可能包含誤報，建議搭配白名單使用
2. **Tor 節點**：Tor 出口節點本身不一定是惡意的，視使用情境決定是否封鎖
3. **更新延遲**：GitHub Actions 可能有數分鐘延遲
4. **流量限制**：某些威脅情報來源有存取頻率限制

## 📝 授權

本專案為開源專案，採用 MIT License。

威脅情報來源各有其授權條款，請參考各來源網站。

## 🤝 貢獻

歡迎提交 Pull Request 新增更多威脅情報來源！

## 📮 問題回報

如有問題請開 Issue 討論。

---

**免責聲明**：此清單僅供參考，使用者應自行評估並承擔使用風險。
