# Rocky Linux 9 政府組態基準 (GCB) 自動化檢測與套用腳本

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![OS](https://img.shields.io/badge/OS-Rocky%20Linux%209-red.svg)](https://rockylinux.org/)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)

這是一套協助系統工程師將 Rocky Linux 9 系統設定符合臺灣政府組態基準 (GCB) 資安要求的自動化工具集，提供完整的檢測與設定功能。

## 📋 目錄

- [專案簡介](#專案簡介)
- [重要警告與免責聲明](#重要警告與免責聲明)
- [系統需求](#系統需求)
- [專案結構](#專案結構)
- [功能說明](#功能說明)
- [使用方法](#使用方法)
- [日誌與記錄](#日誌與記錄)
- [故障排除](#故障排除)
- [注意事項](#注意事項)

## 🎯 專案簡介

**目的**：簡化並加速 Rocky Linux 9 系統的 GCB 安全性設定與檢測流程，透過自動化腳本減少人為疏失，確保設定一致性。

**依據文件**：
- `TWGCB-01-012` Red Hat Enterprise Linux 9 政府組態基準說明文件(伺服器) v1.2
- `TWGCB-04-007` Apache HTTP Server 2.4 政府組態基準說明文件 v1.2

**核心特色**：
- 🔍 **完整檢測**：全面掃描系統現狀與 GCB 規範的符合程度
- ⚙️ **自動化設定**：一鍵套用 GCB 安全性組態
- 📊 **詳細報告**：提供彩色終端輸出和完整日誌記錄
- 🛡️ **安全設計**：檢測腳本為唯讀操作，設定腳本包含安全檢查
- 🔄 **可重複執行**：腳本設計支援多次執行而不造成衝突

## ⚠️ 重要警告與免責聲明

### 🚨 高風險操作警告

- **設定腳本** (`GCB_SET/`) 會對系統進行大量且深層的組態變更
- 包括修改核心參數、服務設定、使用者權限及防火牆規則
- **絕對禁止**在未經測試的情況下於正式生產環境執行

### 📋 執行前必要準備

1. **完整系統備份**：執行任何設定腳本前必須備份整個系統
2. **測試環境驗證**：先在隔離的測試機器上進行完整測試
3. **專業知識要求**：執行者應具備 Linux 系統管理及維運經驗
4. **理解腳本內容**：充分理解腳本中各項指令及其影響

### 📜 免責聲明

- **檢測腳本** (`GCB_CHECK/`) 為唯讀操作，相對安全
- 對於使用此腳本可能造成的任何系統損壞或資料遺失，開發者概不負責
- 使用者須自行承擔所有風險

## 💻 系統需求

### 作業系統
- Rocky Linux 9.x (推薦最新版本)
- Red Hat Enterprise Linux 9.x (相容)

### 執行權限
- **必須**以 `root` 權限執行所有腳本
- 建議使用 `sudo` 而非直接 root 登入

### 系統資源
- 磁碟空間：至少 500MB 可用空間 (用於日誌和備份)
- 記憶體：建議 2GB 以上
- 網路：部分功能需要網際網路連線

## 📁 專案結構

```
Rocky-Linux-9-GCB/
├── README.md                          # 專案說明文件
├── GCB_CHECK/                         # 檢測腳本目錄 (唯讀操作)
│   ├── GCB_check.sh                   # 主要 OS GCB 合規性檢測 (572行)
│   └── GCB_check_apache.sh            # Apache 2.4 GCB 合規性檢測 (592行)
└── GCB_SET/                           # 設定腳本目錄 (會修改系統)
    ├── GCB.sh                         # 主要 OS GCB 組態套用 (971行)
    ├── GCB_apache.sh                  # Apache 2.4 強化設定 (381行)
    ├── GCB_sshd.sh                    # SSH 伺服器強化 (227行)
    └── iptables_to_firewalld.sh       # 防火牆規則轉換工具 (212行)
```

## 🔧 功能說明

### 📊 檢測腳本 (GCB_CHECK/)

#### `GCB_check.sh` - 作業系統 GCB 合規性檢測
- **功能**：依據 `TWGCB-01-012` 對 RHEL 9 系統進行全面合規性掃描
- **檢測範圍**：
  - 磁碟與檔案系統安全性
  - 系統設定與維護
  - 系統服務管理
  - 網路安全設定
  - SELinux 配置
  - 帳號與存取控制
  - SSH 伺服器設定
- **輸出格式**：
  - 終端機彩色顯示：🟢 PASS、🔴 FAIL、🟡 SKIP
  - 詳細日誌：`/var/log/rhel9_gcb_check_YYYYMMDD_HHMMSS.log`
  - 統計摘要：通過/未通過數量與完成比率

#### `GCB_check_apache.sh` - Apache 伺服器 GCB 合規性檢測
- **功能**：依據 `TWGCB-04-007` 檢測 Apache HTTP Server 2.4 組態
- **檢測項目**：66 個 GCB 檢查點
- **檢測範圍**：
  - 模組啟用狀態
  - 執行身份與權限
  - 存取控制設定
  - SSL/TLS 安全配置
  - 資訊洩露防護
  - DoS 攻擊防護
- **預設路徑**：`/usr/local/apache`
- **輸出格式**：即時 CLI 結果 + 詳細 Log 檔案

### ⚙️ 設定腳本 (GCB_SET/)

#### `GCB.sh` - 主要作業系統 GCB 組態套用
- **功能**：系統強化的核心腳本，涵蓋 GCB 標準中絕大部分的安全性設定
- **主要模組**：
  - 磁碟與檔案系統強化
  - 系統設定與維護參數
  - 系統服務安全配置
  - 網路安全設定
  - 日誌與稽核配置
  - 帳號與存取控制
  - 防火牆規則設定
- **安全特性**：
  - 高風險操作顯示明確警告
  - 磁碟分割等操作需要手動確認
  - 完整錯誤記錄和復原資訊
- **日誌位置**：`/var/log/gcb/`

#### `GCB_sshd.sh` - SSH 伺服器強化
- **功能**：專門強化 OpenSSH 伺服器 (sshd) 安全性
- **自動備份**：執行前自動備份 `sshd_config` 與 `/etc/pam.d` 目錄
- **核心設定**：
  - 強制使用 SSH Protocol 2
  - 禁止 root 直接登入
  - 限制認證嘗試次數
  - 設定閒置超時時間
  - 強化加密演算法
  - PAM 安全模組配置
- **錯誤處理**：sshd 重啟失敗時自動匯出錯誤日誌
- **網路檢查**：自動檢測外部網路連線狀態

#### `GCB_apache.sh` - Apache 網站伺服器強化
- **功能**：強化 Apache 2.4 網站伺服器以符合 GCB 規範
- **自動備份**：執行前自動備份 `httpd.conf`
- **主要設定**：
  - 停用非必要模組
  - 設定安全執行身份 (apache:apache)
  - 強化 SSL/TLS 配置 (僅啟用 TLSv1.2+)
  - 防止資訊洩露
  - 緩解 DoS 攻擊
  - 模組化 SSL 設定至 `/usr/local/apache/conf/SSLData/`
- **預設路徑**：`/usr/local/apache/`

#### `iptables_to_firewalld.sh` - 防火牆規則轉換工具
- **功能**：將舊有 iptables 規則遷移至 RHEL 9 預設的 firewalld
- **智慧轉換**：
  - 自動轉換簡單的 INPUT 規則
  - 識別無法轉換的複雜規則 (NAT、FORWARD)
  - 生成對應的 firewalld 指令
- **安全確認**：
  - 列出將執行的指令
  - 顯示無法轉換的規則
  - 要求使用者輸入 `yes` 確認
- **目標區域**：預設加入到 `public` zone

## 🚀 使用方法

### 建議流程：檢測 → 設定 → 再檢測

#### 1. 執行權限設定
```bash
# 下載或clone專案後，設定執行權限
chmod +x GCB_CHECK/*.sh
chmod +x GCB_SET/*.sh
```

#### 2. 首次系統檢測
```bash
# 檢測作業系統 GCB 合規性
sudo ./GCB_CHECK/GCB_check.sh

# 檢測 Apache 伺服器 (如果已安裝)
sudo ./GCB_CHECK/GCB_check_apache.sh
```

#### 3. 系統強化設定

⚠️ **在執行設定腳本前，請務必備份系統！**

```bash
# 主要作業系統強化
sudo ./GCB_SET/GCB.sh

# SSH 伺服器強化
sudo ./GCB_SET/GCB_sshd.sh

# Apache 伺服器強化 (如果需要)
sudo ./GCB_SET/GCB_apache.sh
```

#### 4. 防火牆遷移 (選用)
```bash
# 如果需要從 iptables 遷移到 firewalld
sudo ./GCB_SET/iptables_to_firewalld.sh /path/to/iptables/rules
```

#### 5. 設定後驗證
```bash
# 重新檢測確認設定效果
sudo ./GCB_CHECK/GCB_check.sh
sudo ./GCB_CHECK/GCB_check_apache.sh
```

### 進階使用選項

#### 檢視特定日誌
```bash
# 查看最新的檢測日誌
ls -la /var/log/*gcb_check*

# 查看設定日誌
ls -la /var/log/gcb/
```

#### 自訂 Apache 路徑
如果 Apache 安裝在非標準路徑，請編輯腳本中的路徑變數：
```bash
# 編輯 GCB_check_apache.sh 和 GCB_apache.sh
APACHE_ROOT="/your/custom/apache/path"
```

## 📝 日誌與記錄

### 日誌檔案位置

| 腳本類型 | 日誌位置 | 檔案命名格式 |
|---------|---------|-------------|
| OS 檢測 | `/var/log/` | `rhel9_gcb_check_YYYYMMDD_HHMMSS.log` |
| Apache 檢測 | `/var/log/` | `apache_gcb_check_YYYYMMDD_HHMMSS.log` |
| OS 設定 | `/var/log/gcb/` | `gcb_YYYY-MM-DD_HHMMSS.log` |
| 錯誤記錄 | `/var/log/gcb/` | `gcb_errors_YYYY-MM-DD_HHMMSS.log` |

### 備份檔案位置

| 腳本 | 備份位置 | 內容 |
|-----|---------|------|
| `GCB_sshd.sh` | `/root/gcb_backup_YYYYMMDD_HHMMSS/` | `sshd_config`, `/etc/pam.d/` |
| `GCB_apache.sh` | 設定檔目錄 | `httpd.conf.backup` |

### 日誌內容說明

- **檢測日誌**：包含每個檢查項目的詳細結果、統計摘要
- **設定日誌**：記錄所有執行的指令和其輸出
- **錯誤日誌**：記錄執行失敗的指令和行號

## 🔧 故障排除

### 常見問題

#### 1. 權限不足錯誤
```bash
錯誤：無法在 /var/log/ 中建立日誌檔案
```
**解決方案**：確保使用 `sudo` 或 root 權限執行

#### 2. SSH 服務重啟失敗
**解決方案**：
- 檢查 `/var/log/gcb/` 中的錯誤日誌
- 使用備份的 `sshd_config` 復原設定
- 執行 `sudo systemctl status sshd` 查看詳細錯誤

#### 3. Apache 服務異常
**解決方案**：
- 使用備份的 `httpd.conf` 復原
- 執行 `sudo /usr/local/apache/bin/apachectl configtest` 檢查設定語法
- 檢查 SSL 憑證檔案路徑是否正確

#### 4. 防火牆規則轉換失敗
**解決方案**：
- 檢查原始 iptables 規則格式
- 手動處理無法自動轉換的規則
- 使用 `firewall-cmd --list-all` 驗證結果

### 復原程序

#### 快速復原 SSH 設定
```bash
# 復原 SSH 設定 (使用備份)
sudo cp /root/gcb_backup_*/sshd_config /etc/ssh/
sudo systemctl restart sshd
```

#### 復原 Apache 設定
```bash
# 復原 Apache 設定
sudo cp /usr/local/apache/conf/httpd.conf.backup /usr/local/apache/conf/httpd.conf
sudo /usr/local/apache/bin/apachectl restart
```

## 📋 注意事項

### 手動操作項目

執行設定腳本時，請留意顯示 `[!]` 標記的手動操作需求：

1. **磁碟分割設定**：需要手動配置符合 GCB 要求的分割表
2. **GRUB 密碼設定**：需要手動設定開機密碼
3. **憑證管理**：SSL/TLS 憑證需要手動申請和配置
4. **使用者帳號**：特殊使用者帳號權限需要人工審核

### 系統相容性

- **CentOS Stream 9**：部分相容，建議測試後使用
- **AlmaLinux 9**：高度相容
- **Oracle Linux 9**：部分相容

### 效能影響

- 設定後系統可能出現輕微效能影響 (安全性優先)
- 建議在非尖峰時間執行設定作業
- 大型生產環境建議分批執行

### 定期維護

- 建議每季度重新執行檢測腳本
- 定期更新腳本以符合最新 GCB 標準
- 保持系統和安全修補程式的更新

---

**維護者**：warden  
**最後更新**：2025-01-15  
**版本**：2.0

如有問題或建議，請透過 GitHub Issues 回報。
