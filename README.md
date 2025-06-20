# Rocky Linux 9 GCB (政府組態基準) 自動化套用腳本

這是一套協助系統工程師將 Rocky Linux 9 系統設定符合臺灣政府組態基準 (GCB) 資安要求的自動化腳本。

## 專案簡介

* **🎯 目的**: 旨在簡化並加速 Rocky Linux 9 系統的 GCB 安全性設定流程，透過自動化腳本減少人為疏失，並確保設定的一致性。
* **📄 依據文件**: 腳本內容主要基於 **TWGCB-01-012\_Red Hat Enterprise Linux 9 政府組態基準說明文件(伺服器)v1.2**。
* **💡 核心功能**: 將繁複的 GCB 指令封裝成模組化腳本，涵蓋了從磁碟、檔案系統、系統服務、網路、稽核到帳號控制等多個面向的資安強化。

---

## ⚠️ 重要：執行前必讀 (免責聲明)

* **高風險操作**: 此系列腳本會對系統進行大量且深層的組態變更，包括修改核心參數、服務設定、使用者權限及防火牆規則。
* **務必備份**: 在執行任何腳本之前，**您必須對系統進行完整備份**。
* **嚴禁直接上線**: **絕對禁止**在未經測試的情況下於正式生產環境中執行。請務必先在隔離的測試機器上進行完整驗證。
* **需具備專業知識**: 執行者應具備 Linux 系統管理及維運經驗，並充分理解腳本中所執行的各項指令及其可能帶來的影響。
* **責任歸屬**: 對於使用此腳本可能造成的任何系統損壞或資料遺失，開發者概不負責。

---

## 📁 檔案功能說明

此專案包含三個核心腳本，各司其職：

### 1. `GCB.sh` - 主要 GCB 組態套用腳本

此為主要的系統強化腳本，涵蓋了 GCB 標準中絕大部分的安全性設定。

**主要功能模組：**

* **💽 磁碟與檔案系統**:
    * 停用 `cramfs`, `squashfs`, `udf`, `usb-storage` 等不必要的檔案系統與核心模組。
    * **提示手動操作**: 對於高風險的磁碟分割與 `fstab` 修改，腳本會顯示明確的警告與建議，要求管理者手動為 `/tmp`, `/var`, `/home` 等目錄建立獨立分割區並加上 `nodev`, `nosuid`, `noexec` 等安全掛載選項。

* **⚙️ 系統設定與維護**:
    * **軟體套件驗證**: 強制 `dnf` 套件管理器在安裝及更新時，驗證 GPG 簽章 (`gpgcheck=1`)。
    * **檔案完整性監控**: 自動安裝及初始化 `AIDE` (進階入侵檢測環境)，並建立每日排程以檢查系統檔案是否被竄改。
    * **開機安全 (GRUB)**: 強化開機載入程式的設定檔權限，並提示管理者手動設定一組 GRUB 通行碼，以防止未經授權的單一使用者模式存取。
    * **核心安全**:
        * 停用核心傾印 (Core dump) 功能，防止敏感記憶體資訊外洩。
        * 啟用記憶體位址空間配置隨機載入 (ASLR)，增加遠端攻擊的難度。
    * **帳號設定檔**: 嚴格設定 `/etc/passwd`, `/etc/shadow` 等關鍵檔案的擁有者與權限為 `root` 且權限為唯讀或禁止讀取。

* **🛡️ 系統服務**:
    * 停用 `xinetd`, `rsyncd`, `avahi-daemon`, `snmpd`, `squid`, `samba`, `vsftpd` 等非必要或具潛在風險的服務。
    * 移除 `telnet`, `rsh`, `ypbind` 等不安全的傳統套件。

* **🌐 網路設定**:
    * 關閉 IP 轉送功能，避免伺服器被當成路由器。
    * 阻擋 ICMP 重新導向與來源路由封包，防範中間人攻擊。
    * 啟用 TCP SYN Cookies，緩解 SYN flood 攻擊。
    * 透過 `modprobe` 停用 `dccp`, `sctp`, `rds`, `tipc` 等不常用的網路協定。

* **📜 日誌與稽核 (Logging & Auditing)**:
    * **Auditd**: 安裝並啟用稽核服務，套用 GCB 規範的詳細稽核規則，監控系統時間變更、權限修改、身分認證等重要事件。
    * **Rsyslog & Journald**: 設定 `rsyslog` 的預設檔案權限，並設定 `journald` 將日誌永久保存於磁碟中以便追溯。

* **🔒 帳號與存取控制**:
    * **密碼品質**: 透過 `pwquality.conf` 設定嚴格的密碼原則，如長度至少12碼、包含4種字元類別、禁用字典詞彙等。
    * **帳號鎖定**: 設定登入失敗 5 次後，帳號將自動鎖定 900 秒 (15分鐘)。
    * **密碼生命週期**: 強制密碼最長有效期為 90 天，最短為 1 天。
    * **閒置登出**: 設定 Bash shell 在閒置 900 秒 (15分鐘) 後自動登出。
    * **預設權限**: 設定全域 `umask` 為 `027`，強化新建檔案與目錄的預設安全性。
    * **su 限制**: 限制只有 `wheel` 群組的成員才能使用 `su` 指令切換為 `root`。

* **🧱 防火牆**:
    * 提供 `Firewalld` (預設) 與 `Nftables` 兩種防火牆的設定選項，管理者可二選一或略過。
    * **Firewalld**: 自動安裝並啟用 `firewalld`，同時遮蔽 `iptables` 與 `nftables` 服務。
    * **Nftables**: 提供一個預設拒絕所有傳入(Input)、轉發(Forward)流量的基礎規則集。

### 2. `GCB_sshd.sh` - SSH 伺服器強化腳本

此腳本專門用於強化 OpenSSH 伺服器 (`sshd`) 的安全性，使其符合 GCB 規範。

**主要功能：**

* **自動備份**: 執行前，腳本會自動備份當前的 `/etc/ssh/sshd_config` 檔案與 `/etc/pam.d` 目錄至 `/root/gcb_backup_...`，以便快速還原。
* **安全協定與權限**:
    * 強制僅使用 SSH Protocol 2。
    * 設定 `sshd_config` 與主機金鑰 (`ssh_host_*_key`) 的檔案擁有者及權限，防止被非授權使用者讀取或修改。
* **存取控制**:
    * **禁止 root 登入** (`PermitRootLogin no`)，這是最重要的安全實踐之一。
    * **提示手動設定**: 腳本會提示管理者手動編輯 `sshd_config`，透過 `AllowUsers`, `AllowGroups` 等參數建立可登入使用者的白名單。
* **強化驗證與連線**:
    * 停用 `.rhosts` 及基於主機的不安全驗證方式。
    * 禁止空密碼登入 (`PermitEmptyPasswords no`)。
    * 限制最大認證嘗試次數為 4 次，以防暴力破解。
    * 設定客戶端閒置超時 (`ClientAliveInterval`)，自動踢除閒置連線。
* **加密演算法**:
    * 透過修改系統加密原則後端設定，強制 SSH 使用強化的加密演算法 (`Ciphers`)、訊息鑑別碼 (`MACs`) 及金鑰交換演算法 (`KexAlgorithms`)。
* **通道與轉發**:
    * **停用 X11 Forwarding** (`X11Forwarding no`)。
    * **停用 TCP Forwarding** (`AllowTcpForwarding no`)。
* **錯誤處理**: 若 `sshd` 服務因設定錯誤而重啟失敗，腳本會自動將詳細的錯誤日誌導出，方便管理者進行除錯。

### 3. `iptables_to_firewalld.sh` - iptables 規則轉換工具

這是一個輔助遷移的工具，當您需要將舊有 `iptables` 規則遷移至 RHEL 9 預設的 `firewalld` 時使用。

**主要功能：**

* **規則解析**: 可讀取一個包含 `iptables` 規則的檔案。
* **自動轉換**: 自動將簡單的 `INPUT` 鏈中允許特定 TCP/UDP 連接埠 (`--dport`) 的規則，轉換為 `firewalld` 的 `--add-port` 指令。
* **識別複雜規則**: 對於無法自動處理的規則 (如 `NAT`、`FORWARD` 鏈、來源 IP 限制、自訂鏈等)，會將其單獨列出並存放在記錄檔中，提醒管理者手動進行轉換。
* **互動式確認**: 在執行任何系統變更之前，腳本會清晰地展示**將要執行**的 `firewalld` 指令列表和**無法轉換**的規則列表，並要求管理者輸入 `yes` 進行最終確認，提供一道安全防線。
* **服務管理**: 獲得確認後，腳本會執行轉換指令、重載 `firewalld`，並**停止及禁用 (stop & disable)** `iptables` 相關服務，完成無縫切換。

### 4.`GCB_apache.sh` - Apache 網站伺服器強化腳本

此腳本專門用於強化 Apache 2.4 網站伺服器，使其符合 GCB 的安全規範。

#### 主要功能：

* **自動備份**: 執行前自動備份現有的 `httpd.conf` 設定檔。

* **模組最小化**: 停用 `dav_module` (WebDAV), `status_module`, `autoindex_module`, `proxy_module` 相關模組, `userdir_module`, `info_module` 等非必要或有潛在風險的模組。

* **安全執行身份**: 確保 Apache 以專屬的低權限帳號 (如 `apache`) 運行，並鎖定該帳號的 shell 及密碼，使其無法登入系統。

* **權限與存取控制**:
    * 設定 `ServerRoot` (Apache安裝目錄) 的擁有者為 `root`，並移除不必要的寫入權限。
    * 採用「預設拒絕」原則，全域設定 `<Directory />` 為 `Require all denied`。
    * 禁止 `.htaccess` 等敏感檔案被用戶端存取。

* **防止資訊洩露**:
    * 設定 `ServerTokens Prod` 及 `ServerSignature Off`，隱藏 Apache 的詳細版本與作業系統資訊。
    * 設定 `FileETag None`，避免洩漏檔案的 i-node 資訊。

* **強化 SSL/TLS**:
    * 採用模組化設定，僅啟用 TLSv1.2 及以上的強健協定。
    * 設定強健的加密演算法套件 (Cipher Suite)，並優先使用伺服器端的加密順序。
    * 關閉不安全的 SSL 重新協商與 SSL 壓縮 (防範 CRIME 攻擊)。
    * 提示管理者手動啟用 HSTS (`Strict-Transport-Security`) 來強制瀏覽器使用 HTTPS。

* **緩解 DoS 攻擊**:
    * 設定合理的 `Timeout`、`KeepAliveTimeout` 時間。
    * 啟用 `mod_reqtimeout` 模組，防範 Slowloris 等慢速攻擊。
    * 限制請求行、標頭欄位數量與大小 (`LimitRequestLine`, `LimitRequestFields` 等)，防止緩衝區溢位攻擊。

* **其他安全性設定**:
    * 停用 `TRACE` 請求方法 (`TraceEnable off`)。
    * 提示管理者手動設定 `X-Frame-Options` 或 `Content-Security-Policy` 以防範點擊劫持 (Clickjacking) 攻擊。
---


## 🚀 使用說明

1.  **上傳腳本**: 將整個 `GCB_SET` 目錄上傳到您的 Rocky Linux 9 伺服器上，例如 `/root/GCB_SET`。
2.  **賦予執行權限**:
    ```bash
    cd /root/GCB_SET
    chmod +x GCB.sh GCB_sshd.sh iptables_to_firewalld.sh GCB_apache.sh
    ```
3.  **離線環境準備** (選擇性):
    * 若您的伺服器無法連上外部網路，請事先下載 `sudo`、`aide`、`audit`、
      `rsyslog`、`libselinux`、`firewalld`、`openssh-server` 等套件的 rpm 檔案。
      腳本偵測到離線時會略過上述安裝步驟，您需要手動安裝這些套件。
4.  **執行主要 GCB 腳本**:
    ```bash
    sudo ./GCB.sh
    ```
    * 在過程中，腳本會詢問您要設定的防火牆 (`Firewalld` 或 `Nftables`)。對於標準的 Rocky/RHEL 9 環境，建議選擇 `Firewalld`。

5.  **執行 SSH 強化腳本**:
    ```bash
    sudo ./GCB_sshd.sh
    ```
    * **再次提醒**: 執行此腳本後，`root` 將無法透過 SSH 登入。請務必確認您已建立好具備 `sudo` 權限的一般使用者帳號，並可從遠端成功登入。
6.  **執行 apache 腳本**:
    ```bash
    sudo ./GCB_apache.sh
    ```
7.  **(選擇性) 執行 iptables 轉換腳本**:
    * 僅當您需要從舊的 `iptables` 設定檔遷移規則時才執行此腳本。
    ```bash
    # 範例：假設您的舊規則檔存放於 /etc/sysconfig/iptables
    sudo ./iptables_to_firewalld.sh /etc/sysconfig/iptables
    ```

8.  **重新開機**:
    * `GCB.sh` 腳本執行完畢後會詢問是否立即重新開機。許多核心層級的設定 (如 GRUB 參數、`audit=1`) 需要**重新開機**後才能完全生效。建議在所有腳本執行完畢並確認基本連線無誤後，手動重啟系統。

---

## 📝 稽核與記錄

* **執行日誌**: `GCB.sh` 的所有執行輸出及錯誤訊息，都會被詳細記錄在 `/var/log/gcb/` 目錄下的日誌檔中。若有指令執行失敗，也會產生一個獨立的錯誤摘要檔案。
* **設定備份**: `GCB_sshd.sh` 會在 `/root/` 目錄下，以執行時間命名，建立一個備份目錄，存放修改前的 `sshd_config` 與 `pam.d` 設定，以利還原。
* **手動項目**: 請務必留意腳本在執行過程中顯示的 `[!] 手動操作需求`訊息，這些項目（如磁碟分割、設定 GRUB 密碼）需要您親自完成。
