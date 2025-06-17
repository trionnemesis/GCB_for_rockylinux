#!/bin/bash

#================================================================================
# Red Hat Enterprise Linux 9 - SSH & PAM Government Configuration Baseline (GCB)
# 文件版本: TWGCB-01-012 (v1.3)
#
# 新增功能 v3: 腳本啟動時自動備份 sshd_config 與 /etc/pam.d 目錄。
# 新增功能 v2: 若 sshd 服務重啟失敗，將自動匯出狀態日誌以供除錯。
#
# 注意：執行此腳本前，請確認系統磁碟空間。
# 建議先在測試環境中執行。
#
# 請以 root 權限執行此腳本:
# sudo bash GCB_sshd.sh
# 
#================================================================================

# --- 1. 自動備份區 ---
BACKUP_DIR="/root/gcb_backup_$(date +%Y%m%d_%H%M%S)"
echo "--- 正在建立備份 ---"

echo "--- 檢查外部網路連線狀態 ---"
if curl -s --head --connect-timeout 5 https://www.google.com >/dev/null; then
    NETWORK_AVAILABLE=1
    echo "外部網路連線正常，可直接使用 dnf 安裝。"
else
    NETWORK_AVAILABLE=0
    echo "[警告] 無法連線外部網路，將略過需要下載的安裝步驟。"
    echo "      請預先準備所需的 rpm 套件並手動安裝。"
fi

run_dnf() {
    local cmd="$1"
    local rpm_desc="$2"
    if [ "$NETWORK_AVAILABLE" -eq 1 ]; then
        eval "$cmd"
    else
        echo "[!] 已離線，略過: $cmd"
        [ -n "$rpm_desc" ] && echo "    需額外安裝 rpm 套件: $rpm_desc"
    fi
}

if mkdir -p "${BACKUP_DIR}/pam.d"; then
    echo "備份目錄已建立於: ${BACKUP_DIR}"
else
    echo "[錯誤] 無法建立備份目錄 ${BACKUP_DIR}。腳本中止。"
    exit 1
fi

# 備份 sshd_config
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config "${BACKUP_DIR}/sshd_config.bak"
    echo "✔️ /etc/ssh/sshd_config 已備份。"
else
    echo "[警告] /etc/ssh/sshd_config 不存在，略過備份。"
fi

# 備份 pam.d 目錄
if [ -d /etc/pam.d ]; then
    if cp -r /etc/pam.d/* "${BACKUP_DIR}/pam.d/"; then
        echo "✔️ /etc/pam.d 目錄已備份。"
    else
        echo "[錯誤] 備份 /etc/pam.d 失敗。腳本中止。"
        exit 1
    fi
else
    echo "[警告] /etc/pam.d 不存在，略過備份。"
fi

echo "--- 備份完成 ---"
echo ""


# --- 2. 安全設定套用區 ---
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_SYSCONFIG="/etc/sysconfig/sshd"
CRYPTO_POLICY_FILE="/etc/crypto-policies/backends/opensshserver.config"

# 函數：設定 sshd_config 中的參數
set_sshd_config() {
    local key="$1"
    local value="$2"
    
    # 刪除舊的設定（無論是否被註解）並在檔案末尾添加新設定
    # 使用 # GCB Edited: 標記被修改的行
    if grep -qE "^\s*#?\s*$key" "$SSHD_CONFIG"; then
        sed -i.bak -E "s/^\s*#?\s*$key.*/# GCB Edited: &/" "$SSHD_CONFIG"
    fi
    echo "$key $value" >> "$SSHD_CONFIG"
    echo "設定 $key 為 $value"
}


echo "--- 開始套用 SSH 安全組態基準 ---"

# TWGCB-01-012-0254: 安裝並啟用 sshd 守護程序
echo "正在安裝並啟用 OpenSSH Server..."
run_dnf "dnf install -y openssh-server.x86_64" "openssh-server"
systemctl --now enable sshd.service

# TWGCB-01-012-0255: 設定 SSH 協定版本為 2
set_sshd_config "Protocol" "2"

# TWGCB-01-012-0256: 設定 /etc/ssh/sshd_config 檔案所有權
echo "設定 sshd_config 檔案所有權為 root:root..."
chown root:root "$SSHD_CONFIG"

# TWGCB-01-012-0257: 設定 /etc/ssh/sshd_config 檔案權限
echo "設定 sshd_config 檔案權限為 600..."
chmod 600 "$SSHD_CONFIG"

# TWGCB-01-012-0258: 限制存取 SSH (使用者需手動設定)
echo "-------------------------------------------------------------"
echo "注意 (TWGCB-01-012-0258):"
echo "請手動編輯 $SSHD_CONFIG 檔案，"
echo "設定 AllowUsers, AllowGroups, DenyUsers, 或 DenyGroups 來限制存取。"
echo "範例： AllowUsers youruser1 youruser2"
echo "-------------------------------------------------------------"

# TWGCB-01-012-0259: 設定 SSH 主機私鑰檔案所有權
echo "設定 SSH 主機私鑰檔案所有權為 root:ssh_keys..."
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:ssh_keys {} \;

# TWGCB-01-012-0260: 設定 SSH 主機私鑰檔案權限
echo "設定 SSH 主機私鑰檔案權限為 640..."
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 640 {} \;

# TWGCB-01-012-0261: 設定 SSH 主機公鑰檔案所有權
echo "設定 SSH 主機公鑰檔案所有權為 root:root..."
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

# TWGCB-01-012-0262: 設定 SSH 主機公鑰檔案權限
echo "設定 SSH 主機公鑰檔案權限為 644..."
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 644 {} \;

# TWGCB-01-012-0263: 設定 SSH 加密演算法
echo "設定強化的 SSH 加密演算法..."
sed -i '/^-oCiphers/d' "$CRYPTO_POLICY_FILE"
sed -i '/^-oMACS/d' "$CRYPTO_POLICY_FILE"
sed -i '/^-oKexAlgorithms/d' "$CRYPTO_POLICY_FILE"
echo "-oCiphers aes128-ctr,aes192-ctr,aes256-ctr" >> "$CRYPTO_POLICY_FILE"
echo "-oMACS=hmac-sha2-512,hmac-sha2-256" >> "$CRYPTO_POLICY_FILE"
echo "-oKexAlgorithms=ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512" >> "$CRYPTO_POLICY_FILE"

# TWGCB-01-012-0264: 設定 SSH 日誌記錄等級為 VERBOSE
set_sshd_config "LogLevel" "VERBOSE"

# TWGCB-01-012-0265: 停用 SSH X11Forwarding 功能
set_sshd_config "X11Forwarding" "no"

# TWGCB-01-012-0266: 設定 SSH 最大認證嘗試次數
set_sshd_config "MaxAuthTries" "4"

# TWGCB-01-012-0267: 強制忽略 .rhosts 檔案
set_sshd_config "IgnoreRhosts" "yes"

# TWGCB-01-012-0268: 停用基於主機的身份驗證
set_sshd_config "HostbasedAuthentication" "no"

# TWGCB-01-012-0269: 禁止 root 登入
set_sshd_config "PermitRootLogin" "no"

# TWGCB-01-012-0270: 禁止空密碼登入
set_sshd_config "PermitEmptyPasswords" "no"

# TWGCB-01-012-0271: 禁止使用者設定環境變數
set_sshd_config "PermitUserEnvironment" "no"

# TWGCB-01-012-0272: 設定 SSH 連線逾時時間 (v1.2)
set_sshd_config "ClientAliveInterval" "600"
set_sshd_config "ClientAliveCountMax" "1"

# TWGCB-01-012-0273: 設定 SSH 登入寬限時間
set_sshd_config "LoginGraceTime" "60"

# TWGCB-01-012-0274: 啟用 PAM 認證
set_sshd_config "UsePAM" "yes"

# TWGCB-01-012-0275: 停用 TCP 轉發
set_sshd_config "AllowTcpForwarding" "no"

# TWGCB-01-012-0276: 設定最大併發未認證連線數
set_sshd_config "MaxStartups" "10:30:60"

# TWGCB-01-012-0277: 設定每個網路連線的最大會談數
set_sshd_config "MaxSessions" "4"

# TWGCB-01-012-0278: 啟用嚴格模式
set_sshd_config "StrictModes" "yes"

# TWGCB-01-012-0279: 設定壓縮模式為 no
set_sshd_config "Compression" "no"

# TWGCB-01-012-0280: 忽略使用者 known_hosts 檔案
set_sshd_config "IgnoreUserKnownHosts" "yes"

# TWGCB-01-012-0281: 顯示上次登入資訊
set_sshd_config "PrintLastLog" "yes"

# TWGCB-01-012-0315: 停用 GSSAPI 驗證
#set_sshd_config "GSSAPIAuthentication" "no"

# TWGCB-01-012-0284: 停用覆寫全系統加密原則
echo "停用 SSH 覆寫全系統加密原則..."
[ -f "$SSHD_SYSCONFIG" ] && sed -ri "s/^\s*(CRYPTO_POLICY\s*=.*)$/# \1/" "$SSHD_SYSCONFIG"
sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 600 {} \;

# --- 3. 完成設定，重新啟動服務並進行錯誤檢查 ---
echo ""
echo "所有 SSH 安全組態設定已套用。正在嘗試重新啟動 sshd 服務..."

# 嘗試重新啟動 sshd 服務並檢查其結果 如果執行上有任何問題請mail給warden@sun.net.tw
if systemctl restart sshd; then
    echo "✔️ sshd 服務已成功重新啟動。"
    echo "所有操作已完成！"
else
    # 如果重啟失敗，記錄狀態並通知使用者
    ERROR_LOG="sshd_restart_status_$(date +%Y%m%d_%H%M%S).log"
    echo "***************************************************"
    echo "[錯誤] sshd 服務重新啟動失敗！"
    echo "正在將詳細狀態匯出至目前的目錄下，檔名為: ${ERROR_LOG}"
    echo "請檢查此檔案以了解失敗原因（通常是 sshd_config 設定語法錯誤）。"
    echo "***************************************************"
    systemctl status sshd --no-pager --full > "${ERROR_LOG}"
    exit 1 # 以錯誤碼退出腳本
fi
