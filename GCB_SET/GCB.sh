#!/bin/bash

# ==============================================================================
# Red Hat Enterprise Linux 9 GCB 組態基準套用腳本 (v1.2)
# ------------------------------------------------------------------------------
# 來源文件: TWGCB-01-012_Red Hat Enterprise Linux 9政府組態基準說明文件(伺服器)v1.2
# 產生日期: 2025-06-17
# 作者:warden
#
# ** 免責聲明 **
# 此腳本是基於政府組態基準文件產生，僅供參考與輔助之用。
# 在執行此腳本前，您必須：
# 1. 完全理解腳本中的每一條指令。
# 2. 已對您的系統做了完整的備份。
# 3. 先在非生產環境中進行完整測試。
#
# 對於使用此腳本可能造成的任何系統損壞或資料遺失，本人概不負責。
# ==============================================================================

###############################################################################
#   新增：集中日誌與錯誤擷取  
###############################################################################
# 允許指令失敗但仍繼續跑（不要 set -e），用 trap 擷取失敗事件
set -o pipefail   # 管住管線錯誤

LOG_DIR="/var/log/gcb"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/gcb_$(date +%F_%H%M%S).log"
ERR_FILE="${LOG_DIR}/gcb_errors_$(date +%F_%H%M%S).log"

# 將螢幕輸出同時寫入 LOG_FILE
exec > >(tee -a "$LOG_FILE") 2>&1

# 失敗時呼叫的處理器
log_error() {
    local lineno=$1
    local cmd=$2
    echo "[ERROR] $(date '+%F %T') 行 $lineno 執行失敗：${cmd}" | tee -a "$ERR_FILE"
}

# 捕捉 ERR；${BASH_COMMAND} 為剛失敗的指令
trap 'log_error "${LINENO}" "${BASH_COMMAND}"' ERR
###############################################################################

# 檢查是否以 root 權限執行
if [[ $EUID -ne 0 ]]; then
   echo "錯誤：此腳本必須以 root 權限執行。" 
   echo "請使用 'sudo ./your_script_name.sh' 來執行。"
   exit 1
fi

###############################################################################
#   網路連線檢查與 dnf 包裝函式
###############################################################################
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

# --- 全域函式 ---

# 顯示手動操作 fstab 的說明
manual_fstab_action() {
    local twgcb_id=$1
    local description=$2
    local example_entry=$3
    echo "----------------------------------------------------------------"
    echo "[!] 手動操作需求 for ${twgcb_id}: ${description}"
    echo "    警告：自動修改 /etc/fstab 風險極高，可能導致系統無法開機。"
    echo "    請根據您的磁碟分割區規劃，手動編輯 /etc/fstab 檔案。"
    echo "    GCB 建議的 fstab 條目範例："
    echo "    ${example_entry}"
    echo "----------------------------------------------------------------"
}

# 顯示手動分割磁碟的說明
manual_partition_action() {
    local twgcb_id=$1
    local description=$2
    local mount_point=$3
    echo "----------------------------------------------------------------"
    echo "[!] 手動操作需求 for ${twgcb_id}: ${description}"
    echo "    警告：磁碟分割屬於高風險操作，本腳本不會自動執行。"
    echo "    請在備份系統後，手動為 ${mount_point} 建立獨立的分割磁區或邏輯磁區。"
    echo "    您可以參考 GCB 文件中的 gdisk 和 LVM 操作範例來完成此項設定。"
    echo "----------------------------------------------------------------"
}


# --- 設定函式 ---

apply_disk_and_fs_settings() {
    echo ""
    echo "==========================================================="
    echo "=== 1. 套用磁碟與檔案系統 (Disk and File Systems) 設定 ==="
    echo "==========================================================="

    echo "[*] TWGCB-01-012-0001: 停用 cramfs 檔案系統..."
    echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
    echo "blacklist cramfs" >> /etc/modprobe.d/cramfs.conf
    rmmod cramfs 2>/dev/null

    echo "[*] TWGCB-01-012-0002: 停用 squashfs 檔案系統..."
    echo "install squashfs /bin/true" > /etc/modprobe.d/squashfs.conf
    echo "blacklist squashfs" >> /etc/modprobe.d/squashfs.conf
    rmmod squashfs 2>/dev/null

    echo "[*] TWGCB-01-012-0003: 停用 udf 檔案系統..."
    echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
    echo "blacklist udf" >> /etc/modprobe.d/udf.conf
    rmmod udf 2>/dev/null
    
    # fstab 相關設定改為手動提示
    manual_fstab_action "TWGCB-01-012-0004" "設定 /tmp 目錄之檔案系統為 tmpfs" "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    manual_fstab_action "TWGCB-01-012-0005" "設定 /tmp 目錄之 nodev 選項" "在 /tmp 的掛載選項中加入 'nodev'"
    manual_fstab_action "TWGCB-01-012-0006" "設定 /tmp 目錄之 nosuid 選項" "在 /tmp 的掛載選項中加入 'nosuid'"
    manual_fstab_action "TWGCB-01-012-0007" "設定 /tmp 目錄之 noexec 選項" "在 /tmp 的掛載選項中加入 'noexec'"
    
    # 磁碟分割相關設定改為手動提示
    manual_partition_action "TWGCB-01-012-0008" "設定 /var 目錄使用獨立之分割磁區" "/var"
    manual_partition_action "TWGCB-01-012-0009" "設定 /var/tmp 目錄使用獨立之分割磁區" "/var/tmp"
    manual_fstab_action "TWGCB-01-012-0010" "設定 /var/tmp 目錄之 nodev 選項" "在 /var/tmp 的掛載選項中加入 'nodev'"
    manual_fstab_action "TWGCB-01-012-0011" "設定 /var/tmp 目錄之 nosuid 選項" "在 /var/tmp 的掛載選項中加入 'nosuid'"
    manual_fstab_action "TWGCB-01-012-0012" "設定 /var/tmp 目錄之 noexec 選項" "在 /var/tmp 的掛載選項中加入 'noexec'"
    manual_partition_action "TWGCB-01-012-0013" "設定 /var/log 目錄使用獨立之分割磁區" "/var/log"
    manual_partition_action "TWGCB-01-012-0014" "設定 /var/log/audit 目錄使用獨立之分割磁區" "/var/log/audit"
    manual_partition_action "TWGCB-01-012-0015" "設定 /home 目錄使用獨立之分割磁區" "/home"
    manual_fstab_action "TWGCB-01-012-0016" "設定 /home 目錄之 nodev 選項" "在 /home 的掛載選項中加入 'nodev'"
    manual_fstab_action "TWGCB-01-012-0017" "設定 /dev/shm 目錄之 nodev 選項" "在 /dev/shm 的掛載選項中加入 'nodev'"
    manual_fstab_action "TWGCB-01-012-0018" "設定 /dev/shm 目錄之 nosuid 選項" "在 /dev/shm 的掛載選項中加入 'nosuid'"
    manual_fstab_action "TWGCB-01-012-0019" "設定 /dev/shm 目錄之 noexec 選項" "在 /dev/shm 的掛載選項中加入 'noexec'"

    echo "[*] TWGCB-01-012-0030: 停用 autofs 服務..."
    systemctl --now disable autofs

    echo "[*] TWGCB-01-012-0031: 停用 USB 儲存裝置..."
    echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
    echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
    rmmod usb-storage 2>/dev/null
    
    echo "[*] TWGCB-01-012-0285: 停用 freevxfs 檔案系統..."
    echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
    echo "blacklist freevxfs" >> /etc/modprobe.d/freevxfs.conf
    rmmod freevxfs 2>/dev/null
    
    echo "[*] TWGCB-01-012-0286: 停用 hfs 檔案系統..."
    echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
    echo "blacklist hfs" >> /etc/modprobe.d/hfs.conf
    rmmod hfs 2>/dev/null
    
    echo "[*] TWGCB-01-012-0287: 停用 hfsplus 檔案系統..."
    echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
    echo "blacklist hfsplus" >> /etc/modprobe.d/hfsplus.conf
    rmmod hfsplus 2>/dev/null

    echo "[*] TWGCB-01-012-0288: 停用 jffs2 檔案系統..."
    echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
    echo "blacklist jffs2" >> /etc/modprobe.d/jffs2.conf
    rmmod jffs2 2>/dev/null

    # 根據 v1.1 新增項目
    echo "[*] TWGCB-01-012-0289: 停用 afs 檔案系統..."
    echo "install afs /bin/true" > /etc/modprobe.d/afs.conf
    echo "blacklist afs" >> /etc/modprobe.d/afs.conf
    rmmod afs 2>/dev/null

    echo "[*] TWGCB-01-012-0290: 停用 ceph 檔案系統..."
    echo "install ceph /bin/true" > /etc/modprobe.d/ceph.conf
    echo "blacklist ceph" >> /etc/modprobe.d/ceph.conf
    rmmod ceph 2>/dev/null

    echo "[*] TWGCB-01-012-0291: 停用 cifs 檔案系統..."
    echo "install cifs /bin/true" > /etc/modprobe.d/cifs.conf
    echo "blacklist cifs" >> /etc/modprobe.d/cifs.conf
    rmmod cifs 2>/dev/null

    echo "[*] TWGCB-01-012-0292: 停用 exfat 檔案系統..."
    echo "install exfat /bin/true" > /etc/modprobe.d/exfat.conf
    echo "blacklist exfat" >> /etc/modprobe.d/exfat.conf
    rmmod exfat 2>/dev/null
    
    echo "[*] TWGCB-01-012-0293: 停用 ext 檔案系統..."
    echo "install ext /bin/true" > /etc/modprobe.d/ext.conf
    echo "blacklist ext" >> /etc/modprobe.d/ext.conf
    rmmod ext 2>/dev/null

    echo "[*] TWGCB-01-012-0294: 停用 fat 檔案系統..."
    echo "install fat /bin/true" > /etc/modprobe.d/fat.conf
    echo "blacklist fat" >> /etc/modprobe.d/fat.conf
    rmmod fat 2>/dev/null
    
    echo "[*] TWGCB-01-012-0295: 停用 fscache 檔案系統..."
    echo "install fscache /bin/true" > /etc/modprobe.d/fscache.conf
    echo "blacklist fscache" >> /etc/modprobe.d/fscache.conf
    rmmod fscache 2>/dev/null
    
    echo "[*] TWGCB-01-012-0296: 停用 fuse 檔案系統..."
    echo "install fuse /bin/true" > /etc/modprobe.d/fuse.conf
    echo "blacklist fuse" >> /etc/modprobe.d/fuse.conf
    rmmod fuse 2>/dev/null

    echo "[*] TWGCB-01-012-0297: 停用 gfs2 檔案系統..."
    echo "install gfs2 /bin/true" > /etc/modprobe.d/gfs2.conf
    echo "blacklist gfs2" >> /etc/modprobe.d/gfs2.conf
    rmmod gfs2 2>/dev/null

    echo "[*] TWGCB-01-012-0298: 停用 nfs_common 檔案系統..."
    echo "install nfs_common /bin/true" > /etc/modprobe.d/nfs_common.conf
    echo "blacklist nfs_common" >> /etc/modprobe.d/nfs_common.conf
    rmmod nfs_common 2>/dev/null

    echo "[*] TWGCB-01-012-0299: 停用 nfsd 檔案系統..."
    echo "install nfsd /bin/true" > /etc/modprobe.d/nfsd.conf
    echo "blacklist nfsd" >> /etc/modprobe.d/nfsd.conf
    rmmod nfsd 2>/dev/null

    echo "[*] TWGCB-01-012-0300: 停用 smbfs_common 檔案系統..."
    echo "install smbfs_common /bin/true" > /etc/modprobe.d/smbfs_common.conf
    echo "blacklist smbfs_common" >> /etc/modprobe.d/smbfs_common.conf
    rmmod smbfs_common 2>/dev/null
}

apply_system_settings() {
    echo ""
    echo "========================================================"
    echo "=== 2. 套用系統設定與維護 (System Settings) 設定 ==="
    echo "========================================================"

    echo "[*] TWGCB-01-012-0032: 啟用 GPG 簽章驗證..."
    sed -i '/^gpgcheck/d' /etc/dnf/dnf.conf
    sed -i '/^localpkg_gpgcheck/d' /etc/dnf/dnf.conf
    echo "gpgcheck=1" >> /etc/dnf/dnf.conf
    echo "localpkg_gpgcheck=1" >> /etc/dnf/dnf.conf
    # Note: yum.conf is often a symlink to dnf.conf in RHEL 9
    if [ -f /etc/yum.conf ] && [ ! -L /etc/yum.conf ]; then
        sed -i '/^gpgcheck/d' /etc/yum.conf
        sed -i '/^localpkg_gpgcheck/d' /etc/yum.conf
        echo "gpgcheck=1" >> /etc/yum.conf
        echo "localpkg_gpgcheck=1" >> /etc/yum.conf
    fi
    find /etc/yum.repos.d/ -type f -name "*.repo" -exec sed -i 's/gpgcheck=0/gpgcheck=1/g' {} +

    echo "[*] 設定 skip_if_unavailable (無法連線時跳過軟體庫)..."
    sed -i '/^skip_if_unavailable/d' /etc/dnf/dnf.conf
    echo "skip_if_unavailable=1" >> /etc/dnf/dnf.conf
    if [ -f /etc/yum.conf ] && [ ! -L /etc/yum.conf ]; then
        sed -i '/^skip_if_unavailable/d' /etc/yum.conf
        echo "skip_if_unavailable=1" >> /etc/yum.conf
    fi

    echo "[*] TWGCB-01-012-0033: 安裝 sudo 套件..."
    run_dnf "dnf install -y sudo" "sudo"

    echo "[*] TWGCB-01-012-0034: 設定 sudo 指令使用 pty..."
    echo "Defaults use_pty" > /etc/sudoers.d/gcb_pty
    
    echo "[*] TWGCB-01-012-0035: 設定 sudo 自定義日誌檔案..."
    echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/gcb_logfile

    echo "[*] TWGCB-01-012-0036 & 0037: 安裝並設定 AIDE 定期檢查..."
    run_dnf "dnf install -y aide" "aide"
    aide --init
    mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    echo "0 5 * * * /usr/sbin/aide --check" > /etc/cron.d/aide_check

    echo "[*] TWGCB-01-012-0038: 設定開機載入程式設定檔之所有權..."
    chown root:root /boot/grub2/grub.cfg
    chown root:root /boot/grub2/grubenv
    [ -f /boot/grub2/user.cfg ] && chown root:root /boot/grub2/user.cfg
    manual_fstab_action "TWGCB-01-012-0038 (UEFI)" "設定 GRUB (UEFI) 設定檔之擁有者與群組" "在 /boot/efi 掛載點加入 'uid=0, gid=0' 選項"

    echo "[*] TWGCB-01-012-0039: 設定開機載入程式設定檔之權限..."
    chmod 600 /boot/grub2/grub.cfg
    chmod 600 /boot/grub2/grubenv
    [ -f /boot/grub2/user.cfg ] && chmod 600 /boot/grub2/user.cfg
    manual_fstab_action "TWGCB-01-012-0039 (UEFI)" "設定 GRUB (UEFI) 設定檔之權限" "在 /boot/efi 掛載點加入 'fmask=0177' 選項"
    
    echo "[!] TWGCB-01-012-0040: 手動設定開機載入程式之通行碼..."
    echo "    請執行 'grub2-setpassword' 並依提示設定一組安全的通行碼。"
    
    echo "[*] TWGCB-01-012-0041: 啟用單一使用者模式身分鑑別..."
    sed -i 's#ExecStart=-/usr/sbin/sulogin#ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue#' /usr/lib/systemd/system/rescue.service
    sed -i 's#ExecStart=-/usr/sbin/sulogin#ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency#' /usr/lib/systemd/system/emergency.service

    echo "[*] TWGCB-01-012-0042: 停用核心傾印 (Core dump) 功能..."
    echo "* hard core 0" > /etc/security/limits.d/gcb-coredump.conf
    echo "fs.suid_dumpable = 0" > /etc/sysctl.d/60-gcb.conf
    echo "kernel.core_pattern = |/bin/false" >> /etc/sysctl.d/60-gcb.conf
    sysctl -w fs.suid_dumpable=0 >/dev/null
    sysctl -w kernel.core_pattern="|/bin/false" >/dev/null
    if [ -f /etc/systemd/coredump.conf ]; then
        sed -i 's/Storage=.*/Storage=none/' /etc/systemd/coredump.conf
        sed -i 's/ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf
        systemctl daemon-reload
        systemctl mask systemd-coredump.socket
    fi

    echo "[*] TWGCB-01-012-0043: 啟用記憶體位址空間配置隨機載入 (ASLR)..."
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-gcb.conf
    sysctl -w kernel.randomize_va_space=2 >/dev/null
    
    echo "[*] TWGCB-01-012-0044: 設定全系統加密原則為 FIPS 或 FUTURE..."
    read -p "請選擇全系統加密原則 (FIPS/FUTURE) [FUTURE]: " crypto_policy
    case "${crypto_policy^^}" in
        FIPS)
            echo "正在設定為 FIPS 模式..."
            fips-mode-setup --enable
            echo "請注意：FIPS 模式需要重新開機才能完全生效。"
            ;;
        *)
            echo "設定為 FUTURE 模式..."
            update-crypto-policies --set FUTURE
            ;;
    esac
    
    echo "[*] TWGCB-01-012-0045 & 0046: 設定 /etc/passwd 檔案所有權與權限..."
    chown root:root /etc/passwd
    chmod 644 /etc/passwd

    echo "[*] TWGCB-01-012-0047 & 0048: 設定 /etc/shadow 檔案所有權與權限..."
    chown root:root /etc/shadow
    chmod 000 /etc/shadow

    echo "[*] TWGCB-01-012-0049 & 0050: 設定 /etc/group 檔案所有權與權限..."
    chown root:root /etc/group
    chmod 644 /etc/group
    
    echo "[*] TWGCB-01-012-0051 & 0052: 設定 /etc/gshadow 檔案所有權與權限..."
    chown root:root /etc/gshadow
    chmod 000 /etc/gshadow

    echo "[*] TWGCB-01-012-0053 to 0060: 設定備份檔案所有權與權限..."
    [ -f /etc/passwd- ] && chown root:root /etc/passwd- && chmod 644 /etc/passwd-
    [ -f /etc/shadow- ] && chown root:root /etc/shadow- && chmod 000 /etc/shadow-
    [ -f /etc/group- ] && chown root:root /etc/group- && chmod 644 /etc/group-
    [ -f /etc/gshadow- ] && chown root:root /etc/gshadow- && chmod 000 /etc/gshadow-

    echo "[*] TWGCB-01-012-0078: 檢查 UID=0 之帳號..."
    awk -F: '($3 == 0) { print $1 }' /etc/passwd | while read -r user; do
        if [ "$user" != "root" ]; then
            echo "警告: 發現非 root 帳號 ${user} 的 UID 為 0。請手動處理。"
        fi
    done

    echo "[*] TWGCB-01-012-0257: 設定 /etc/shells 檔案所有權與權限..."
    chown root:root /etc/shells
    chmod 644 /etc/shells

    echo "[*] TWGCB-01-012-0303 & 0304: 設定 opasswd 檔案所有權與權限..."
    [ -f /etc/security/opasswd ] && chown root:root /etc/security/opasswd && chmod 644 /etc/security/opasswd
    [ -f /etc/security/opasswd.old ] && chown root:root /etc/security/opasswd.old && chmod 644 /etc/security/opasswd.old
    
    echo "[*] TWGCB-01-012-0305: 確保 /etc/shells 中不應存在 nologin..."
    if grep -qE '^[^#]*\/sbin\/nologin$' /etc/shells; then
        echo "正在從 /etc/shells 移除 nologin..."
        sed -i '/\/sbin\/nologin/d' /etc/shells
    fi
    
    echo "[*] TWGCB-01-012-0306: 禁止 chrony 以 root 權限執行..."
    if grep -q "OPTIONS=" /etc/sysconfig/chronyd; then
        sed -i 's/OPTIONS=".*"/OPTIONS="-F 2"/' /etc/sysconfig/chronyd
    else
        echo 'OPTIONS="-F 2"' >> /etc/sysconfig/chronyd
    fi
    systemctl restart chronyd.service

    echo "[*] TWGCB-01-012-0307: 啟用 ptrace 限制模式..."
    echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/60-gcb.conf
    sysctl -w kernel.yama.ptrace_scope=1 >/dev/null

    # 套用所有 sysctl 變更
    sysctl --system >/dev/null
}


apply_services_settings() {
    echo ""
    echo "========================================================"
    echo "=== 3. 套用系統服務 (System Services) 設定         ==="
    echo "========================================================"
    
    echo "[*] TWGCB-01-012-0092: 移除 xinetd 套件..."
    dnf remove -y xinetd
    
    echo "[*] TWGCB-01-012-0093: 設定 chrony 校時來源..."
    echo "    請手動編輯 /etc/chrony.conf，設定至少一個有效的NTP伺服器。"
    echo "    範例: server time.stdtime.gov.tw"
    
    echo "[*] TWGCB-01-012-0094: 停用 rsyncd 服務..."
    systemctl --now mask rsyncd 2>/dev/null

    echo "[*] TWGCB-01-012-0095: 停用 avahi-daemon 服務..."
    systemctl --now mask avahi-daemon.service avahi-daemon.socket 2>/dev/null
    
    echo "[*] TWGCB-01-012-0096: 停用 SNMP 服務..."
    systemctl --now mask snmpd 2>/dev/null

    echo "[*] TWGCB-01-012-0097: 停用 Squid 服務..."
    systemctl --now mask squid 2>/dev/null

    echo "[*] TWGCB-01-012-0098: 停用 Samba 服務..."
    systemctl --now mask smb 2>/dev/null

    echo "[*] TWGCB-01-012-0099: 停用 FTP 伺服器 (vsftpd)..."
    systemctl --now mask vsftpd 2>/dev/null

    echo "[*] TWGCB-01-012-0100: 停用 NIS 伺服器 (ypserv)..."
    systemctl --now mask ypserv 2>/dev/null
    
    echo "[*] TWGCB-01-012-0101: 啟用 kdump 服務..."
    systemctl --now enable kdump.service
}

apply_software_install_settings() {
    echo ""
    echo "========================================================"
    echo "=== 4. 套用安裝與維護軟體 (Software Installation) 設定 ==="
    echo "========================================================"
    
    echo "[*] TWGCB-01-012-0102: 移除 NIS 用戶端套件 (ypbind)..."
    dnf remove -y ypbind

    echo "[*] TWGCB-01-012-0103: 移除 telnet 用戶端套件..."
    dnf remove -y telnet

    echo "[*] TWGCB-01-012-0104: 移除 telnet 伺服器套件..."
    dnf remove -y telnet-server
    
    echo "[*] TWGCB-01-012-0105: 移除 rsh 伺服器套件..."
    dnf remove -y rsh-server

    echo "[*] TWGCB-01-012-0106: 移除 tftp 伺服器套件..."
    dnf remove -y tftp-server

    echo "[*] TWGCB-01-012-0107: 設定更新後移除舊版本元件..."
    echo "clean_requirements_on_remove=True" >> /etc/dnf/dnf.conf
}

apply_network_settings() {
    echo ""
    echo "================================================"
    echo "=== 5. 套用網路設定 (Network Settings) 設定 ==="
    echo "================================================"

    echo "[*] TWGCB-01-012-0108: 停用 IP 轉送..."
    echo "net.ipv4.ip_forward = 0" > /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.ip_forward=0 >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null

    echo "[*] TWGCB-01-012-0109 & 0110: 禁止傳送 ICMP 重新導向封包..."
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
    sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null

    echo "[*] TWGCB-01-012-0111 & 0112: 阻擋來源路由封包..."
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null
    sysctl -w net.ipv4.conf.default.accept_source_route=0 >/dev/null
    sysctl -w net.ipv6.conf.all.accept_source_route=0 >/dev/null
    sysctl -w net.ipv6.conf.default.accept_source_route=0 >/dev/null
    
    echo "[*] TWGCB-01-012-0113 & 0114: 阻擋 ICMP 重新導向封包..."
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null
    sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null
    sysctl -w net.ipv6.conf.all.accept_redirects=0 >/dev/null
    sysctl -w net.ipv6.conf.default.accept_redirects=0 >/dev/null

    echo "[*] TWGCB-01-012-0117 & 0118: 記錄可疑封包..."
    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null
    sysctl -w net.ipv4.conf.default.log_martians=1 >/dev/null

    echo "[*] TWGCB-01-012-0119: 不回應 ICMP 廣播要求..."
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null

    echo "[*] TWGCB-01-012-0120: 忽略偽造之 ICMP 錯誤訊息..."
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 >/dev/null

    echo "[*] TWGCB-01-012-0121 & 0122: 啟用逆向路徑過濾功能..."
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/60-gcb-network.conf
    echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null
    sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null

    echo "[*] TWGCB-01-012-0123: 啟用 TCP SYN cookies..."
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60-gcb-network.conf
    sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null

    # 套用所有 sysctl 變更
    sysctl --system >/dev/null

    echo "[*] TWGCB-01-012-0126: 停用 DCCP 協定..."
    echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
    echo "blacklist dccp" >> /etc/modprobe.d/dccp.conf

    echo "[*] TWGCB-01-012-0127: 停用 SCTP 協定..."
    echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
    echo "blacklist sctp" >> /etc/modprobe.d/sctp.conf

    echo "[*] TWGCB-01-012-0128: 停用 RDS 協定..."
    echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
    echo "blacklist rds" >> /etc/modprobe.d/rds.conf

    echo "[*] TWGCB-01-012-0129: 停用 TIPC 協定..."
    echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf
    echo "blacklist tipc" >> /etc/modprobe.d/tipc.conf
    
    echo "[*] TWGCB-01-012-0130: 停用無線網路介面..."
    if command -v nmcli &> /dev/null; then
        nmcli radio all off
    else
        echo "nmcli not found. Trying modprobe method to disable wireless..."
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then 
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)"; done | sort -u)
            for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
                echo "blacklist $dm" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi
}

apply_logging_and_auditing_settings() {
    echo ""
    echo "========================================================"
    echo "=== 6. 套用日誌與稽核 (Logging and Auditing) 設定 ==="
    echo "========================================================"
    
    echo "[*] TWGCB-01-012-0132: 安裝 auditd 套件..."
    run_dnf "dnf install -y audit audit-libs" "audit audit-libs"

    echo "[*] TWGCB-01-012-0133: 啟用 auditd 服務..."
    systemctl --now enable auditd

    # 確保稽核規則目錄存在
    mkdir -p /etc/audit/rules.d/
    
    echo "[*] TWGCB-01-012-0134: 稽核 auditd 服務啟動前之程序..."
    sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
    
    echo "[*] TWGCB-01-012-0135: 設定稽核待辦事項數量限制..."
    sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit_backlog_limit=8192"/' /etc/default/grub
    # 更新 grub 配置 (注意: 不同系統可能有不同路徑)
    if [ -f /boot/grub2/grub.cfg ]; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
    elif [ -f /boot/efi/EFI/redhat/grub.cfg ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
    else
        echo "警告: 無法找到 grub.cfg，請手動執行 grub2-mkconfig。"
    fi

    echo "[*] TWGCB-01-012-0141: 設定稽核規則檔案權限..."
    touch /etc/audit/rules.d/audit.rules
    chmod 600 /etc/audit/rules.d/audit.rules

    echo "[*] TWGCB-01-012-0142: 設定稽核設定檔案權限..."
    chmod 640 /etc/audit/auditd.conf

    echo "[*] TWGCB-01-012-0146: 設定稽核日誌檔案大小上限..."
    sed -i 's/max_log_file = .*/max_log_file = 32/' /etc/audit/auditd.conf

    echo "[*] TWGCB-01-012-0147: 設定稽核日誌達到其檔案大小上限之行為..."
    sed -i 's/max_log_file_action = .*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

    echo "[*] TWGCB-01-012-0148 to 0172: 寫入稽核規則..."
    # 寫入到一個 gcb.rules 檔案中
    cat <<EOF > /etc/audit/rules.d/gcb.rules
# TWGCB-01-012-0148
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
# TWGCB-01-012-0149
-w /var/run/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k logins
# TWGCB-01-012-0150
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
# TWGCB-01-012-0151
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# TWGCB-01-012-0152
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
# TWGCB-01-012-0153
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network-scripts -p wa -k system-locale
-w /etc/NetworkManager -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
# TWGCB-01-012-0154
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
# TWGCB-01-012-0156
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
# TWGCB-01-012-0173 (Final rule)
-e 2
--loginuid-immutable
EOF
    
    # 載入稽核規則
    augenrules --load
    
    echo "[*] TWGCB-01-012-0174: 安裝 rsyslog 套件..."
    run_dnf "dnf install -y rsyslog" "rsyslog"

    echo "[*] TWGCB-01-012-0175: 啟用 rsyslog 服務..."
    systemctl --now enable rsyslog

    echo "[*] TWGCB-01-012-0176: 設定 rsyslog 日誌檔案預設權限..."
    echo "\$FileCreateMode 0640" > /etc/rsyslog.d/gcb.conf
    
    echo "[*] TWGCB-01-012-0177: 設定 rsyslog 日誌記錄規則..."
    echo "auth.*,authpriv.*,daemon.* /var/log/secure" >> /etc/rsyslog.d/gcb.conf
    systemctl restart rsyslog.service

    echo "[*] TWGCB-01-012-0180: 設定 journald 壓縮日誌檔案..."
    sed -i 's/#Compress=yes/Compress=yes/' /etc/systemd/journald.conf

    echo "[*] TWGCB-01-012-0181: 設定 journald 將日誌檔案永久保存於磁碟..."
    sed -i 's/#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
    systemctl restart systemd-journald
    
    echo "[*] TWGCB-01-012-0308: 啟用 rsyslog logrotate..."
    mkdir -p /var/log/rsyslog
    chmod 750 /var/log/rsyslog
    cat <<EOF > /etc/logrotate.d/rsyslog
/var/log/rsyslog/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    postrotate
        /usr/bin/systemctl reload rsyslog.service >/dev/null || true
    endscript
}
EOF
}

apply_selinux_settings() {
    echo ""
    echo "================================================"
    echo "=== 7. 套用 SELinux 設定                   ==="
    echo "================================================"

    echo "[*] TWGCB-01-012-0182: 安裝 SELinux 套件..."
    run_dnf "dnf install -y libselinux" "libselinux"
    
    echo "[*] TWGCB-01-012-0183: 於開機載入程式中啟用 SELinux..."
    # 移除 selinux=0 和 enforcing=0
    sed -i 's/ selinux=0//g' /etc/default/grub
    sed -i 's/ enforcing=0//g' /etc/default/grub
    # Re-run grub2-mkconfig from previous step
    if [ -f /boot/grub2/grub.cfg ]; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
    elif [ -f /boot/efi/EFI/redhat/grub.cfg ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
    fi

    echo "[*] TWGCB-01-012-0184: 設定 SELinux 政策為 targeted..."
    sed -i 's/SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

    echo "[*] TWGCB-01-012-0185: 設定 SELinux 為 enforcing 模式..."
    sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1
    
    echo "[*] TWGCB-01-012-0187: 移除 setroubleshoot 套件..."
    dnf remove -y setroubleshoot

    echo "[*] TWGCB-01-012-0188: 移除 mcstrans 套件..."
    dnf remove -y mcstrans
}

apply_cron_settings() {
    echo ""
    echo "================================================"
    echo "=== 8. 套用 cron 設定                      ==="
    echo "================================================"

    echo "[*] TWGCB-01-012-0189: 啟用 cron 守護程序..."
    systemctl --now enable crond

    echo "[*] TWGCB-01-012-0190 & 0191: 設定 /etc/crontab 所有權與權限..."
    chown root:root /etc/crontab
    chmod 600 /etc/crontab
    
    echo "[*] TWGCB-01-012-0192 to 0202: 設定 cron 目錄所有權與權限..."
    chown root:root /etc/cron.hourly
    chmod 700 /etc/cron.hourly
    chown root:root /etc/cron.daily
    chmod 700 /etc/cron.daily
    chown root:root /etc/cron.weekly
    chmod 700 /etc/cron.weekly
    chown root:root /etc/cron.monthly
    chmod 700 /etc/cron.monthly
    chown root:root /etc/cron.d
    chmod 700 /etc/cron.d

    echo "[*] TWGCB-01-012-0202 & 0203: 限制 at/cron 使用者..."
    rm -f /etc/cron.deny
    rm -f /etc/at.deny
    touch /etc/cron.allow
    touch /etc/at.allow
    chown root:root /etc/cron.allow /etc/at.allow
    chmod 600 /etc/cron.allow /etc/at.allow

    echo "[*] TWGCB-01-012-0204: 啟用 cron 日誌記錄功能..."
    echo "cron.* /var/log/cron" >> /etc/rsyslog.d/gcb-cron.conf
    systemctl restart rsyslog.service
}

apply_account_and_access_settings() {
    echo ""
    echo "=========================================================="
    echo "=== 9. 套用帳號與存取控制 (Account and Access) 設定 ==="
    echo "=========================================================="

    echo "[*] TWGCB-01-012-0205 to 0216: 設定通行碼品質..."
    sed -i '/^retry/d' /etc/security/pwquality.conf && echo "retry = 3" >> /etc/security/pwquality.conf
    sed -i '/^minlen/d' /etc/security/pwquality.conf && echo "minlen = 12" >> /etc/security/pwquality.conf
    sed -i '/^minclass/d' /etc/security/pwquality.conf && echo "minclass = 4" >> /etc/security/pwquality.conf
    sed -i '/^dcredit/d' /etc/security/pwquality.conf && echo "dcredit = -1" >> /etc/security/pwquality.conf
    sed -i '/^ucredit/d' /etc/security/pwquality.conf && echo "ucredit = -1" >> /etc/security/pwquality.conf
    sed -i '/^lcredit/d' /etc/security/pwquality.conf && echo "lcredit = -1" >> /etc/security/pwquality.conf
    sed -i '/^ocredit/d' /etc/security/pwquality.conf && echo "ocredit = -1" >> /etc/security/pwquality.conf
    sed -i '/^difok/d' /etc/security/pwquality.conf && echo "difok = 3" >> /etc/security/pwquality.conf
    sed -i '/^maxclassrepeat/d' /etc/security/pwquality.conf && echo "maxclassrepeat = 4" >> /etc/security/pwquality.conf
    sed -i '/^maxrepeat/d' /etc/security/pwquality.conf && echo "maxrepeat = 3" >> /etc/security/pwquality.conf
    sed -i '/^dictcheck/d' /etc/security/pwquality.conf && echo "dictcheck=1" >> /etc/security/pwquality.conf
    sed -i '/^maxsequence/d' /etc/security/pwquality.conf && echo "maxsequence=3" >> /etc/security/pwquality.conf # 0311
    
    echo "[*] TWGCB-01-012-0217 & 0218: 設定帳戶鎖定..."
    sed -i '/^deny/d' /etc/security/faillock.conf && echo "deny = 5" >> /etc/security/faillock.conf
    sed -i '/^unlock_time/d' /etc/security/faillock.conf && echo "unlock_time = 900" >> /etc/security/faillock.conf
    sed -i '/^even_deny_root/d' /etc/security/faillock.conf && echo "even_deny_root" >> /etc/security/faillock.conf # 0310
    sed -i '/^root_unlock_time/d' /etc/security/faillock.conf && echo "root_unlock_time=60" >> /etc/security/faillock.conf # 0310

    echo "[*] TWGCB-01-012-0221: 設定通行碼雜湊演算法為 SHA512..."
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    authselect enable-feature with-pamaccess
    if ! grep -q "sha512" /etc/pam.d/system-auth; then
       sed -i '/password\s*sufficient\s*pam_unix.so/ s/$/ sha512/' /etc/pam.d/system-auth
    fi
    if ! grep -q "sha512" /etc/pam.d/password-auth; then
       sed -i '/password\s*sufficient\s*pam_unix.so/ s/$/ sha512/' /etc/pam.d/password-auth
    fi

    echo "[*] TWGCB-01-012-0222 to 0224: 設定通行碼期限..."
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
    # For existing users
    awk -F: '($3 >= 1000) {print $1}' /etc/passwd | xargs -I{} chage --mindays 1 --maxdays 90 --warndays 14 {}

    echo "[*] TWGCB-01-012-0226: 設定登入嘗試失敗之延遲時間..."
    sed -i 's/^FAIL_DELAY.*/FAIL_DELAY 4/' /etc/login.defs

    echo "[*] TWGCB-01-012-0235: 設定系統帳號登入方式為 nologin..."
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    awk -F: -v "uid_min=${UID_MIN}" -v "nologin=$(which nologin)" '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3 < uid_min && $7 != nologin && $7 != "/bin/false") {print $1}' /etc/passwd | while read user; do usermod -s "$(which nologin)" "$user"; done
    
    echo "[*] TWGCB-01-012-0236: 設定 Bash shell 閒置登出時間..."
    echo "readonly TMOUT=900; export TMOUT" > /etc/profile.d/gcb-timeout.sh
    chmod +x /etc/profile.d/gcb-timeout.sh

    echo "[*] TWGCB-01-012-0238: 設定 root 帳號所屬群組為 GID 0..."
    usermod -g 0 root

    echo "[*] TWGCB-01-012-0239 & 0240: 設定預設 umask..."
    echo "umask 027" >> /etc/bashrc
    echo "umask 027" >> /etc/profile
    sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
    
    echo "[*] TWGCB-01-012-0241: 限制 su 指令使用群組..."
    sed -i '/^# auth\s*required\s*pam_wheel.so\s*use_uid/s/^# //' /etc/pam.d/su

    echo "[*] TWGCB-01-012-0309: 設定 root 之預設 umask..."
    echo "umask 027" >> /root/.bashrc
    echo "umask 027" >> /root/.bash_profile
    
    echo "[*] TWGCB-01-012-0312: 啟用 without-nullok..."
    authselect enable-feature without-nullok
}

apply_firewalld_settings() {
    echo ""
    echo "========================================================"
    echo "=== 套用 Firewalld 防火牆設定                      ==="
    echo "========================================================"

    echo "[*] TWGCB-01-012-0242: 安裝 firewalld 防火牆套件..."
    run_dnf "dnf install -y firewalld" "firewalld"

    echo "[*] TWGCB-01-012-0243: 啟用 firewalld 服務..."
    systemctl --now enable firewalld

    echo "[*] TWGCB-01-012-0244: 停用 iptables 服務..."
    systemctl --now mask iptables ip6tables 2>/dev/null

    echo "[*] TWGCB-01-012-0245: 停用 nftables 服務..."
    systemctl --now mask nftables 2>/dev/null
    
    echo "[*] TWGCB-01-012-0246: 設定 firewalld 防火牆預設區域為 public..."
    firewall-cmd --set-default-zone=public
}

apply_nftables_settings() {
    echo ""
    echo "========================================================"
    echo "=== 套用 Nftables 防火牆設定                       ==="
    echo "========================================================"
    
    echo "[*] TWGCB-01-012-0247: 啟用 nftables 服務..."
    systemctl --now enable nftables
    
    echo "[*] TWGCB-01-012-0248: 停用 firewalld 服務..."
    systemctl --now mask firewalld 2>/dev/null

    echo "[*] TWGCB-01-012-0249, 0250, 0252: 建立 nftables 基本規則..."
    cat <<EOF > /etc/nftables/gcb-rules.nft
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ip saddr 127.0.0.0/8 counter drop
        ip6 saddr ::1 counter drop
        # 在此加入您允許的規則, e.g., ct state established,related accept
        ct state established,related accept
        # 範例：允許 SSH
        # tcp dport 22 accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oif lo accept
        ct state established,related accept
        # 在此加入您允許的規則
    }
}
EOF

    echo "[*] TWGCB-01-012-0253: 設定開機載入 nftables 規則..."
    if ! grep -q "/etc/nftables/gcb-rules.nft" /etc/sysconfig/nftables.conf; then
        echo 'include "/etc/nftables/gcb-rules.nft"' >> /etc/sysconfig/nftables.conf
    fi
    
    # 重新啟動 nftables 以載入規則
    systemctl restart nftables
}

# --- 主程式 ---

main() {
    echo "Red Hat Enterprise Linux 9 GCB 組態基準腳本啟動。"
    echo "注意：SSH 設定請執行GCB_sshd.sh。"
    
    # 執行各項設定
    apply_disk_and_fs_settings
    apply_system_settings
    apply_services_settings
    apply_software_install_settings
    apply_network_settings
    apply_logging_and_auditing_settings
    apply_selinux_settings
    apply_cron_settings
    apply_account_and_access_settings
    
    # 詢問使用者要設定哪種防火牆
    echo ""
    echo "------------------- 防火牆設定 -------------------"
    echo "請選擇您系統使用的防火牆 (RHEL 9 預設為 firewalld):"
    PS3="請輸入選項 (1-3): "
    select fw_choice in "Firewalld" "Nftables" "略過防火牆設定"; do
        case $fw_choice in
            "Firewalld")
                apply_firewalld_settings
                break
                ;;
            "Nftables")
                apply_nftables_settings
                break
                ;;
            "略過防火牆設定")
                echo "[i] 已略過防火牆設定。"
                break
                ;;
            *) 
                echo "無效選項 $REPLY"
                ;;
        esac
    done
    
    echo ""
# --- 失敗摘要 ---
if [[ -s "$ERR_FILE" ]]; then
    echo "========================================================"
    echo "!!!  以下指令執行失敗，請檢查並手動處理  !!!"
    cat "$ERR_FILE"
    echo "完整日誌：$LOG_FILE"
    echo "========================================================"
else
    echo "所有指令均已成功執行。完整日誌：$LOG_FILE"
fi

    echo "========================================================"
    echo "=== GCB 腳本執行完畢 ==="
    echo "========================================================"
	echo "重要：如果原來防火牆設定是在iptables上請額外執行iptables_to_firwalld.sh。"
    echo "重要：部分設定 (如核心模組、GRUB) 需要重新開機後才會完整生效。"
    read -p "您想現在重新開機嗎? (y/N): " reboot_confirm
    if [[ "${reboot_confirm,,}" == "y" ]]; then
        echo "系統將在 5 秒後重新啟動..."
        sleep 5
        reboot
    else
        echo "操作完成，請記得在適當時機手動重新開機。"
    fi
}

# 執行主函式
main