#!/bin/bash

# ==============================================================================
# Red Hat Enterprise Linux 9 政府組態基準 (TWGCB-01-012) v1.2 合規性檢測腳本 v3
#
# 作者: warden
# 日期: 2026-06-15
#
# 功能更新:
# 1. 新增日誌匯出功能至 /var/log/
# 2. 針對 TWGCB-01-012-0063 項目新增檔案數量統計
# 3. 新增 CLI 統計摘要 (通過/未通過數量與比率)
# 4. v3 對齊 NICS TWGCB-01-012 v1.2 (1140612)：
#    - 修正檔案系統停用檢查 (0285~0300) 顯示佔位 ID 之問題
#    - 新增 sudo 相關檢查 (0033, 0034, 0035)
#    - 新增 v1.2 新增項目：opasswd 權限 (0303, 0304)、/etc/shells nologin (0305)、
#      chrony 非 root 執行 (0306)、ptrace 限制模式 (0307)
# 5. v3.1 補齊 GCB_SET/GCB.sh 已套用但未檢測之項目：
#    - 新增 cron / at 權限檢查 (0189, 0190/91, 0192~0201, 0202/03, 0204)
#    - 新增通行碼 SHA512 雜湊 (0221)
#    - 新增 rsyslog logrotate (0308)、root umask (0309)、even_deny_root (0310)
#    - 新增 maxsequence (0311)、without-nullok (0312)
#    - 新增 SSH GSSAPIAuthentication=no (0315)
#
# 來源依據：
#   國家資通安全研究院 (NICS) TWGCB-01-012 v1.2 (中華民國114年6月12日)
#   https://www.nics.nat.gov.tw/
#
# 免責聲明: 此腳本僅用於檢測，不會修改任何系統設定。
# 執行前請詳閱腳本內容。建議以 root 權限執行以獲得最準確的結果。
# ==============================================================================

# --- Color Definitions ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'

# --- Global variables for logging and stats ---
LOG_FILE="/var/log/rhel9_gcb_check_$(date +%Y%m%d_%H%M%S).log"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
INFO_COUNT=0

# --- Log file setup ---
touch "$LOG_FILE"
if [ $? -ne 0 ]; then
    echo -e "${C_RED}錯誤：無法在 /var/log/ 中建立日誌檔案。請確認權限或使用 sudo 執行。${C_RESET}"
    exit 1
fi
# Write initial header to log file
echo "Red Hat Enterprise Linux 9 政府組態基準 (TWGCB-01-012) v1.2 檢測日誌" > "$LOG_FILE"
echo "檢測時間: $(date)" >> "$LOG_FILE"
echo "==============================================================================" >> "$LOG_FILE"


# --- Helper Functions ---
strip_colors() {
    echo -e "$1" | sed -r "s/\x1B\[[0-9;]*[mK]//g"
}

print_header() {
    local message="\n${C_BLUE}### $1 ###${C_RESET}"
    echo -e "$message"
    echo -e "\n### $1 ###" >> "$LOG_FILE"
}

print_pass() {
    local message="[ ${C_GREEN}PASS${C_RESET} ] $1"
    echo -e "$message"
    echo "[ PASS ] $1" >> "$LOG_FILE"
    ((PASS_COUNT++))
}

print_fail() {
    local message="[ ${C_RED}FAIL${C_RESET} ] $1"
    echo -e "$message"
    echo "[ FAIL ] $1" >> "$LOG_FILE"
    # Log additional details if provided
    if [ -n "$2" ]; then
        echo -e "$2" # Print details to console
        echo -e "DETAILS:\n$(strip_colors "$2")" >> "$LOG_FILE"
    fi
    ((FAIL_COUNT++))
}

print_info() {
    local message="[ ${C_YELLOW}INFO${C_RESET} ] $1"
    echo -e "$message"
    echo "[ INFO ] $1" >> "$LOG_FILE"
    ((INFO_COUNT++))
}

print_skip() {
    local message="[ ${C_CYAN}SKIP${C_RESET} ] $1"
    echo -e "$message"
    echo "[ SKIP ] $1" >> "$LOG_FILE"
    ((SKIP_COUNT++))
}

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   print_fail "此腳本需要 root 權限才能完整執行。請使用 'sudo ./check_rhel9_gcb.sh' 執行。"
fi

# ==============================================================================
# --- 檢測函式 ---
# ==============================================================================

# 磁碟與檔案系統
check_filesystem() {
    print_header "磁碟與檔案系統 (1/3)"

    # TWGCB-01-012-0001: 停用 cramfs 檔案系統
    if ! modprobe -n -v cramfs | grep -q "install /bin/true" && ! lsmod | grep -q "cramfs"; then
        print_pass "TWGCB-01-012-0001: cramfs 檔案系統已停用。"
    else
        print_fail "TWGCB-01-012-0001: cramfs 檔案系統未停用。應在 /etc/modprobe.d/ 建立設定檔停用。"
    fi

    # TWGCB-01-012-0002: 停用 squashfs 檔案系統
    if ! modprobe -n -v squashfs | grep -q "install /bin/true" && ! lsmod | grep -q "squashfs"; then
        print_pass "TWGCB-01-012-0002: squashfs 檔案系統已停用。"
    else
        print_fail "TWGCB-01-012-0002: squashfs 檔案系統未停用。應在 /etc/modprobe.d/ 建立設定檔停用。"
    fi

    # TWGCB-01-012-0003: 停用 udf 檔案系統
    if ! modprobe -n -v udf | grep -q "install /bin/true" && ! lsmod | grep -q "udf"; then
        print_pass "TWGCB-01-012-0003: udf 檔案系統已停用。"
    else
        print_fail "TWGCB-01-012-0003: udf 檔案系統未停用。應在 /etc/modprobe.d/ 建立設定檔停用。"
    fi

    # TWGCB-01-012-0004, 0008, 0009, 0013, 0014, 0015: 獨立分割區檢查 (已跳過)
    print_skip "TWGCB-01-012-0004, 0008, 0009, 0013, 0014, 0015: 依指示跳過獨立分割區檢查。"

    # TWGCB-01-012-0005, 0006, 0007: 檢查 /tmp 目錄掛載選項
    TMP_OPTS=$(findmnt -n /tmp | awk '{print $4}')
    [[ "$TMP_OPTS" =~ "nodev" ]] && print_pass "TWGCB-01-012-0005: /tmp 已設定 nodev 選項。" || print_fail "TWGCB-01-012-0005: /tmp 未設定 nodev 選項。目前選項: $TMP_OPTS"
    [[ "$TMP_OPTS" =~ "nosuid" ]] && print_pass "TWGCB-01-012-0006: /tmp 已設定 nosuid 選項。" || print_fail "TWGCB-01-012-0006: /tmp 未設定 nosuid 選項。目前選項: $TMP_OPTS"
    [[ "$TMP_OPTS" =~ "noexec" ]] && print_pass "TWGCB-01-012-0007: /tmp 已設定 noexec 選項。" || print_fail "TWGCB-01-012-0007: /tmp 未設定 noexec 選項。目前選項: $TMP_OPTS"

    # TWGCB-01-012-0010, 0011, 0012: 檢查 /var/tmp 目錄掛載選項
    VARTMP_OPTS=$(findmnt -n /var/tmp | awk '{print $4}')
    if [ -n "$VARTMP_OPTS" ]; then
        [[ "$VARTMP_OPTS" =~ "nodev" ]] && print_pass "TWGCB-01-012-0010: /var/tmp 已設定 nodev 選項。" || print_fail "TWGCB-01-012-0010: /var/tmp 未設定 nodev 選項。目前選項: $VARTMP_OPTS"
        [[ "$VARTMP_OPTS" =~ "nosuid" ]] && print_pass "TWGCB-01-012-0011: /var/tmp 已設定 nosuid 選項。" || print_fail "TWGCB-01-012-0011: /var/tmp 未設定 nosuid 選項。目前選項: $VARTMP_OPTS"
        [[ "$VARTMP_OPTS" =~ "noexec" ]] && print_pass "TWGCB-01-012-0012: /var/tmp 已設定 noexec 選項。" || print_fail "TWGCB-01-012-0012: /var/tmp 未設定 noexec 選項。目前選項: $VARTMP_OPTS"
    else
        print_info "TWGCB-01-012-0010~0012: /var/tmp 未掛載為獨立檔案系統，無法檢查掛載選項。"
    fi

    # TWGCB-01-012-0016: 檢查 /home 目錄掛載選項
    HOME_OPTS=$(findmnt -n /home | awk '{print $4}')
    if [ -n "$HOME_OPTS" ]; then
        [[ "$HOME_OPTS" =~ "nodev" ]] && print_pass "TWGCB-01-012-0016: /home 已設定 nodev 選項。" || print_fail "TWGCB-01-012-0016: /home 未設定 nodev 選項。目前選項: $HOME_OPTS"
    else
        print_info "TWGCB-01-012-0016: /home 未掛載為獨立檔案系統，無法檢查掛載選項。"
    fi

    print_header "磁碟與檔案系統 (2/3)"
    # TWGCB-01-012-0017, 0018, 0019: 檢查 /dev/shm 掛載選項
    SHM_OPTS=$(findmnt -n /dev/shm | awk '{print $4}')
    [[ "$SHM_OPTS" =~ "nodev" ]] && print_pass "TWGCB-01-012-0017: /dev/shm 已設定 nodev 選項。" || print_fail "TWGCB-01-012-0017: /dev/shm 未設定 nodev 選項。目前選項: $SHM_OPTS"
    [[ "$SHM_OPTS" =~ "nosuid" ]] && print_pass "TWGCB-01-012-0018: /dev/shm 已設定 nosuid 選項。" || print_fail "TWGCB-01-012-0018: /dev/shm 未設定 nosuid 選項。目前選項: $SHM_OPTS"
    [[ "$SHM_OPTS" =~ "noexec" ]] && print_pass "TWGCB-01-012-0019: /dev/shm 已設定 noexec 選項。" || print_fail "TWGCB-01-012-0019: /dev/shm 未設定 noexec 選項。目前選項: $SHM_OPTS"

    # TWGCB-01-012-0029: 檢查全域可寫目錄的粘滯位 (Sticky bit)
    WORLD_WRITABLE_DIRS=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)
    if [ -z "$WORLD_WRITABLE_DIRS" ]; then
        print_pass "TWGCB-01-012-0029: 所有全域可寫目錄皆已設定粘滯位。"
    else
        local details="發現以下全域可寫目錄未設定粘滯位：\n$WORLD_WRITABLE_DIRS"
        print_fail "TWGCB-01-012-0029: 發現全域可寫目錄未設定粘滯位。" "$details"
    fi

    # TWGCB-01-012-0030: 檢查 autofs 服務
    if systemctl is-enabled autofs &> /dev/null; then
        print_fail "TWGCB-01-012-0030: autofs 服務為啟用狀態，應停用。"
    else
        print_pass "TWGCB-01-012-0030: autofs 服務已停用。"
    fi

    # TWGCB-01-012-0031: 停用 USB 儲存裝置
    if ! modprobe -n -v usb-storage | grep -q "install /bin/true" && ! lsmod | grep -q "usb_storage"; then
        print_pass "TWGCB-01-012-0031: USB 儲存裝置已停用。"
    else
        print_fail "TWGCB-01-012-0031: USB 儲存裝置未停用。應在 /etc/modprobe.d/ 建立設定檔停用。"
    fi

    print_header "磁碟與檔案系統 (3/3)"
    # v1.2 新增項目：TWGCB-01-012-0285 ~ 0300 停用各種檔案系統
    # 以 ID 對應檔案系統，避免顯示佔位符 ID
    declare -A FS_GCB_IDS=(
        ["0285"]="freevxfs"
        ["0286"]="hfs"
        ["0287"]="hfsplus"
        ["0288"]="jffs2"
        ["0289"]="afs"
        ["0290"]="ceph"
        ["0291"]="cifs"
        ["0292"]="exfat"
        ["0293"]="ext"
        ["0294"]="fat"
        ["0295"]="fscache"
        ["0296"]="fuse"
        ["0297"]="gfs2"
        ["0298"]="nfs_common"
        ["0299"]="nfsd"
        ["0300"]="smbfs_common"
    )
    # 以 ID 排序輸出，方便比對 GCB 文件
    for id in $(echo "${!FS_GCB_IDS[@]}" | tr ' ' '\n' | sort); do
        fs="${FS_GCB_IDS[$id]}"
        # lsmod 模組名稱會以底線取代連字號，這裡同步轉換以正確比對
        lsmod_name="${fs//-/_}"
        if ! modprobe -n -v "$fs" 2>/dev/null | grep -q "install /bin/true" && ! lsmod | awk '{print $1}' | grep -qw "$lsmod_name"; then
            print_pass "TWGCB-01-012-${id}: ${fs} 檔案系統已停用。"
        else
            print_fail "TWGCB-01-012-${id}: ${fs} 檔案系統未停用。應在 /etc/modprobe.d/ 建立設定檔停用。"
        fi
    done
}

# 通用檔案權限與擁有者檢查函式
# check_file_perms_owner "ID" "File" "Perms" "Owner"
check_file_perms_owner() {
    local id="$1"
    local file="$2"
    local target_perm="$3"
    local target_owner="$4"
    local fail_flag=0

    if [ ! -e "$file" ]; then
        print_fail "$id: 檔案不存在: $file"
        return
    fi

    # 檢查擁有者與群組
    current_owner=$(stat -c "%U:%G" "$file")
    if [[ "$target_owner" == *":"* ]]; then # owner:group
      if [[ "$current_owner" != "$target_owner" ]]; then
          # 檢查 or 的情況 e.g. root:root or root:shadow
          if [[ "$target_owner" == *" or "* ]]; then
              owner1=$(echo "$target_owner" | awk '{print $1}')
              owner2=$(echo "$target_owner" | awk '{print $3}')
              if [[ "$current_owner" != "$owner1" && "$current_owner" != "$owner2" ]]; then
                  print_fail "$id: $file 擁有者不符。應為 $target_owner，現為 $current_owner。"
                  fail_flag=1
              fi
          else
              print_fail "$id: $file 擁有者不符。應為 $target_owner，現為 $current_owner。"
              fail_flag=1
          fi
      fi
    else # 僅 owner
      current_owner_user=$(stat -c "%U" "$file")
      if [[ "$current_owner_user" != "$target_owner" ]]; then
          print_fail "$id: $file 擁有者不符。應為 $target_owner，現為 $current_owner_user。"
          fail_flag=1
      fi
    fi

    # 檢查權限 (更低權限)
    current_perm=$(stat -c "%a" "$file")
    if (( 8#$current_perm > 8#$target_perm )); then
        print_fail "$id: $file 權限過高。應為 $target_perm 或更低，現為 $current_perm。"
        fail_flag=1
    fi

    if [ $fail_flag -eq 0 ]; then
        print_pass "$id: $file 權限與擁有者設定正確 ($current_perm, $current_owner)。"
    fi
}

# 系統設定與維護
check_system_settings() {
    print_header "系統設定與維護 (1/3)"

    # TWGCB-01-012-0032: GPG 簽章驗證
    GPG_CONF=($(grep -hs "^\s*gpgcheck" /etc/yum.conf /etc/dnf/dnf.conf))
    if [[ "${GPG_CONF[0]}" == "gpgcheck=1" ]]; then
        print_pass "TWGCB-01-012-0032: dnf/yum 設定檔已啟用 gpgcheck。"
    else
        print_fail "TWGCB-01-012-0032: dnf/yum 設定檔未啟用 gpgcheck。目前: ${GPG_CONF[0]}"
    fi
    print_info "TWGCB-01-012-0032: 提醒：此檢查未包含 /etc/yum.repos.d/ 下的所有 repo 檔案。"

    # TWGCB-01-012-0033: sudo 套件
    rpm -q sudo &> /dev/null && print_pass "TWGCB-01-012-0033: sudo 套件已安裝。" || print_fail "TWGCB-01-012-0033: sudo 套件未安裝。"

    # TWGCB-01-012-0034: sudo 指令需使用 pty
    if grep -rhqE '^\s*Defaults\s+use_pty' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        print_pass "TWGCB-01-012-0034: sudo 已設定 use_pty。"
    else
        print_fail "TWGCB-01-012-0034: sudo 未設定 use_pty。應於 /etc/sudoers 或 /etc/sudoers.d/ 加入 Defaults use_pty。"
    fi

    # TWGCB-01-012-0035: sudo 自訂日誌檔
    if grep -rhqE '^\s*Defaults\s+logfile\s*=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        print_pass "TWGCB-01-012-0035: sudo 已設定自訂日誌檔。"
    else
        print_fail "TWGCB-01-012-0035: sudo 未設定自訂日誌檔。應於 /etc/sudoers 或 /etc/sudoers.d/ 加入 Defaults logfile=\"/var/log/sudo.log\"。"
    fi

    # TWGCB-01-012-0036: AIDE 套件
    rpm -q aide &> /dev/null && print_pass "TWGCB-01-012-0036: AIDE 套件已安裝。" || print_fail "TWGCB-01-012-0036: AIDE 套件未安裝。"

    # TWGCB-01-012-0037: 定期 AIDE 檢查
    crontab -u root -l | grep -q "aide --check" &>/dev/null && print_pass "TWGCB-01-012-0037: root 的 crontab 中已設定 AIDE 定期檢查。" || print_fail "TWGCB-01-012-0037: root 的 crontab 中未設定 AIDE 定期檢查。"

    # TWGCB-01-012-0038 & 0039: GRUB 設定檔權限
    check_file_perms_owner "TWGCB-01-012-0038/39" "/boot/grub2/grub.cfg" "600" "root:root"
    check_file_perms_owner "TWGCB-01-012-0038/39" "/boot/grub2/grubenv" "600" "root:root"
    if [ -f /boot/grub2/user.cfg ]; then
        check_file_perms_owner "TWGCB-01-012-0038/39" "/boot/grub2/user.cfg" "600" "root:root"
    fi

    # TWGCB-01-012-0040: GRUB 設定通行碼
    grep -q "^GRUB2_PASSWORD=" /boot/grub2/user.cfg 2>/dev/null && print_pass "TWGCB-01-012-0040: GRUB 已設定通行碼。" || print_fail "TWGCB-01-012-0040: GRUB 未設定通行碼。"

    # TWGCB-01-012-0041: 單一使用者模式身分鑑別
    grep -q "systemd-sulogin-shell rescue" /usr/lib/systemd/system/rescue.service && print_pass "TWGCB-01-012-0041: rescue.service 已設定身分鑑別。" || print_fail "TWGCB-01-012-0041: rescue.service 未設定身分鑑別。"
    
    # TWGCB-01-012-0042: 核心傾印功能
    grep -q '^\*\s*hard\s*core\s*0' /etc/security/limits.conf /etc/security/limits.d/* &>/dev/null && print_pass "TWGCB-01-012-0042: limits.conf 已設定 hard core 0。" || print_fail "TWGCB-01-012-0042: limits.conf 未設定 hard core 0。"
    sysctl fs.suid_dumpable | grep -q "fs.suid_dumpable = 0" && print_pass "TWGCB-01-012-0042: fs.suid_dumpable 已設為 0。" || print_fail "TWGCB-01-012-0042: fs.suid_dumpable 未設為 0。"
    
    # TWGCB-01-012-0043: ASLR
    sysctl kernel.randomize_va_space | grep -q "kernel.randomize_va_space = 2" && print_pass "TWGCB-01-012-0043: ASLR (kernel.randomize_va_space) 已設為 2。" || print_fail "TWGCB-01-012-0043: ASLR (kernel.randomize_va_space) 未設為 2。"
    
    print_header "系統設定與維護 (2/3)"
    # TWGCB-01-012-0044: 全系統加密原則
    CRYPTO_POLICY=$(update-crypto-policies --show)
    if [[ "$CRYPTO_POLICY" == "FIPS" || "$CRYPTO_POLICY" == "FUTURE" ]]; then
        print_pass "TWGCB-01-012-0044: 全系統加密原則為 $CRYPTO_POLICY，符合要求。"
    else
        print_fail "TWGCB-01-012-0044: 全系統加密原則為 $CRYPTO_POLICY，應為 FUTURE 或 FIPS。"
    fi

    # TWGCB-01-012-0045 & 0046: /etc/passwd 權限
    check_file_perms_owner "TWGCB-01-012-0045/46" "/etc/passwd" "644" "root:root"

    # TWGCB-01-012-0047 & 0048: /etc/shadow 權限
    check_file_perms_owner "TWGCB-01-012-0047/48" "/etc/shadow" "000" "root:root or root:shadow"
    
    # TWGCB-01-012-0049 & 0050: /etc/group 權限
    check_file_perms_owner "TWGCB-01-012-0049/50" "/etc/group" "644" "root:root"

    # TWGCB-01-012-0051 & 0052: /etc/gshadow 權限
    check_file_perms_owner "TWGCB-01-012-0051/52" "/etc/gshadow" "000" "root:root or root:shadow"

    print_header "系統設定與維護 (3/3)"
    # TWGCB-01-012-0062: 檢查無擁有者之檔案
    NO_USER_FILES=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)
    if [ -z "$NO_USER_FILES" ]; then
        print_pass "TWGCB-01-012-0062: 系統中沒有無擁有者之檔案。"
    else
        local file_count=$(echo "$NO_USER_FILES" | wc -l)
        local details="CLI僅顯示前10筆，完整列表請見日誌檔。\n$(echo "$NO_USER_FILES" | head -n 10)"
        print_fail "TWGCB-01-012-0062: 發現 ${file_count} 個無擁有者之檔案。" "$details"
        echo -e "\n--- 無擁有者之檔案完整列表 ---\n$NO_USER_FILES" >> "$LOG_FILE"
    fi

    # TWGCB-01-012-0063: 檢查無擁有群組之檔案
    NO_GROUP_FILES=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)
    if [ -z "$NO_GROUP_FILES" ]; then
        print_pass "TWGCB-01-012-0063: 系統中沒有無擁有群組之檔案。"
    else
        local file_count=$(echo "$NO_GROUP_FILES" | wc -l)
        local details="CLI僅顯示前10筆，完整列表請見日誌檔。\n$(echo "$NO_GROUP_FILES" | head -n 10)"
        print_fail "TWGCB-01-012-0063: 發現 ${file_count} 個無擁有群組之檔案。" "$details"
        echo -e "\n--- 無擁有群組之檔案完整列表 ---\n$NO_GROUP_FILES" >> "$LOG_FILE"
    fi

    # v1.2 新增項目：TWGCB-01-012-0303 & 0304: opasswd 檔案所有權與權限
    if [ -f /etc/security/opasswd ]; then
        check_file_perms_owner "TWGCB-01-012-0303/04" "/etc/security/opasswd" "644" "root:root"
    else
        print_info "TWGCB-01-012-0303/04: /etc/security/opasswd 不存在 (系統尚未啟用 pam_pwhistory 紀錄)。"
    fi
    if [ -f /etc/security/opasswd.old ]; then
        check_file_perms_owner "TWGCB-01-012-0303/04" "/etc/security/opasswd.old" "644" "root:root"
    fi

    # v1.2 新增項目：TWGCB-01-012-0305: /etc/shells 不應包含 nologin
    if [ -f /etc/shells ]; then
        if grep -qE '^[^#]*/sbin/nologin\s*$' /etc/shells; then
            print_fail "TWGCB-01-012-0305: /etc/shells 中包含 /sbin/nologin，應移除。"
        else
            print_pass "TWGCB-01-012-0305: /etc/shells 中未包含 /sbin/nologin。"
        fi
    else
        print_info "TWGCB-01-012-0305: /etc/shells 不存在，無法檢查。"
    fi

    # v1.2 新增項目：TWGCB-01-012-0306: 禁止 chrony 以 root 權限執行
    if [ -f /etc/sysconfig/chronyd ]; then
        if grep -qE '^\s*OPTIONS=.*-u\s+root' /etc/sysconfig/chronyd; then
            print_fail "TWGCB-01-012-0306: chronyd 設定為以 root 權限執行，應改為以非特權使用者執行 (例如 -F 2)。"
        elif grep -qE '^\s*OPTIONS=.*-F\s*2' /etc/sysconfig/chronyd; then
            print_pass "TWGCB-01-012-0306: chronyd 已設定 -F 2，禁止以 root 權限執行。"
        else
            print_info "TWGCB-01-012-0306: /etc/sysconfig/chronyd 未明確設定執行身分 (預設為 chrony 使用者)。"
        fi
    else
        print_info "TWGCB-01-012-0306: /etc/sysconfig/chronyd 不存在，無法檢查。"
    fi

    # v1.2 新增項目：TWGCB-01-012-0307: 啟用 ptrace 限制模式
    PTRACE_SCOPE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
    if [[ "$PTRACE_SCOPE" =~ ^[1-3]$ ]]; then
        print_pass "TWGCB-01-012-0307: kernel.yama.ptrace_scope 已設為 ${PTRACE_SCOPE}，符合啟用限制模式要求。"
    else
        print_fail "TWGCB-01-012-0307: kernel.yama.ptrace_scope 為 '${PTRACE_SCOPE:-未設定}'，應設為 1 (或更嚴格)。"
    fi
}

# 系統服務
check_services() {
    print_header "系統服務"

    # TWGCB-01-012-0092: 移除 xinetd 套件
    rpm -q xinetd &> /dev/null && print_fail "TWGCB-01-012-0092: xinetd 套件已安裝，應移除。" || print_pass "TWGCB-01-012-0092: xinetd 套件未安裝。"
    
    # TWGCB-01-012-0093: chrony 校時設定
    grep -qE "^\s*(server|pool)" /etc/chrony.conf && print_pass "TWGCB-01-012-0093: /etc/chrony.conf 已設定校時來源。" || print_fail "TWGCB-01-012-0093: /etc/chrony.conf 未設定校時來源。"

    # TWGCB-01-012-0095: avahi-daemon 服務
    if systemctl is-enabled avahi-daemon.service &> /dev/null || systemctl is-enabled avahi-daemon.socket &> /dev/null; then
        print_fail "TWGCB-01-012-0095: avahi-daemon 服務或 socket 為啟用狀態，應停用。"
    else
        print_pass "TWGCB-01-012-0095: avahi-daemon 服務與 socket 已停用。"
    fi

    # TWGCB-01-012-0099: FTP 伺服器
    if systemctl is-enabled vsftpd &> /dev/null; then
        print_fail "TWGCB-01-012-0099: vsftpd (FTP伺服器) 服務為啟用狀態，應停用。"
    else
        print_pass "TWGCB-01-012-0099: vsftpd (FTP伺服器) 服務已停用。"
    fi
}

# 安裝與維護軟體
check_software() {
    print_header "安裝與維護軟體"
    
    # TWGCB-01-012-0103: 移除 telnet 用戶端套件
    rpm -q telnet &> /dev/null && print_fail "TWGCB-01-012-0103: telnet 套件已安裝，應移除。" || print_pass "TWGCB-01-012-0103: telnet 套件未安裝。"

    # TWGCB-01-012-0104: 移除 telnet 伺服器套件
    rpm -q telnet-server &> /dev/null && print_fail "TWGCB-01-012-0104: telnet-server 套件已安裝，應移除。" || print_pass "TWGCB-01-012-0104: telnet-server 套件未安裝。"

    # TWGCB-01-012-0105: 移除 rsh 伺服器套件
    rpm -q rsh-server &> /dev/null && print_fail "TWGCB-01-012-0105: rsh-server 套件已安裝，應移除。" || print_pass "TWGCB-01-012-0105: rsh-server 套件未安裝。"
}

# 網路設定
check_network() {
    print_header "網路設定"

    # TWGCB-01-012-0108: IP 轉送
    IPF4=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
    IPF6=$(sysctl net.ipv6.conf.all.forwarding | awk '{print $3}')
    if [[ "$IPF4" -eq 0 && "$IPF6" -eq 0 ]]; then
        print_pass "TWGCB-01-012-0108: IPv4 與 IPv6 轉送功能已停用。"
    else
        print_fail "TWGCB-01-012-0108: IP 轉送功能未停用 (ipv4: $IPF4, ipv6: $IPF6)。"
    fi

    # TWGCB-01-012-0109 & 0110: 禁止傳送 ICMP 重新導向封包
    if [[ $(sysctl net.ipv4.conf.all.send_redirects | awk '{print $3}') -eq 0 && $(sysctl net.ipv4.conf.default.send_redirects | awk '{print $3}') -eq 0 ]]; then
        print_pass "TWGCB-01-012-0109/0110: 禁止傳送 ICMP 重新導向封包。"
    else
        print_fail "TWGCB-01-012-0109/0110: 未禁止傳送 ICMP 重新導向封包。"
    fi
}

# SELinux
check_selinux() {
    print_header "SELinux"

    # TWGCB-01-012-0182: SELinux 套件
    rpm -q libselinux &> /dev/null && print_pass "TWGCB-01-012-0182: libselinux 套件已安裝。" || print_fail "TWGCB-01-012-0182: libselinux 套件未安裝。"
    
    # TWGCB-01-012-0185: SELinux 政策
    grep -q "^\s*SELINUXTYPE=targeted" /etc/selinux/config && print_pass "TWGCB-01-012-0185: SELinux 政策設定為 targeted。" || print_fail "TWGCB-01-012-0185: SELinux 政策未設定為 targeted。"

    # TWGCB-01-012-0186: SELinux 啟用狀態
    if getenforce | grep -q "Enforcing"; then
        print_pass "TWGCB-01-012-0186: SELinux 啟用狀態為 Enforcing。"
    else
        print_fail "TWGCB-01-012-0186: SELinux 啟用狀態不為 Enforcing，目前為 $(getenforce)。"
    fi
    
    # TWGCB-01-012-0187: 移除 setroubleshoot 套件
    rpm -q setroubleshoot &> /dev/null && print_fail "TWGCB-01-012-0187: setroubleshoot 套件已安裝，應移除。" || print_pass "TWGCB-01-012-0187: setroubleshoot 套件未安裝。"
}

# 帳號與存取控制
# cron / at 排程權限
check_cron() {
    print_header "cron / at 排程權限"

    # TWGCB-01-012-0189: 啟用 cron 守護程序
    if systemctl is-enabled crond &> /dev/null; then
        print_pass "TWGCB-01-012-0189: crond 服務已啟用。"
    else
        print_fail "TWGCB-01-012-0189: crond 服務未啟用。"
    fi

    # TWGCB-01-012-0190 & 0191: /etc/crontab 所有權與權限
    if [ -e /etc/crontab ]; then
        check_file_perms_owner "TWGCB-01-012-0190/91" "/etc/crontab" "600" "root:root"
    else
        print_info "TWGCB-01-012-0190/91: /etc/crontab 不存在。"
    fi

    # TWGCB-01-012-0192 ~ 0201: 各 cron 目錄所有權與權限 (600 或更嚴格)
    local cron_dir id
    declare -A CRON_DIRS=(
        ["/etc/cron.hourly"]="TWGCB-01-012-0192/93"
        ["/etc/cron.daily"]="TWGCB-01-012-0194/95"
        ["/etc/cron.weekly"]="TWGCB-01-012-0196/97"
        ["/etc/cron.monthly"]="TWGCB-01-012-0198/99"
        ["/etc/cron.d"]="TWGCB-01-012-0200/01"
    )
    for cron_dir in "${!CRON_DIRS[@]}"; do
        id="${CRON_DIRS[$cron_dir]}"
        if [ -d "$cron_dir" ]; then
            check_file_perms_owner "$id" "$cron_dir" "700" "root:root"
        else
            print_info "$id: 目錄 $cron_dir 不存在。"
        fi
    done

    # TWGCB-01-012-0202 & 0203: 限制 at/cron 使用者 (cron.allow / at.allow 存在且權限正確)
    local allow_file
    for allow_file in /etc/cron.allow /etc/at.allow; do
        if [ -f "$allow_file" ]; then
            check_file_perms_owner "TWGCB-01-012-0202/03" "$allow_file" "600" "root:root"
        else
            print_fail "TWGCB-01-012-0202/03: $allow_file 不存在，應建立並設定為 root:root 600。"
        fi
    done
    if [ -f /etc/cron.deny ]; then
        print_fail "TWGCB-01-012-0202/03: /etc/cron.deny 存在，應移除以避免與 cron.allow 衝突。"
    else
        print_pass "TWGCB-01-012-0202/03: /etc/cron.deny 已移除。"
    fi
    if [ -f /etc/at.deny ]; then
        print_fail "TWGCB-01-012-0202/03: /etc/at.deny 存在，應移除以避免與 at.allow 衝突。"
    else
        print_pass "TWGCB-01-012-0202/03: /etc/at.deny 已移除。"
    fi

    # TWGCB-01-012-0204: 啟用 cron 日誌記錄
    if grep -rqsE '^\s*cron\.\*' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
        print_pass "TWGCB-01-012-0204: rsyslog 已設定 cron 日誌記錄。"
    else
        print_fail "TWGCB-01-012-0204: rsyslog 未設定 cron 日誌記錄。應於 /etc/rsyslog.conf 或 /etc/rsyslog.d/ 加入 'cron.*' 規則。"
    fi
}

check_accounts() {
    print_header "帳號與存取控制 (1/2)"
    
    # TWGCB-01-012-0207: 通行碼最小長度
    MINLEN=$(grep '^\s*minlen' /etc/security/pwquality.conf | awk -F= '{print $2}' | xargs)
    if [[ "$MINLEN" -ge 12 ]]; then
        print_pass "TWGCB-01-012-0207: 通行碼最小長度 (minlen) 為 $MINLEN，符合 >= 12 要求。"
    else
        print_fail "TWGCB-01-012-0207: 通行碼最小長度 (minlen) 為 $MINLEN，應 >= 12。"
    fi

    # TWGCB-01-012-0208: 通行碼字元類別數量
    MINCLASS=$(grep '^\s*minclass' /etc/security/pwquality.conf | awk -F= '{print $2}' | xargs)
    if [[ "$MINCLASS" -ge 4 ]]; then
        print_pass "TWGCB-01-012-0208: 通行碼字元類別數 (minclass) 為 $MINCLASS，符合 >= 4 要求。"
    else
        print_fail "TWGCB-01-012-0208: 通行碼字元類別數 (minclass) 為 $MINCLASS，應 >= 4。"
    fi

    # TWGCB-01-012-0218: 帳戶鎖定閾值
    DENY=$(grep '^\s*deny' /etc/security/faillock.conf | awk -F= '{print $2}' | xargs)
    if [[ "$DENY" -gt 0 && "$DENY" -le 5 ]]; then
        print_pass "TWGCB-01-012-0218: 帳戶鎖定閾值 (deny) 為 $DENY，符合 1-5 次要求。"
    else
        print_fail "TWGCB-01-012-0218: 帳戶鎖定閾值 (deny) 為 $DENY，應設定為 1-5 次。"
    fi
    
    # TWGCB-01-012-0219: 帳戶鎖定時間
    UNLOCK_TIME=$(grep '^\s*unlock_time' /etc/security/faillock.conf | awk -F= '{print $2}' | xargs)
    if [[ "$UNLOCK_TIME" -ge 900 ]]; then
        print_pass "TWGCB-01-012-0219: 帳戶鎖定時間 (unlock_time) 為 $UNLOCK_TIME 秒，符合 >= 900 要求。"
    else
        print_fail "TWGCB-01-012-0219: 帳戶鎖定時間 (unlock_time) 為 $UNLOCK_TIME 秒，應 >= 900。"
    fi

    # TWGCB-01-012-0310: 鎖定原則同樣套用 root (even_deny_root)
    if grep -qE '^\s*even_deny_root' /etc/security/faillock.conf 2>/dev/null; then
        print_pass "TWGCB-01-012-0310: faillock 已設定 even_deny_root，鎖定原則套用至 root。"
    else
        print_fail "TWGCB-01-012-0310: faillock 未設定 even_deny_root，應於 /etc/security/faillock.conf 加入。"
    fi

    # TWGCB-01-012-0311: 通行碼最大連續字元數 (maxsequence)
    MAXSEQ=$(grep -E '^\s*maxsequence' /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | xargs)
    if [[ "$MAXSEQ" =~ ^[0-9]+$ && "$MAXSEQ" -gt 0 && "$MAXSEQ" -le 3 ]]; then
        print_pass "TWGCB-01-012-0311: 通行碼最大連續字元數 (maxsequence) 為 $MAXSEQ，符合 1-3 要求。"
    else
        print_fail "TWGCB-01-012-0311: 通行碼最大連續字元數 (maxsequence) 為 '${MAXSEQ:-未設定}'，應設定為 1-3。"
    fi

    print_header "帳號與存取控制 (2/2)"
    # TWGCB-01-012-0222: 通行碼最短使用期限
    PASS_MIN_DAYS=$(grep '^\s*PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}')
    if [[ "$PASS_MIN_DAYS" -ge 1 ]]; then
        print_pass "TWGCB-01-012-0222: 通行碼最短使用期限為 $PASS_MIN_DAYS 天，符合 >= 1 要求。"
    else
        print_fail "TWGCB-01-012-0222: 通行碼最短使用期限為 $PASS_MIN_DAYS 天，應 >= 1。"
    fi
    print_info "TWGCB-01-012-0222: 提醒：此設定對既有使用者需使用 'chage' 指令個別設定。"

    # TWGCB-01-012-0224: 通行碼最長使用期限
    PASS_MAX_DAYS=$(grep '^\s*PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
    if [[ "$PASS_MAX_DAYS" -le 90 && "$PASS_MAX_DAYS" -gt 0 ]]; then
        print_pass "TWGCB-01-012-0224: 通行碼最長使用期限為 $PASS_MAX_DAYS 天，符合 1-90 天要求。"
    else
        print_fail "TWGCB-01-012-0224: 通行碼最長使用期限為 $PASS_MAX_DAYS 天，應設定在 1-90 天內。"
    fi
    print_info "TWGCB-01-012-0224: 提醒：此設定對既有使用者需使用 'chage' 指令個別設定。"

    # TWGCB-01-012-0235: Bash shell 閒置登出時間
    TMOUT_VAL=$(grep -E '^\s*readonly TMOUT=' /etc/profile /etc/bashrc 2>/dev/null | tail -1 | grep -o '[0-9]*')
    if [[ "$TMOUT_VAL" -gt 0 && "$TMOUT_VAL" -le 900 ]]; then
        print_pass "TWGCB-01-012-0235: Bash shell 閒置登出時間為 $TMOUT_VAL 秒，符合 1-900 秒要求。"
    else
        print_fail "TWGCB-01-012-0235: Bash shell 閒置登出時間未設定或不符要求 (目前: $TMOUT_VAL)，應設定在 1-900 秒內。"
    fi

    # TWGCB-01-012-0238: 使用者帳號預設 umask
    UMASK_VAL=$(grep '^\s*umask' /etc/profile /etc/bashrc | tail -n1 | awk '{print $2}')
    if [[ "$UMASK_VAL" == "027" || "$UMASK_VAL" == "077" ]]; then
        print_pass "TWGCB-01-012-0238: 使用者預設 umask 為 $UMASK_VAL，符合 027 或更嚴格要求。"
    else
        print_fail "TWGCB-01-012-0238: 使用者預設 umask 為 $UMASK_VAL，應為 027 或更嚴格。"
    fi

    # TWGCB-01-012-0221: 通行碼雜湊演算法為 SHA512
    ENCRYPT=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [[ "$ENCRYPT" == "SHA512" ]]; then
        print_pass "TWGCB-01-012-0221: /etc/login.defs ENCRYPT_METHOD 已設為 SHA512。"
    else
        print_fail "TWGCB-01-012-0221: /etc/login.defs ENCRYPT_METHOD 為 '${ENCRYPT:-未設定}'，應為 SHA512。"
    fi

    # TWGCB-01-012-0308: rsyslog logrotate 設定
    if [ -f /etc/logrotate.d/rsyslog ]; then
        if grep -qE '^\s*(weekly|daily|monthly)' /etc/logrotate.d/rsyslog && \
           grep -qE '^\s*rotate\s+[0-9]+' /etc/logrotate.d/rsyslog; then
            print_pass "TWGCB-01-012-0308: /etc/logrotate.d/rsyslog 已設定 logrotate 規則。"
        else
            print_fail "TWGCB-01-012-0308: /etc/logrotate.d/rsyslog 缺少必要之 rotate 設定。"
        fi
    else
        print_fail "TWGCB-01-012-0308: /etc/logrotate.d/rsyslog 不存在，未啟用 rsyslog logrotate。"
    fi

    # TWGCB-01-012-0309: root 預設 umask
    ROOT_UMASK=""
    for f in /root/.bashrc /root/.bash_profile; do
        if [ -f "$f" ]; then
            ROOT_UMASK=$(grep -E '^\s*umask\s+0?27' "$f" | tail -n1 | awk '{print $2}')
            [ -n "$ROOT_UMASK" ] && break
        fi
    done
    if [[ "$ROOT_UMASK" == "027" || "$ROOT_UMASK" == "077" ]]; then
        print_pass "TWGCB-01-012-0309: root 預設 umask 為 $ROOT_UMASK，符合要求。"
    else
        print_fail "TWGCB-01-012-0309: root 之 /root/.bashrc 或 /root/.bash_profile 未設定 umask 027/077。"
    fi

    # TWGCB-01-012-0312: 啟用 authselect without-nullok 功能
    if command -v authselect &>/dev/null; then
        if authselect list-features "$(authselect current 2>/dev/null | awk -F: '/Profile ID/{print $2}' | xargs)" 2>/dev/null | grep -qE '^\s*-?\s*without-nullok' && \
           authselect current 2>/dev/null | grep -qE 'without-nullok'; then
            print_pass "TWGCB-01-012-0312: authselect 已啟用 without-nullok 功能。"
        elif authselect current 2>/dev/null | grep -qE 'without-nullok'; then
            print_pass "TWGCB-01-012-0312: authselect 已啟用 without-nullok 功能。"
        else
            print_fail "TWGCB-01-012-0312: authselect 未啟用 without-nullok。請執行: authselect enable-feature without-nullok"
        fi
    else
        print_info "TWGCB-01-012-0312: 系統未安裝 authselect，無法檢查。"
    fi
}

# SSH 伺服器
check_ssh() {
    print_header "SSH 伺服器"
    SSHD_CONFIG="/etc/ssh/sshd_config"

    if [ ! -f "$SSHD_CONFIG" ]; then
        print_fail "SSH 伺服器設定檔 $SSHD_CONFIG 不存在。"
        return
    fi
    
    # TWGCB-01-012-0255: SSH 協定版本
    grep -qE "^\s*Protocol\s+2" "$SSHD_CONFIG" && print_pass "TWGCB-01-012-0255: SSH 協定版本已設為 2。" || print_fail "TWGCB-01-012-0255: SSH 協定版本未設為 2。"

    # TWGCB-01-012-0256 & 0257: sshd_config 檔案權限
    check_file_perms_owner "TWGCB-01-012-0256/57" "$SSHD_CONFIG" "600" "root:root"

    # TWGCB-01-012-0266: SSH MaxAuthTries
    MAX_AUTH_TRIES=$(grep -iE "^\s*MaxAuthTries" "$SSHD_CONFIG" | awk '{print $2}')
    if [[ "$MAX_AUTH_TRIES" -gt 0 && "$MAX_AUTH_TRIES" -le 4 ]]; then
        print_pass "TWGCB-01-012-0266: SSH MaxAuthTries 為 $MAX_AUTH_TRIES，符合 1-4 次要求。"
    else
        print_fail "TWGCB-01-012-0266: SSH MaxAuthTries 為 $MAX_AUTH_TRIES，應為 1-4 次。"
    fi

    # TWGCB-01-012-0269: SSH PermitRootLogin
    grep -qE "^\s*PermitRootLogin\s+no" "$SSHD_CONFIG" && print_pass "TWGCB-01-012-0269: SSH PermitRootLogin 已設為 no。" || print_fail "TWGCB-01-012-0269: SSH PermitRootLogin 未設為 no。"
    
    # TWGCB-01-012-0270: SSH PermitEmptyPasswords
    grep -qE "^\s*PermitEmptyPasswords\s+no" "$SSHD_CONFIG" && print_pass "TWGCB-01-012-0270: SSH PermitEmptyPasswords 已設為 no。" || print_fail "TWGCB-01-012-0270: SSH PermitEmptyPasswords 未設為 no。"

    # TWGCB-01-012-0272: SSH 逾時時間 (v1.2 修改)
    ALIVE_INTERVAL=$(grep -iE "^\s*ClientAliveInterval" "$SSHD_CONFIG" | awk '{print $2}')
    ALIVE_COUNT_MAX=$(grep -iE "^\s*ClientAliveCountMax" "$SSHD_CONFIG" | awk '{print $2}')
    if [[ "$ALIVE_INTERVAL" -gt 0 && "$ALIVE_INTERVAL" -le 600 && "$ALIVE_COUNT_MAX" -eq 1 ]]; then
        print_pass "TWGCB-01-012-0272: SSH 逾時時間設定符合要求 (Interval: $ALIVE_INTERVAL, CountMax: $ALIVE_COUNT_MAX)。"
    else
        print_fail "TWGCB-01-012-0272: SSH 逾時時間設定不符要求 (Interval: $ALIVE_INTERVAL, CountMax: $ALIVE_COUNT_MAX)。應為 Interval <= 600 且 CountMax = 1。"
    fi

    # TWGCB-01-012-0274: SSH UsePAM
    grep -qE "^\s*UsePAM\s+yes" "$SSHD_CONFIG" && print_pass "TWGCB-01-012-0274: SSH UsePAM 已設為 yes。" || print_fail "TWGCB-01-012-0274: SSH UsePAM 未設為 yes。"

    # TWGCB-01-012-0315: 停用 GSSAPI 驗證
    if grep -qE "^\s*GSSAPIAuthentication\s+no" "$SSHD_CONFIG"; then
        print_pass "TWGCB-01-012-0315: SSH GSSAPIAuthentication 已設為 no。"
    else
        print_fail "TWGCB-01-012-0315: SSH GSSAPIAuthentication 未設為 no (預設為 yes)。"
    fi
}

print_summary() {
    local total_checks=$((PASS_COUNT + FAIL_COUNT))
    local pass_rate="0.00"
    local fail_rate="0.00"

    if [ $total_checks -gt 0 ]; then
        pass_rate=$(printf "%.2f" $(echo "scale=4; ($PASS_COUNT / $total_checks) * 100" | bc))
        fail_rate=$(printf "%.2f" $(echo "scale=4; ($FAIL_COUNT / $total_checks) * 100" | bc))
    fi

    local summary
    summary="\n==============================================================================\n"
    summary+="檢測完成。統計摘要如下：\n"
    summary+="------------------------------------------------------------------------------\n"
    summary+=$(printf "通過項目: %-5s  |  未通過項目: %-5s  |  跳過項目: %-5s\n" "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT")
    summary+=$(printf "完成比率: %-5s%% |  未完成比率: %-5s%%\n" "$pass_rate" "$fail_rate")
    summary+="------------------------------------------------------------------------------\n"
    summary+="詳細報告已儲存至: ${C_YELLOW}${LOG_FILE}${C_RESET}\n"
    summary+="請檢視以上標示為 [${C_RED}FAIL${C_RESET}] 的項目，並根據 GCB 文件進行修正。\n"
    summary+="=============================================================================="

    echo -e "$summary"
    # Log summary without color codes
    echo -e "$(strip_colors "$summary")" >> "$LOG_FILE"
}

# ==============================================================================
# --- 主函式執行 ---
# ==============================================================================
main() {
    echo "=============================================================================="
    echo "開始檢測 RHEL 9 政府組態基準 (TWGCB-01-012 v1.2)"
    echo "日誌檔案將儲存於: $LOG_FILE"
    echo "=============================================================================="
    
    check_filesystem
    check_system_settings
    check_services
    check_software
    check_network
    check_selinux
    check_cron
    check_accounts
    check_ssh

    print_summary
}

main
