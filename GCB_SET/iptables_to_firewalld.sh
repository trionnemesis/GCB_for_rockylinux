#!/bin/bash

# ===================================================================================
# Advanced iptables to firewalld Migration & Automation Script
#
# 版本：2.0
# 功能：
# 1. 解析 iptables 規則檔案。
# 2. 自動將可識別的規則 (INPUT -p tcp/udp --dport) 轉換為 firewalld 指令。
# 3. 識別並列出無法自動轉換的規則，供使用者手動處理。
# 4. 在使用者確認後，執行轉換、停用 iptables 並啟用 firewalld。
#
# !!! 警告 - 高風險操作 !!!
# 此腳本會直接修改系統的防火牆和服務配置。
# 請務必在執行前備份規則，並確保您有伺服器的帶外管理權限（如 KVM）。
# 強烈建議先在測試環境中運行。
# ===================================================================================

# --- 設定 ---

# 指定要將規則加入到哪個 firewalld zone。
TARGET_ZONE="public"

# 從腳本的第一個參數讀取 iptables 規則檔案路徑。
IPTABLES_RULES_FILE=$1

# 暫存檔案，用於存放產生的指令和無法轉換的規則
TIMESTAMP=$(date +%s)
CONVERTED_COMMANDS_FILE="/tmp/firewalld_commands_${TIMESTAMP}.sh"
UNCONVERTED_RULES_FILE="/tmp/unconverted_rules_${TIMESTAMP}.log"

# --- 函式定義 ---

# 函式：輸出帶有顏色的訊息
print_info() {
    echo -e "\n\033[1;34m[資訊] $1\033[0m"
}

print_warning() {
    echo -e "\033[1;33m[警告] $1\033[0m"
}

print_error() {
    echo -e "\033[1;31m[錯誤] $1\033[0m" >&2
}

print_success() {
    echo -e "\033[1;32m[成功] $1\033[0m"
}

# --- 腳本開始 ---

# 檢查是否以 root 權限執行
if [ "$(id -u)" -ne 0 ]; then
    print_error "此腳本需要 root 權限來修改防火牆和系統服務。請使用 sudo 執行。"
    exit 1
fi

# 檢查是否提供了規則檔案作為參數
if [ -z "$IPTABLES_RULES_FILE" ]; then
    print_error "缺少 iptables 規則檔案路徑。"
    echo "用法: sudo $0 /path/to/your/iptables.rules"
    exit 1
fi

# 檢查規則檔案是否存在
if [ ! -f "$IPTABLES_RULES_FILE" ]; then
    print_error "檔案不存在: $IPTABLES_RULES_FILE"
    exit 1
fi

# 初始化暫存檔案
echo "#!/bin/bash" > "$CONVERTED_COMMANDS_FILE"
echo "# 自動產生的 firewalld 轉換指令" >> "$CONVERTED_COMMANDS_FILE"
chmod +x "$CONVERTED_COMMANDS_FILE"

> "$UNCONVERTED_RULES_FILE"

print_info "開始解析檔案: $IPTABLES_RULES_FILE..."

# --- 規則解析 ---

unconverted_count=0
converted_count=0

while IFS= read -r line; do
    # 忽略空行和註解行
    if [[ -z "$line" ]] || [[ "$line" =~ ^# ]] || [[ "$line" =~ ^: ]] || [[ "$line" =~ ^\* ]] || [[ "$line" =~ ^COMMIT ]]; then
        continue
    fi

    # 嘗試解析簡單的 INPUT allow 規則
    # 範例: -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
    if [[ "$line" =~ -A\ INPUT ]] && [[ "$line" =~ -j\ ACCEPT ]] && [[ "$line" =~ --dport ]]; then
        protocol=$(echo "$line" | grep -oP '(-p|--protocol)\s+\K\w+')
        port=$(echo "$line" | grep -oP '--dport\s+\K\w+')

        if [ -n "$protocol" ] && [ -n "$port" ]; then
            # 這是我們能處理的規則
            echo "firewall-cmd --zone=${TARGET_ZONE} --add-port=${port}/${protocol} --permanent # 來源: $line" >> "$CONVERTED_COMMANDS_FILE"
            ((converted_count++))
        else
            # 雖然符合大規則，但無法提取 port/protocol，標記為無法轉換
            echo "$line" >> "$UNCONVERTED_RULES_FILE"
            ((unconverted_count++))
        fi
    else
        # 所有其他規則（FORWARD, NAT, -s, 自訂鏈等）都標記為無法轉換
        echo "$line" >> "$UNCONVERTED_RULES_FILE"
        ((unconverted_count++))
    fi
done < "$IPTABLES_RULES_FILE"

# --- 結果預覽與使用者確認 ---

clear
echo "======================================================="
echo "                iptables 轉換預覽"
echo "======================================================="
echo

print_info "共找到 $converted_count 條可自動轉換的規則。"
if [ $converted_count -gt 0 ]; then
    echo "以下 firewalld 指令將被執行："
    echo "-------------------------------------------------------"
    cat "$CONVERTED_COMMANDS_FILE" | grep 'firewall-cmd'
    echo "-------------------------------------------------------"
fi

echo

if [ $unconverted_count -gt 0 ]; then
    print_warning "共找到 $unconverted_count 條「無法」自動轉換的規則。"
    print_warning "這些規則需要您手動處理！規則已儲存至: $UNCONVERTED_RULES_FILE"
    echo "-------------------------------------------------------"
    cat "$UNCONVERTED_RULES_FILE"
    echo "-------------------------------------------------------"
    print_warning "常見無法轉換原因：NAT 規則、FORWARD 鏈、來源 IP (-s) 限制、自訂鏈等。"
else
    print_success "所有規則似乎都已成功轉換！"
fi

echo
echo "======================================================="
print_info "接下來，腳本將執行以下系統層級的操作："
echo " 1. 執行上面列出的 'firewall-cmd' 指令。"
echo " 2. 執行 'firewall-cmd --reload' 使新規則生效。"
echo " 3. 停止並禁用 'iptables' 和 'ip6tables' 服務。"
echo " 4. 啟用並啟動 'firewalld' 服務。"
echo "======================================================="
echo

# 最後的確認
read -p $'\033[1;33m您是否確認要繼續執行這些操作？ (yes/no): \033[0m' user_confirmation

if [ "$user_confirmation" != "yes" ]; then
    print_error "操作已取消。"
    # 清理暫存檔案
    rm -f "$CONVERTED_COMMANDS_FILE" "$UNCONVERTED_RULES_FILE"
    exit 0
fi

# --- 執行轉換與服務管理 ---

print_info "開始執行轉換..."

# 1. 執行 firewalld 指令
if [ $converted_count -gt 0 ]; then
    bash "$CONVERTED_COMMANDS_FILE"
    if [ $? -ne 0 ]; then
        print_error "執行 firewalld 指令時發生錯誤。請檢查上面的輸出。中止操作！"
        exit 1
    fi
    print_success "firewalld 規則已成功加入到 permanent 設定中。"
fi

# 2. 重新載入 firewalld
print_info "重新載入 firewalld 使規則生效..."
firewall-cmd --reload
print_success "firewalld 已重新載入。"

# 3. 停用舊的防火牆服務
print_info "停止並禁用 iptables 服務..."
systemctl stop iptables &>/dev/null
systemctl stop ip6tables &>/dev/null
systemctl disable iptables &>/dev/null
systemctl disable ip6tables &>/dev/null
print_success "iptables / ip6tables 服務已停止並禁用。"

# 4. 啟用新的防火牆服務
print_info "啟用並啟動 firewalld 服務..."
# 在某些系統上，iptables 服務會遮蔽 firewalld，需要先解除
systemctl unmask firewalld &>/dev/null
systemctl enable firewalld
systemctl start firewalld
print_success "firewalld 服務已啟用並啟動。"

echo
echo "======================================================="
print_success "防火牆轉換流程已完成！"
echo "======================================================="
if [ $unconverted_count -gt 0 ]; then
    print_warning "重要提醒：請務必手動檢查並轉換以下檔案中列出的規則："
    echo "$UNCONVERTED_RULES_FILE"
fi
print_info "建議立即驗證您的伺服器連線和服務是否正常。"
print_info "可以使用 'firewall-cmd --list-all' 來檢查目前的 firewalld 設定。"

# 清理暫存檔案
rm -f "$CONVERTED_COMMANDS_FILE"

exit 0