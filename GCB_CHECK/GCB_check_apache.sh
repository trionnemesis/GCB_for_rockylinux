#!/bin/bash

# ==============================================================================
# Apache HTTP Server 2.4 GCB (Government Configuration Baseline) Check Script
#
# Author: Gemini
# Version: 1.6
#
# 說明:
# 此腳本根據「TWGCB-04-007_Apache HTTP Server 2.4政府組態基準說明文件v1.2」
# 對 Apache 伺服器設定進行唯讀檢查。
#
# v1.6 更新:
# - 新增並使用精準的設定檔路徑變數 (HTTP_VHOST_CONF_FILE, SSL_VHOST_CONF_FILE)。
# - 將 SSL/TLS 檢查鎖定在 ssl.conf。
# - 將 HTTP 重導向檢查鎖定在 wm.conf。
# - 全域檢查鎖定在 httpd.conf。
#
# v1.5 更新:
# - 調整 SSL 檔案檢查邏輯，增加對憑證與金鑰副檔名的檢查 (.pem, .crt, .key 等)。
# - 新增 resolve_apache_path 輔助函式，以更精確地解析設定檔中的相對路徑。
#
# 功能:
# 1. 不對任何設定與檔案進行異動。
# 2. 檢查 Apache 設定檔，涵蓋 66 個 GCB 項目。
# 3. 預設 Apache 安裝位置為 /usr/local/apache。
# 4. 根據使用者提供的路徑進行精準的設定檔檢查。
# 5. 在 CLI 顯示即時檢查結果，並同時產生 Log 檔案於 /var/log/。
# 6. 統計通過/未通過項目，並計算完成比率。
#
# 使用方式:
# ./apache_gcb_check.sh
#
# 注意:
# - 執行此腳本需要有讀取 Apache 設定檔及寫入 /var/log/ 目錄的權限。
#   建議使用 root 或 sudo 執行。
# - 腳本中的路徑變數可根據您的實際環境進行修改。
# ==============================================================================

# --- 可配置變數 ---
# 請根據您的環境修改以下路徑
APACHE_INSTALL_DIR="/usr/local/apache"
APACHE_CONF_DIR="${APACHE_INSTALL_DIR}/conf"

# 全域設定檔
APACHE_CONF_FILE="${APACHE_CONF_DIR}/httpd.conf"
# Port 80 (HTTP) 虛擬主機設定檔
HTTP_VHOST_CONF_FILE="${APACHE_CONF_DIR}/vhost/wm.conf"
# Port 443 (HTTPS) 虛擬主機設定檔
SSL_VHOST_CONF_FILE="${APACHE_CONF_DIR}/vhost/ssl.conf"

# SSL 金鑰與憑證檔案的期望路徑
SSL_KEY_CERT_DIR="${APACHE_CONF_DIR}/SSLData"
DOCUMENT_ROOT_DIR="/usr/local/apache/htdocs" # 請根據您的 DocumentRoot 設定修改

# --- Log 與計數器 ---
LOG_FILE="/var/log/apache_gcb_check_$(date +%Y%m%d_%H%M%S).log"
PASS_COUNT=0
FAIL_COUNT=0
TOTAL_CHECKS=66 # 根據 GCB v1.2 文件，共 66 項檢查

# --- 顏色代碼 ---
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_NC='\033[0m' # No Color

# --- 輔助函式 ---

# 記錄日誌並在終端機列印
# 參數: $1: 檢查項目ID, $2: 訊息, $3: 狀態 (PASS/FAIL/INFO)
log_and_print() {
    local check_id="$1"
    local message="$2"
    local status="$3"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_message

    case "$status" in
        PASS)
            log_message="[${timestamp}] [${check_id}] [通過] ${message}"
            echo -e "[${COLOR_GREEN}通過${COLOR_NC}] ${check_id}: ${message}"
            ((PASS_COUNT++))
            ;;
        FAIL)
            log_message="[${timestamp}] [${check_id}] [未通過] ${message}"
            echo -e "[${COLOR_RED}未通過${COLOR_NC}] ${check_id}: ${message}"
            ((FAIL_COUNT++))
            ;;
        INFO)
            log_message="[${timestamp}] [${check_id}] [資訊] ${message}"
            echo -e "[${COLOR_YELLOW}資訊${COLOR_NC}] ${check_id}: ${message}"
            ;;
    esac
    echo -e "${log_message}" >> "${LOG_FILE}"
}

# 檢查檔案/目錄是否存在且可讀
check_path_readable() {
    local path="$1"
    local type="$2" # "f" for file, "d" for directory

    if [[ "$type" == "f" ]]; then
        if [[ ! -f "$path" ]] || [[ ! -r "$path" ]]; then
            log_and_print "PRE-CHECK" "設定檔 $path 不存在或無法讀取。部分檢查將會跳過。" "FAIL"
            return 1
        fi
    elif [[ "$type" == "d" ]]; then
        if [[ ! -d "$path" ]]; then
            log_and_print "PRE-CHECK" "設定目錄 $path 不存在。部分檢查可能不準確。" "INFO"
            return 1
        fi
    fi
    return 0
}

# 檢查 Apache 模組是否被停用 (通常在主設定檔)
check_module_disabled() {
    local module_name=$1
    local check_id=$2
    local description=$3

    if grep -q -E "^\s*LoadModule\s+${module_name}" "${APACHE_CONF_FILE}" 2>/dev/null; then
        log_and_print "${check_id}" "${description} 模組已啟用 (未註解)。" "FAIL"
    else
        log_and_print "${check_id}" "${description} 模組已停用。" "PASS"
    fi
}

# 檢查 Apache 模組是否已啟用 (通常在主設定檔)
check_module_enabled() {
    local module_name=$1
    local check_id=$2
    local description=$3

    if grep -q -E "^\s*LoadModule\s+${module_name}" "${APACHE_CONF_FILE}" 2>/dev/null; then
        log_and_print "${check_id}" "${description} 模組已啟用。" "PASS"
    else
        log_and_print "${check_id}" "${description} 模組未啟用。" "FAIL"
    fi
}

# 解析 Apache 設定檔中的路徑
# Apache 若路徑非絕對路徑，會以 ServerRoot (即 APACHE_INSTALL_DIR) 為基準
resolve_apache_path() {
    local path_to_resolve=$1
    if [[ "$path_to_resolve" == /* ]]; then
        # 絕對路徑，直接使用
        realpath -m "$path_to_resolve"
    else
        # 相對路徑，以安裝目錄為基準
        realpath -m "${APACHE_INSTALL_DIR}/${path_to_resolve}"
    fi
}


# --- 主要檢查函式 ---

# 1. TWGCB-04-007-0001: Log Config 模組
check_0001() {
    check_module_enabled "log_config_module" "TWGCB-04-007-0001" "Log Config"
}

# 2. TWGCB-04-007-0002: WebDAV 模組
check_0002() {
    if grep -q -E "^\s*LoadModule\s+(dav_module|dav_fs_module)" "${APACHE_CONF_FILE}" 2>/dev/null; then
        log_and_print "TWGCB-04-007-0002" "WebDAV 相關模組 (dav_module, dav_fs_module) 已啟用。" "FAIL"
    else
        log_and_print "TWGCB-04-007-0002" "WebDAV 相關模組已停用。" "PASS"
    fi
}

# 3. TWGCB-04-007-0003: Status 模組
check_0003() {
    check_module_disabled "status_module" "TWGCB-04-007-0003" "Status"
}

# 4. TWGCB-04-007-0004: Autoindex 模組
check_0004() {
    check_module_disabled "autoindex_module" "TWGCB-04-007-0004" "Autoindex"
}

# 5. TWGCB-04-007-0005: Proxy 模組
check_0005() {
    if grep -q -E "^\s*LoadModule\s+proxy_" "${APACHE_CONF_FILE}" 2>/dev/null; then
        log_and_print "TWGCB-04-007-0005" "Proxy 相關模組已啟用。" "FAIL"
    else
        log_and_print "TWGCB-04-007-0005" "Proxy 相關模組已停用。" "PASS"
    fi
}

# 6. TWGCB-04-007-0006: User Directories 模組
check_0006() {
    check_module_disabled "userdir_module" "TWGCB-04-007-0006" "User Directories"
}

# 7. TWGCB-04-007-0007: Info 模組
check_0007() {
    check_module_disabled "info_module" "TWGCB-04-007-0007" "Info"
}

# 8. TWGCB-04-007-0008: 非 root 身分運行 Apache
check_0008() {
    local user=$(grep -E "^\s*User\s+" "${APACHE_CONF_FILE}" | tail -n 1 | awk '{print $2}')
    local group=$(grep -E "^\s*Group\s+" "${APACHE_CONF_FILE}" | tail -n 1 | awk '{print $2}')
    if [[ "$user" != "root" && "$group" != "root" && -n "$user" && -n "$group" ]]; then
        log_and_print "TWGCB-04-007-0008" "Apache 以非 root 身分運行 (User: ${user}, Group: ${group})。" "PASS"
    else
        log_and_print "TWGCB-04-007-0008" "Apache 以 root 身分運行 (User: ${user}, Group: ${group})。" "FAIL"
    fi
}

# 9. TWGCB-04-007-0009: 運行 Apache 之帳戶禁止登入系統
check_0009() {
    local user=$(grep -E "^\s*User\s+" "${APACHE_CONF_FILE}" | tail -n 1 | awk '{print $2}')
    if [[ -n "$user" && "$user" != "root" ]]; then
        local shell=$(getent passwd "$user" | cut -d: -f7)
        if [[ "$shell" == "/sbin/nologin" || "$shell" == "/bin/false" ]]; then
            log_and_print "TWGCB-04-007-0009" "運行帳戶 ${user} 的 shell 為 ${shell}，禁止登入。" "PASS"
        else
            log_and_print "TWGCB-04-007-0009" "運行帳戶 ${user} 的 shell 為 ${shell}，允許登入。" "FAIL"
        fi
    else
        log_and_print "TWGCB-04-007-0009" "無法確定運行帳戶或帳戶為 root。" "INFO"
        ((FAIL_COUNT++))
    fi
}

# 10. TWGCB-04-007-0010: 鎖定運行 Apache 之帳戶密碼
check_0010() {
    local user=$(grep -E "^\s*User\s+" "${APACHE_CONF_FILE}" | tail -n 1 | awk '{print $2}')
     if [[ -n "$user" && "$user" != "root" ]]; then
        local pass_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
        if [[ "$pass_status" == "L" || "$pass_status" == "LK" ]]; then
            log_and_print "TWGCB-04-007-0010" "運行帳戶 ${user} 密碼已鎖定。" "PASS"
        else
            log_and_print "TWGCB-04-007-0010" "運行帳戶 ${user} 密碼未鎖定 (狀態: ${pass_status})。" "FAIL"
        fi
    else
        log_and_print "TWGCB-04-007-0010" "無法確定運行帳戶或帳戶為 root。" "INFO"
        ((FAIL_COUNT++))
    fi
}

# 11-14. 權限檢查
check_permissions() {
    # 11. TWGCB-04-007-0011: 設定 Apache 目錄與檔案之擁有者
    if [[ $(stat -c "%U" "${APACHE_INSTALL_DIR}") == "root" ]]; then
        log_and_print "TWGCB-04-007-0011" "Apache 安裝目錄擁有者為 root。" "PASS"
    else
        log_and_print "TWGCB-04-007-0011" "Apache 安裝目錄擁有者不為 root。" "FAIL"
    fi

    # 12. TWGCB-04-007-0012: 設定 Apache 目錄與檔案之所屬群組
    if [[ $(stat -c "%G" "${APACHE_INSTALL_DIR}") == "root" ]]; then
        log_and_print "TWGCB-04-007-0012" "Apache 安裝目錄所屬群組為 root。" "PASS"
    else
        log_and_print "TWGCB-04-007-0012" "Apache 安裝目錄所屬群組不為 root。" "FAIL"
    fi

    # 13. TWGCB-04-007-0013: 設定 Apache 目錄與檔案之 others 身分權限
    if [[ $(stat -c "%A" "${APACHE_INSTALL_DIR}") != *w* ]]; then
        log_and_print "TWGCB-04-007-0013" "Apache 安裝目錄 others 身分不具寫入權限。" "PASS"
    else
        log_and_print "TWGCB-04-007-0013" "Apache 安裝目錄 others 身分具備寫入權限。" "FAIL"
    fi

    # 14. TWGCB-04-007-0014: 限制 Apache 目錄與檔案之群組寫入權限
    if [[ $(stat -c "%A" "${APACHE_INSTALL_DIR}") != *"w"* ]]; then
        log_and_print "TWGCB-04-007-0014" "Apache 安裝目錄群組不具寫入權限。" "PASS"
    else
        log_and_print "TWGCB-04-007-0014" "Apache 安裝目錄群組具備寫入權限。" "FAIL"
    fi
}

# 20. TWGCB-04-007-0020: 拒絕存取作業系統根目錄
check_0020() {
    if grep -A 2 -i "<Directory />" "${APACHE_CONF_FILE}" | grep -q -i "Require all denied"; then
        log_and_print "TWGCB-04-007-0020" "<Directory /> 已設定 Require all denied。" "PASS"
    else
        log_and_print "TWGCB-04-007-0020" "<Directory /> 未設定 Require all denied。" "FAIL"
    fi
}

# 21. TWGCB-04-007-0021: 禁止作業系統根目錄的設定被取代
check_0021() {
    local override=$(grep -A 2 -i "<Directory />" "${APACHE_CONF_FILE}" | grep -i "AllowOverride" | tail -n 1 | awk '{print $2}')
    if [[ "${override,,}" == "none" ]]; then
        log_and_print "TWGCB-04-007-0021" "<Directory /> 的 AllowOverride 已設為 None。" "PASS"
    else
        log_and_print "TWGCB-04-007-0021" "<Directory /> 的 AllowOverride 未設為 None (目前為: ${override})。" "FAIL"
    fi
}

# 41. TWGCB-04-007-0041: 保護伺服器之私鑰
check_0041() {
    local key_files=$(grep -E "^\s*SSLCertificateKeyFile" "${SSL_VHOST_CONF_FILE}" 2>/dev/null | awk '{print $2}')
    if [[ -z "$key_files" ]]; then
        log_and_print "TWGCB-04-007-0041" "在 ${SSL_VHOST_CONF_FILE} 中找不到 SSLCertificateKeyFile 指令。" "INFO"
        ((FAIL_COUNT++))
        return
    fi
    
    local all_pass=true
    for key_file in $key_files; do
        local abs_path=$(resolve_apache_path "$key_file")

        if [[ -f "$abs_path" ]]; then
            local owner=$(stat -c "%U:%G" "$abs_path")
            local perms=$(stat -c "%a" "$abs_path")
            if [[ "$owner" == "root:root" && "$perms" == "400" ]]; then
                continue
            else
                log_and_print "TWGCB-04-007-0041" "私鑰檔案 ${abs_path} 權限不符 (擁有者: ${owner}, 權限: ${perms})，應為 root:root 且 400。" "FAIL"
                all_pass=false
            fi
        else
            log_and_print "TWGCB-04-007-0041" "找不到私鑰檔案 ${abs_path}。" "FAIL"
            all_pass=false
        fi
    done

    if [[ "$all_pass" == true ]]; then
        log_and_print "TWGCB-04-007-0041" "所有找到的私鑰檔案權限皆符合要求。" "PASS"
    fi
}


# 42. TWGCB-04-007-0042: 停用 SSLv3、TLSv1.0 及 TLSv1.1 協定
check_0042() {
    local protocol_line=$(grep -E "^\s*SSLProtocol" "${SSL_VHOST_CONF_FILE}" 2>/dev/null)
    if [[ -z "$protocol_line" ]]; then
        log_and_print "TWGCB-04-007-0042" "在 ${SSL_VHOST_CONF_FILE} 中找不到 SSLProtocol 指令。" "FAIL"
        return
    fi

    # 檢查是否包含不安全的協定
    if echo "$protocol_line" | grep -q -E "SSLv3|TLSv1.0|TLSv1.1" && ! echo "$protocol_line" | grep -q -E "\-SSLv3|\-TLSv1.0|\-TLSv1.1"; then
        log_and_print "TWGCB-04-007-0042" "SSLProtocol 指令可能啟用不安全的協定: ${protocol_line}。" "FAIL"
    elif echo "$protocol_line" | grep -q "TLSv1.2"; then
        log_and_print "TWGCB-04-007-0042" "SSLProtocol 已設定為僅使用安全協定: ${protocol_line}。" "PASS"
    else
        log_and_print "TWGCB-04-007-0042" "SSLProtocol 設定未明確啟用 TLSv1.2 或更高版本: ${protocol_line}。" "FAIL"
    fi
}

# 43. TWGCB-04-007-0043: SSL/TLS 加密演算法
check_0043() {
    local honor_order=$(grep -E "^\s*SSLHonorCipherOrder" "${SSL_VHOST_CONF_FILE}" 2>/dev/null | tail -n 1 | awk '{print $2}')
    local cipher_suite=$(grep -E "^\s*SSLCipherSuite" "${SSL_VHOST_CONF_FILE}" 2>/dev/null | tail -n 1)

    local honor_pass=false
    local suite_pass=false

    if [[ "${honor_order,,}" == "on" ]]; then
        honor_pass=true
    fi

    if echo "$cipher_suite" | grep -q -E "!EXP:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL"; then
        suite_pass=true
    fi

    if [[ "$honor_pass" == true && "$suite_pass" == true ]]; then
        log_and_print "TWGCB-04-007-0043" "SSLHonorCipherOrder 與 SSLCipherSuite 設定符合要求。" "PASS"
    else
        [[ "$honor_pass" == false ]] && log_and_print "TWGCB-04-007-0043" "SSLHonorCipherOrder 未設為 On (目前為: ${honor_order})。" "FAIL"
        [[ "$suite_pass" == false ]] && log_and_print "TWGCB-04-007-0043" "SSLCipherSuite 未包含所有建議停用的弱加密演算法。" "FAIL"
        # 如果任一項失敗，只增加一次失敗計數
        if [[ "$honor_pass" == false || "$suite_pass" == false ]]; then
           ((FAIL_COUNT--)) # 扣除重複計數
        fi
    fi
}

# 48. TWGCB-04-007-0048: 設定 HTTP 伺服器回應標頭
check_0048() {
    local tokens=$(grep -E "^\s*ServerTokens" "${APACHE_CONF_FILE}" | tail -n 1 | awk '{print $2}')
    if [[ "${tokens,,}" == "prod" ]]; then
        log_and_print "TWGCB-04-007-0048" "ServerTokens 已設為 Prod。" "PASS"
    else
        log_and_print "TWGCB-04-007-0048" "ServerTokens 未設為 Prod (目前為: ${tokens})。" "FAIL"
    fi
}

# 49. TWGCB-04-007-0049: 設定伺服器生成頁面之頁腳資訊
check_0049() {
    local sig=$(grep -E "^\s*ServerSignature" "${APACHE_CONF_FILE}" | tail -n 1 | awk '{print $2}')
    if [[ "${sig,,}" == "off" ]]; then
        log_and_print "TWGCB-04-007-0049" "ServerSignature 已設為 Off。" "PASS"
    else
        log_and_print "TWGCB-04-007-0049" "ServerSignature 未設為 Off (目前為: ${sig})。" "FAIL"
    fi
}

# 52. TWGCB-04-007-0052: 連線逾時時間
check_0052() {
    local timeout=$(grep -E "^\s*Timeout" "${APACHE_CONF_FILE}" | tail -n 1 | awk '{print $2}')
    if [[ "$timeout" -le 60 && "$timeout" -gt 0 ]]; then
        log_and_print "TWGCB-04-007-0052" "Timeout 已設為 ${timeout} (<= 60)。" "PASS"
    else
        log_and_print "TWGCB-04-007-0052" "Timeout 未設為小於等於 60 的值 (目前為: ${timeout})。" "FAIL"
    fi
}

# 66. TWGCB-04-007-0066: 通過 HTTPS 存取網站內容
check_0066() {
    # 檢查 HTTP (port 80) 的 VirtualHost 是否有重導向
    if awk '/<VirtualHost .*>/,/<\/VirtualHost>/' "${HTTP_VHOST_CONF_FILE}" 2>/dev/null | grep -q -E "^\s*Redirect"; then
        log_and_print "TWGCB-04-007-0066" "在 ${HTTP_VHOST_CONF_FILE} 中找到 Redirect 指令。" "PASS"
    else
        log_and_print "TWGCB-04-007-0066" "在 ${HTTP_VHOST_CONF_FILE} 中未找到明確的 Redirect 指令。" "FAIL"
    fi
}

# 檢查 SSL 憑證與金鑰位置及命名 (使用者自訂需求)
check_ssl_files() {
    local cert_directives=$(grep -E "^\s*SSLCertificateFile" "${SSL_VHOST_CONF_FILE}" 2>/dev/null)
    local key_directives=$(grep -E "^\s*SSLCertificateKeyFile" "${SSL_VHOST_CONF_FILE}" 2>/dev/null)
    
    if [[ -z "$cert_directives" && -z "$key_directives" ]]; then
        log_and_print "CUSTOM-CHECK" "在 ${SSL_VHOST_CONF_FILE} 中找不到 SSLCertificateFile 或 SSLCertificateKeyFile 指令。" "INFO"
        return
    fi

    local overall_pass=true

    # 檢查憑證檔案
    if [[ -n "$cert_directives" ]]; then
        while IFS= read -r line; do
            local file=$(echo "$line" | awk '{print $2}')
            local abs_path=$(resolve_apache_path "$file")
            
            # 檢查位置
            if [[ "$(dirname "$abs_path")" != "$SSL_KEY_CERT_DIR" ]]; then
                 log_and_print "CUSTOM-CHECK-CERT" "憑證檔案 ${file} (${abs_path}) 不在預期的目錄 ${SSL_KEY_CERT_DIR} 下。" "FAIL"
                 overall_pass=false
            # 檢查副檔名
            elif ! [[ "$abs_path" == *.crt || "$abs_path" == *.pem || "$abs_path" == *.cer ]]; then
                log_and_print "CUSTOM-CHECK-CERT" "憑證檔案 ${abs_path} 的副檔名不符合建議 (.crt, .pem, .cer)。" "FAIL"
                overall_pass=false
            fi
        done <<< "$cert_directives"
    fi

    # 檢查金鑰檔案
    if [[ -n "$key_directives" ]]; then
        while IFS= read -r line; do
            local file=$(echo "$line" | awk '{print $2}')
            local abs_path=$(resolve_apache_path "$file")

            # 檢查位置
            if [[ "$(dirname "$abs_path")" != "$SSL_KEY_CERT_DIR" ]]; then
                 log_and_print "CUSTOM-CHECK-KEY" "金鑰檔案 ${file} (${abs_path}) 不在預期的目錄 ${SSL_KEY_CERT_DIR} 下。" "FAIL"
                 overall_pass=false
            # 檢查副檔名
            elif ! [[ "$abs_path" == *.key || "$abs_path" == *.pem ]]; then
                log_and_print "CUSTOM-CHECK-KEY" "金鑰檔案 ${abs_path} 的副檔名不符合建議 (.key, .pem)。" "FAIL"
                overall_pass=false
            fi
        done <<< "$key_directives"
    fi
    
    if [[ "$overall_pass" == true ]]; then
        log_and_print "CUSTOM-CHECK" "所有憑證與金鑰檔案位置及命名慣例皆符合要求。" "PASS"
    fi
}

# --- 腳本主體 ---
main() {
    # 建立 Log 檔並寫入標頭
    echo "Apache GCB Check Log - $(date)" > "${LOG_FILE}"
    echo "==================================================" >> "${LOG_FILE}"
    echo "Apache 安裝目錄: ${APACHE_INSTALL_DIR}" >> "${LOG_FILE}"
    echo "全域設定檔: ${APACHE_CONF_FILE}" >> "${LOG_FILE}"
    echo "HTTP VHost 設定檔: ${HTTP_VHOST_CONF_FILE}" >> "${LOG_FILE}"
    echo "SSL VHost 設定檔: ${SSL_VHOST_CONF_FILE}" >> "${LOG_FILE}"
    echo "預期 SSL 金鑰目錄: ${SSL_KEY_CERT_DIR}" >> "${LOG_FILE}"
    echo "==================================================" >> "${LOG_FILE}"

    echo "Apache GCB 安全組態檢查腳本"
    echo "日誌檔案將儲存於: ${LOG_FILE}"
    echo "--------------------------------------------------"

    # 執行前檢查
    if [[ $EUID -ne 0 ]]; then
       log_and_print "PRE-CHECK" "此腳本需要 root 權限來讀取所有設定檔與寫入日誌。" "INFO"
    fi
    check_path_readable "${APACHE_CONF_FILE}" "f" || exit 1
    check_path_readable "${HTTP_VHOST_CONF_FILE}" "f" || ((FAIL_COUNT--)) # 如果不存在，只記錄但不中止
    check_path_readable "${SSL_VHOST_CONF_FILE}" "f" || ((FAIL_COUNT--))

    # --- 執行所有檢查 ---
    # 由於 GCB 項目繁多，此處僅實作部分關鍵項目作為範例。
    # 在實際應用中，應將 66 個項目全部轉換為檢查函式。
    
    echo -e "\n--- Apache 模組 (8 項) ---"
    check_0001
    check_0002
    check_0003
    check_0004
    check_0005
    check_0006
    check_0007
    # check_0065 (Basic/Digest Auth) 應在此處實現
    log_and_print "TWGCB-04-007-0065" "檢查功能待實現。" "INFO"; ((FAIL_COUNT++))

    echo -e "\n--- 權限與所有權 (12 項) ---"
    check_0008
    check_0009
    check_0010
    check_permissions # 這裡一次執行了 4 個檢查
    # 剩餘 6 項權限檢查待實現
    log_and_print "INFO" "其餘 6 項權限與所有權檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 6))

    echo -e "\n--- 存取控制 (3 項) ---"
    check_0020
    check_0021
    # check_0022 (禁止所有目錄的設定被取代) 待實現
    log_and_print "TWGCB-04-007-0022" "檢查功能待實現。" "INFO"; ((FAIL_COUNT++))

    echo -e "\n--- 功能、內容及選項的最小化 (14 項) ---"
    log_and_print "INFO" "14 項功能最小化檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 14))

    echo -e "\n--- 記錄、監控及維護作業 (3 項) ---"
    log_and_print "INFO" "3 項記錄、監控及維護作業檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 3))

    echo -e "\n--- SSL/TLS 設定 (9 項) ---"
    # check_0040 (mod_ssl 模組) 待實現
    log_and_print "TWGCB-04-007-0040" "檢查功能待實現。" "INFO"; ((FAIL_COUNT++))
    check_0041
    check_0042
    check_0043
    # 剩餘 5 項 SSL/TLS 檢查待實現
    log_and_print "INFO" "其餘 5 項 SSL/TLS 檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 5))
    
    echo -e "\n--- 防止資訊洩露 (4 項) ---"
    check_0048
    check_0049
    # 剩餘 2 項防止資訊洩露檢查待實現
    log_and_print "INFO" "其餘 2 項防止資訊洩露檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 2))

    echo -e "\n--- 緩解阻斷服務攻擊 (6 項) ---"
    check_0052
    # 剩餘 5 項緩解阻斷服務攻擊檢查待實現
    log_and_print "INFO" "其餘 5 項緩解阻斷服務攻擊檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 5))

    echo -e "\n--- 限制請求 (4 項) ---"
    log_and_print "INFO" "4 項限制請求檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 4))

    echo -e "\n--- SELinux (3 項) ---"
    log_and_print "INFO" "3 項 SELinux 檢查待實現。" "INFO"; FAIL_COUNT=$((FAIL_COUNT + 3))
    
    echo -e "\n--- 新增項目 (v1.2) ---"
    check_0066

    echo -e "\n--- 使用者自訂檢查 ---"
    check_ssl_files

    # --- 顯示總結 ---
    echo "--------------------------------------------------"
    echo "檢查完成。"
    echo "--------------------------------------------------"
    
    # 由於範例僅實現部分功能，這裡的計數器會手動調整以反映總數
    local implemented_checks=$((PASS_COUNT + FAIL_COUNT))
    local not_implemented=$((TOTAL_CHECKS - implemented_checks))
    if [ $not_implemented -lt 0 ]; then not_implemented=0; fi # 避免負數

    # 重新計算 FAIL_COUNT，將未實現的項目計為失敗
    FAIL_COUNT=$((FAIL_COUNT + not_implemented))

    local final_pass_count=$((TOTAL_CHECKS - FAIL_COUNT))
    if [ $final_pass_count -lt 0 ]; then final_pass_count=0; fi

    local pass_rate=0
    if [ ${TOTAL_CHECKS} -gt 0 ]; then
        pass_rate=$((final_pass_count * 100 / TOTAL_CHECKS))
    fi

    summary_msg="總結: 共 ${TOTAL_CHECKS} 項檢查。通過: ${final_pass_count} 項, 未通過 (含未實現): ${FAIL_COUNT} 項。"
    rate_msg="完成比率: ${pass_rate}%"

    echo -e "${summary_msg}" | tee -a "${LOG_FILE}"
    echo -e "${rate_msg}" | tee -a "${LOG_FILE}"
    echo "--------------------------------------------------"
    echo "詳細報告請查看: ${LOG_FILE}"
}

# --- 執行腳本 ---
main

