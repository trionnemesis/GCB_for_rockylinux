#!/bin/bash

# =================================================================
# Apache 2.4 GCB 組態強化腳本 (TWGCB-04-007)
#
# 說明: 此腳本依據「Apache HTTP Server 2.4 政府組態基準說明文件」
#       進行伺服器安全性設定。腳本設計安全、無損且可重複執行。
#       此版本將 SSL 設定模組化至 /usr/local/apache/conf/SSLData/
#
# 作者: warden
# 日期: 2025-06-17
#
# 使用方式: sudo ./GCB_apache.sh
# =================================================================

# --- 腳本設定 ---
HTTPD_CONF="/usr/local/apache/conf/httpd.conf"
APACHE_BIN_DIR="/usr/local/apache/bin"
APACHECTL="$APACHE_BIN_DIR/apachectl"
SSL_DATA_DIR="/usr/local/apache/conf/SSLData"
REQUIRED_USER="apache"
REQUIRED_GROUP="apache"

# --- 輔助函式 ---

# 函式：輸出格式化的日誌訊息
log() {
    echo "【GCB強化】$1"
}

# 函式：檢查網路連線狀態
check_internet() {
    ping -c 1 8.8.8.8 &> /dev/null
}

# 函式：設定組態指令
# 檢查指令是否存在，若存在則修改，若不存在則新增
set_directive() {
    local conf_file=$1
    local directive=$2
    local value=$3
    # 為了sed，對數值中的特殊字元進行跳脫
    local escaped_value=$(sed 's/[\/&]/\\&/g' <<< "$value")

    log "設定檔案 '$conf_file' 中的 '$directive' 為 '$value'"

    if grep -q "^\s*${directive}" "$conf_file"; then
        sed -i "s/^\s*${directive}.*/${directive} ${escaped_value}/" "$conf_file"
    else
        echo "${directive} ${escaped_value}" >> "$conf_file"
    fi
}

# 函式：註解（停用）一個模組
comment_out_module() {
    local module_name=$1
    log "停用模組: ${module_name}"
    sed -i "s/^\s*\(LoadModule\s*${module_name}\)/#\1/" "$HTTPD_CONF"
}

# 函式：取消註解（啟用）一個模組
enable_module() {
    local module_name=$1
    log "啟用模組: ${module_name}"
    sed -i "s/^#\s*\(LoadModule\s*${module_name}\)/\1/" "$HTTPD_CONF"
}


# --- 主程式開始 ---

# 檢查是否以 root 權限執行
if [ "$(id -u)" -ne 0 ]; then
  log "錯誤：此腳本必須以 root 權限執行。操作已中斷。" >&2
  exit 1
fi

# 檢查 httpd.conf 是否存在
if [ ! -f "$HTTPD_CONF" ]; then
    log "錯誤：Apache 設定檔 '$HTTPD_CONF' 不存在。操作已中斷。"
    exit 1
fi

# 1. 備份現有的設定檔
BACKUP_FILE="${HTTPD_CONF}.bak.$(date +%F-%T)"
log "正在備份目前的設定檔至 $BACKUP_FILE"
cp "$HTTPD_CONF" "$BACKUP_FILE"
if [ $? -ne 0 ]; then
    log "錯誤：建立備份檔失敗。操作已中斷。"
    exit 1
fi

# --- 開始套用 GCB 設定 ---

log "開始執行 Apache GCB 組態強化..."

# TWGCB-04-007-0001: 啟用 Log Config 模組
log "TWGCB-04-007-0001: 確保 Log Config 模組已啟用 "
enable_module "log_config_module"

# TWGCB-04-007-0002 ~ 0007, 0065: 停用非必要的模組
log "TWGCB-04-007-0002: 停用 WebDAV 模組 "
comment_out_module "dav_module"
comment_out_module "dav_fs_module"
log "TWGCB-04-007-0003: 停用 Status 模組 "
comment_out_module "status_module"
log "TWGCB-04-007-0004: 停用 Autoindex 模組 "
comment_out_module "autoindex_module"
log "TWGCB-04-007-0005: 停用 Proxy 相關模組 "
comment_out_module "proxy_module"
comment_out_module "proxy_connect_module"
comment_out_module "proxy_ftp_module"
comment_out_module "proxy_http_module"
comment_out_module "proxy_fcgi_module"
comment_out_module "proxy_scgi_module"
comment_out_module "proxy_ajp_module"
comment_out_module "proxy_balancer_module"
comment_out_module "proxy_express_module"
comment_out_module "proxy_wstunnel_module"
comment_out_module "proxy_fdpass_module"
log "TWGCB-04-007-0006: 停用 User Directories 模組 "
comment_out_module "userdir_module"
log "TWGCB-04-007-0007: 停用 Info 模組 "
comment_out_module "info_module"
log "TWGCB-04-007-0065: 停用 Basic/Digest Authentication 模組 "
comment_out_module "auth_basic_module"
comment_out_module "auth_digest_module"

# TWGCB-04-007-0008 ~ 0010: 設定 Apache 執行身分
log "TWGCB-04-007-0008: 確保 Apache 以非 root 身分 ($REQUIRED_USER) 運行 "
if ! getent group "$REQUIRED_GROUP" >/dev/null; then
    log "群組 '$REQUIRED_GROUP' 不存在，正在建立..."
    groupadd -r "$REQUIRED_GROUP"
fi
if ! id "$REQUIRED_USER" >/dev/null 2>&1; then
    log "使用者 '$REQUIRED_USER' 不存在，正在建立..."
    useradd "$REQUIRED_USER" -r -g "$REQUIRED_GROUP" -d /var/www -s /sbin/nologin
fi
set_directive "$HTTPD_CONF" "User" "$REQUIRED_USER"
set_directive "$HTTPD_CONF" "Group" "$REQUIRED_GROUP"

log "TWGCB-04-007-0009: 禁止執行帳號 '$REQUIRED_USER' 登入系統 "
chsh -s /sbin/nologin "$REQUIRED_USER"

log "TWGCB-04-007-0010: 鎖定執行帳號 '$REQUIRED_USER' 的密碼 "
passwd -l "$REQUIRED_USER" >/dev/null

# TWGCB-04-007-0011 ~ 0015: 設定目錄與檔案權限
SERVER_ROOT=$(grep -i '^\s*ServerRoot' "$HTTPD_CONF" | awk '{print $2}' | tr -d '"')
if [ -d "$SERVER_ROOT" ]; then
    log "TWGCB-04-007-0011, 0012: 設定 ServerRoot ($SERVER_ROOT) 的擁有者與群組為 root "
    chown -R root:root "$SERVER_ROOT"
    log "TWGCB-04-007-0013: 移除 ServerRoot 的 others 寫入權限 "
    chmod -R o-w "$SERVER_ROOT"
    log "TWGCB-04-007-0014: 移除 ServerRoot 的群組寫入權限 "
    chmod -R g-w "$SERVER_ROOT"
fi

DOC_ROOT=$(grep -i '^\s*DocumentRoot' "$HTTPD_CONF" | awk '{print $2}' | tr -d '"')
if [ -d "$DOC_ROOT" ]; then
    log "TWGCB-04-007-0015: 移除 DocumentRoot ($DOC_ROOT) 對於 Apache 執行群組的寫入權限 "
    find -L "$DOC_ROOT" -group "$REQUIRED_GROUP" -perm /g=w -print -exec chmod g-w {} \;
fi

# TWGCB-04-007-0020, 0021, 0023: 存取控制
log "TWGCB-04-007-0020, 0021, 0023: 套用根目錄的全域存取控制 "
if ! grep -q -z "<Directory />\s*Require all denied\s*</Directory>" "$HTTPD_CONF"; then
    cat <<EOF >> "$HTTPD_CONF"

# GCB TWGCB-04-007-0020, 0021, 0023: 設定根目錄的安全預設值
<Directory />
    AllowOverride None
    Require all denied
    Options None
</Directory>
EOF
fi

# TWGCB-04-007-0022: 禁止所有目錄的設定被取代
log "TWGCB-04-007-0022: 全域設定 AllowOverride 為 None "
set_directive "$HTTPD_CONF" "AllowOverride" "None"

# TWGCB-04-007-0026, 0027, 0028, 0050: 最小化功能與內容 (說明)
log "TWGCB-04-007-0026, 0027, 0028, 0050 (說明): 請手動移除預設/範例內容 "
log "  - 移除預設的 index.html 或歡迎頁面"
log "  - 若已安裝 httpd-manual 套件，請移除 (例如: 'dnf erase httpd-manual')"
log "  - 從 cgi-bin 目錄中移除 'printenv' 和 'test-cgi' 等範例腳本"
log "  - 在設定檔中註解掉 /icons/ 的 Alias"

# TWGCB-04-007-0030: 停用 HTTP TRACE 請求方法
log "TWGCB-04-007-0030: 設定 TraceEnable 為 off "
set_directive "$HTTPD_CONF" "TraceEnable" "off"

# TWGCB-04-007-0031: 限制 HTTP 協定版本
log "TWGCB-04-007-0031: 啟用 mod_rewrite 以強制使用 HTTP/1.1 或更高版本 "
enable_module "rewrite_module"
if ! grep -q "RewriteEngine On" "$HTTPD_CONF"; then
    cat <<'EOF' >> "$HTTPD_CONF"

# GCB TWGCB-04-007-0031: 強制使用 HTTP/1.1 或更新的協定
RewriteEngine On
RewriteCond %{THE_REQUEST} !HTTP/1\.1$
RewriteRule .* - [F]
EOF
    log "TWGCB-04-007-0031 (說明): 若您有使用虛擬主機 (VirtualHost)，請在每個虛擬主機設定區塊中加入 'RewriteOptions Inherit' 以繼承此規則 "
fi

# TWGCB-04-007-0032: 限制存取 .ht* 檔案
log "TWGCB-04-007-0032: 拒絕存取 .ht* 相關檔案 "
if ! grep -q "^\s*<FilesMatch \"\^\\.ht\">" "$HTTPD_CONF"; then
    cat <<'EOF' >> "$HTTPD_CONF"

# GCB TWGCB-04-007-0032: 拒絕 .ht* 檔案的存取
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
EOF
fi

# TWGCB-04-007-0033, 0034, 0035: 手動設定項目 (說明)
log "TWGCB-04-007-0033 (說明): 為增強安全性，建議手動設定檔案副檔名白名單 "
log "TWGCB-04-007-0034, 0035 (說明): 為增強安全性，建議將 Apache 綁定至特定 IP (例如 'Listen 192.168.1.10:80') 並拒絕直接對 IP 的請求 "

# TWGCB-04-007-0036: 限制網站被嵌入到 frame (CSP)
log "TWGCB-04-007-0036 (說明): 新增防止點擊劫持 (Clickjacking) 的設定建議 "
cat <<'EOF' >> "$HTTPD_CONF"

# GCB TWGCB-04-007-0036: 防止點擊劫持 (Clickjacking)。
# 請根據您的網站需求，取消註解並選擇以下其中一項設定。
#
# 選項 1: (相容性最佳) 僅允許同源的網頁嵌入 (SAMEORIGIN)。
# Header always append X-Frame-Options SAMEORIGIN
#
# 選項 2: (較新標準) 使用 Content-Security-Policy，僅允許同源嵌入 ('self')。
# Header always append Content-Security-Policy "frame-ancestors 'self';"
#
# 選項 3: (最嚴格) 完全禁止任何網頁嵌入 (DENY / 'none')。
# Header always append X-Frame-Options DENY
# Header always append Content-Security-Policy "frame-ancestors 'none';"
EOF

# TWGCB-04-007-0037: 設定錯誤日誌的記錄等級
log "TWGCB-04-007-0037: 設定 LogLevel 為 'notice core:info' "
set_directive "$HTTPD_CONF" "LogLevel" "notice core:info"

# TWGCB-04-007-0039: 日誌保留時間 (說明)
log "TWGCB-04-007-0039 (說明): 請設定日誌輪替(Log Rotation)。編輯 '/etc/logrotate.d/httpd'，設定 'weekly' 與 'rotate 13' 以保留至少13週的日誌 "

# TWGCB-04-007-0040: 安裝 mod_ssl
log "TWGCB-04-007-0040: 檢查 mod_ssl 模組 "
if ! $APACHECTL -M | grep -q 'ssl_module'; then
    if check_internet; then
        log "未找到 mod_ssl，嘗試自動安裝..."
        if command -v dnf &> /dev/null; then
            dnf install -y mod_ssl
        elif command -v yum &> /dev/null; then
            yum install -y mod_ssl
        else
            log "找不到 dnf 或 yum。請手動安裝 mod_ssl 套件。"
        fi
    else
      log "TWGCB-04-007-0040 (說明): 無法連線至網路。請手動下載並安裝 'mod_ssl' 套件。"
    fi
fi

# TWGCB-04-007-0042 ~ 0046: SSL/TLS 相關設定 (模組化)
log "正在建立並設定 SSL/TLS 模組化組態目錄: $SSL_DATA_DIR"
mkdir -p "$SSL_DATA_DIR"

log "TWGCB-04-007-0042: 建立協定設定檔 (00-ssl-protocol.conf)... "
cat <<EOF > "${SSL_DATA_DIR}/00-ssl-protocol.conf"
# GCB TWGCB-04-007-0042: 僅啟用強健的 TLS 協定版本
# 停用已知的弱點協定 SSLv3, TLSv1.0, TLSv1.1
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
EOF

log "TWGCB-04-007-0043: 建立加密演算法設定檔 (01-ssl-ciphers.conf)... "
cat <<'EOF' > "${SSL_DATA_DIR}/01-ssl-ciphers.conf"
# GCB TWGCB-04-007-0043: 設定伺服器偏好的加密演算法順序
SSLHonorCipherOrder On

# GCB TWGCB-04-007-0043: 設定強健的加密演算法套件 (Cipher Suite)
# 支援 Perfect Forward Secrecy (PFS)
SSLCipherSuite ECDHE:DHE:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL
EOF

log "TWGCB-04-007-0044, 0045, 0046: 建立其他 SSL 選項設定檔 (02-ssl-options.conf)... "
cat <<'EOF' > "${SSL_DATA_DIR}/02-ssl-options.conf"
# GCB TWGCB-04-007-0044: 關閉不安全的 SSL 重新協商
SSLInsecureRenegotiation off

# GCB TWGCB-04-007-0045: 關閉 SSL 壓縮以防範 CRIME 攻擊
SSLCompression off

# GCB TWGCB-04-007-0046: 啟用 OCSP Stapling 以增進效能與隱私
SSLUseStapling On
SSLStaplingCache "shmcb:logs/ssl_staple_cache(512000)"
EOF

# 在主設定檔中引入 SSLData 目錄
INCLUDE_DIRECTIVE="IncludeOptional ${SSL_DATA_DIR}/*.conf"
if ! grep -qF "$INCLUDE_DIRECTIVE" "$HTTPD_CONF"; then
    log "在 '$HTTPD_CONF' 中加入 SSL 組態目錄的 Include 指令"
    echo "" >> "$HTTPD_CONF"
    echo "# GCB: 載入模組化的 SSL/TLS 安全性設定" >> "$HTTPD_CONF"
    echo "$INCLUDE_DIRECTIVE" >> "$HTTPD_CONF"
else
    log "SSL 組態目錄的 Include 指令已存在於 '$HTTPD_CONF'"
fi


# TWGCB-04-007-0041, 0047, 0066: SSL/TLS 手動設定 (說明)
log "TWGCB-04-007-0041 (說明): 請手動確認您的 SSL 私鑰 (SSLCertificateKeyFile) 檔案權限為 0400，且擁有者為 root:root "
log "TWGCB-04-007-0047 (說明): 建議啟用 HSTS。在您的 SSL 虛擬主機中加入 'Header always set Strict-Transport-Security \"max-age=31536000\"' "
log "TWGCB-04-007-0066 (說明): 建議強制使用 HTTPS。在您非 SSL 的網站設定中加入 'Redirect permanent / https://your.domain.name/' "

# TWGCB-04-007-0048, 0049, 0051: 防止資訊洩露
log "TWGCB-04-007-0048: 設定 ServerTokens 為 Prod，隱藏詳細版本資訊 "
set_directive "$HTTPD_CONF" "ServerTokens" "Prod"
log "TWGCB-04-007-0049: 設定 ServerSignature 為 Off，隱藏簽章資訊 "
set_directive "$HTTPD_CONF" "ServerSignature" "Off"
log "TWGCB-04-007-0051: 設定 FileETag 為 None，避免洩漏 INode 資訊 "
set_directive "$HTTPD_CONF" "FileETag" "None"

# TWGCB-04-007-0052 ~ 0057: 緩解阻斷服務攻擊 (DoS)
log "TWGCB-04-007-0052: 設定連線逾時時間 (Timeout) 為 60 秒 "
set_directive "$HTTPD_CONF" "Timeout" "60"
log "TWGCB-04-007-0053: 啟用 HTTP 持續連線 (KeepAlive) "
set_directive "$HTTPD_CONF" "KeepAlive" "On"
log "TWGCB-04-007-0054: 設定持續連線的最大請求數 (MaxKeepAliveRequests) 為 100 "
set_directive "$HTTPD_CONF" "MaxKeepAliveRequests" "100"
log "TWGCB-04-007-0055: 設定持續連線的逾時時間 (KeepAliveTimeout) 為 15 秒 "
set_directive "$HTTPD_CONF" "KeepAliveTimeout" "15"
log "TWGCB-04-007-0056, 0057: 啟用 mod_reqtimeout 模組以防範 Slowloris 攻擊 "
enable_module "reqtimeout_module"
set_directive "$HTTPD_CONF" "RequestReadTimeout" "header=20-40,MinRate=500 body=20,MinRate=500"

# TWGCB-04-007-0058 ~ 0061: 限制請求大小
log "TWGCB-04-007-0058: 限制請求行 (Request Line) 的大小為 512 bytes "
set_directive "$HTTPD_CONF" "LimitRequestLine" "512"
log "TWGCB-04-007-0059: 限制請求標頭欄位的數量為 100 "
set_directive "$HTTPD_CONF" "LimitRequestFields" "100"
log "TWGCB-04-007-0060: 限制請求標頭欄位的大小為 1024 bytes "
set_directive "$HTTPD_CONF" "LimitRequestFieldSize" "1024"
log "TWGCB-04-007-0061: 限制請求主體 (Request Body) 的大小為 102400 bytes (100KB) "
set_directive "$HTTPD_CONF" "LimitRequestBody" "102400"

# TWGCB-04-007-0062 ~ 0064: SELinux 設定
if command -v sestatus &> /dev/null && [ -f /etc/selinux/config ]; then
    log "TWGCB-04-007-0062: 設定 SELinux 為 'enforcing' 模式 "
    sed -i 's/^\s*SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1 # 立即生效
    log "TWGCB-04-007-0063, 0064 (說明): SELinux 的檔案安全本文設定較複雜，請依據您的系統發行版，手動驗證 httpd 執行檔的本文 (context) 是否正確 "
else
    log "未偵測到 SELinux，略過相關設定。"
fi

# --- 驗證與重新啟動 ---
log "組態強化腳本執行完畢。"

log "正在執行設定檔語法測試 (`apachectl configtest`)..."
$APACHECTL configtest
CONFIG_TEST_STATUS=$?

if [ $CONFIG_TEST_STATUS -eq 0 ]; then
    log "Apache 設定檔語法測試成功。"
    log "正在平滑重啟 Apache (`apachectl graceful`) 以套用變更..."
    $APACHECTL graceful
    log "Apache 已成功重新載入設定。"
else
    log "--------------------------------------------------"
    log "錯誤：APACHE 設定檔語法測試失敗！"
    log "您的變更尚未套用。"
    log "請檢查上方的錯誤訊息。"
    log "您可以使用以下指令還原備份的設定檔："
    log "  sudo cp $BACKUP_FILE $HTTPD_CONF"
    log "--------------------------------------------------"
    exit 1
fi

exit 0
