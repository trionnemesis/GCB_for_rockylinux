Rocky Linux 9 GCB (政府組態基準) 自動化檢測與套用腳本
這是一套協助系統工程師將 Rocky Linux 9 系統設定符合臺灣政府組態基準 (GCB) 資安要求，並提供檢測與設定功能的自動化腳本。

專案簡介
🎯 目的: 旨在簡化並加速 Rocky Linux 9 系統的 GCB 安全性設定與檢測流程，透過自動化腳本減少人為疏失，並確保設定的一致性。

📄 依據文件: 腳本內容主要基於 TWGCB-01-012_Red Hat Enterprise Linux 9 政府組態基準說明文件(伺服器)v1.2 及 TWGCB-04-007_Apache HTTP Server 2.4政府組態基準說明文件v1.2。

💡 核心功能: 將繁複的 GCB 指令封裝成模組化腳本，涵蓋了從系統設定、服務、網路、稽核、帳號控制到網頁伺服器等多個面向的資安強化與合規性檢查。

⚠️ 重要：執行前必讀 (免責聲明)
高風險操作: 設定腳本 (GCB_SET 目錄下) 會對系統進行大量且深層的組態變更，包括修改核心參數、服務設定、使用者權限及防火牆規則。

務必備份: 在執行任何 設定腳本 之前，您必須對系統進行完整備份。

嚴禁直接上線: 絕對禁止在未經測試的情況下於正式生產環境中執行設定腳本。請務必先在隔離的測試機器上進行完整驗證。

需具備專業知識: 執行者應具備 Linux 系統管理及維運經驗，並充分理解腳本中所執行的各項指令及其可能帶來的影響。

責任歸屬: 對於使用此腳本可能造成的任何系統損壞或資料遺失，開發者概不負責。

檢測腳本: 檢測腳本 (GCB_CHECK 目錄下) 為唯讀操作，不會對系統進行任何修改，相對安全。

📁 檔案功能說明
此專案包含兩大類核心腳本：GCB 檢測腳本 (GCB_CHECK) 與 GCB 設定腳本 (GCB_SET)。

1. GCB 檢測腳本 (GCB_CHECK)
此目錄下的腳本用於評估系統目前狀態與 GCB 規範的符合程度，所有操作均為唯讀。

GCB_check.sh - 主要作業系統 GCB 合規性檢測
功能: 依據 TWGCB-01-012 文件，對 RHEL 9 系統進行全面的合規性掃描。

檢測範圍: 涵蓋磁碟與檔案系統、系統設定、服務、網路、SELinux、帳號與存取控制、SSH 伺服器等多個方面。

輸出: 在終端機以顏色標示 PASS, FAIL, SKIP，並將詳細的檢測日誌匯出至 /var/log/，包含通過/未通過的統計摘要與完成比率。

GCB_check_apache.sh - Apache 伺服器 GCB 合規性檢測
功能: 依據 TWGCB-04-007 文件，專門用來檢測 Apache HTTP Server 2.4 的組態設定。

檢測範圍: 檢查模組啟用狀態、執行身份、權限、存取控制、SSL/TLS 設定、資訊洩露防護等 66 個 GCB 項目。

輸出: 同樣提供即時的 CLI 檢查結果與詳細的 Log 檔案，並統計完成比率。

2. GCB 設定腳本 (GCB_SET)
此目錄下的腳本會實際修改系統設定以符合 GCB 要求。

GCB.sh - 主要作業系統 GCB 組態套用
功能: 此為最核心的系統強化腳本，涵蓋 GCB 標準中絕大部分的作業系統安全性設定。

主要模組: 包含磁碟與檔案系統、系統設定與維護、系統服務、網路設定、日誌與稽核、帳號與存取控制、防火牆等。

高風險提示: 對於磁碟分割、fstab 修改等高風險操作，腳本會顯示明確的警告與建議，要求管理者手動介入。

日誌記錄: 所有執行過程與錯誤訊息都會記錄在 /var/log/gcb/ 目錄下。

GCB_sshd.sh - SSH 伺服器強化
功能: 專門用於強化 OpenSSH 伺服器 (sshd) 的安全性。

自動備份: 執行前會自動備份 sshd_config 與 /etc/pam.d 目錄。

核心設定: 強制使用 SSH Protocol 2、禁止 root 登入、限制認證次數、設定閒置超時、強化加密演算法等。

錯誤處理: 若 sshd 重啟失敗，會自動導出錯誤日誌以利除錯。

GCB_apache.sh - Apache 網站伺服器強化
功能: 專門強化 Apache 2.4 網站伺服器，使其符合 GCB 規範。

自動備份: 執行前會自動備份 httpd.conf。

主要設定: 停用非必要模組、設定安全執行身份、強化 SSL/TLS (僅啟用 TLSv1.2 以上)、防止資訊洩露、緩解 DoS 攻擊等。

iptables_to_firewalld.sh - iptables 規則轉換工具
功能: 一個輔助遷移的工具，當您需要將舊有 iptables 規則遷移至 RHEL 9 預設的 firewalld 時使用。

智慧轉換: 自動將簡單的 INPUT 規則轉換為 firewalld 指令，並識別出無法轉換的複雜規則（如 NAT、FORWARD）供管理者手動處理。

互動確認: 在執行任何變更前，會列出將執行的指令與無法轉換的規則，並要求使用者輸入 yes 確認，提供一道安全防線。
🚀 使用說明 (建議流程)
建議採用「先檢測 -> 後設定 -> 再檢測」的流程。
📝 稽核與記錄
執行日誌:

GCB.sh 的日誌位於 /var/log/gcb/。

檢測腳本的日誌位於 /var/log/，以 rhel9_gcb_check_ 或 apache_gcb_check_ 開頭。

設定備份: GCB_sshd.sh 和 GCB_apache.sh 會在 /root/ 或設定檔當前目錄建立備份，以利還原。

手動項目: 請務必留意腳本在執行過程中顯示的 [!] 手動操作需求訊息，這些項目（如磁碟分割、設定 GRUB 密碼）需要您親自完成。
