#!/bin/bash

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 全局变量
CONFIG_FILE="/etc/v2ray/config.json"
SERVICE_FILE="/etc/systemd/system/v2ray.service"
NGINX_CONF_PATH="/etc/nginx/conf.d/"
LOG_FILE="/var/log/v2ray_install.log"
IP=$(curl -sL --fail -4 https://ip.sb || curl -sL --fail -6 https://ip.sb)

# 日志记录函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo -e "$1"
}

# 颜色输出函数
colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

# 检查 root 权限
checkRoot() {
    [[ $EUID -ne 0 ]] && {
        colorEcho $RED "请以 root 身份运行此脚本"
        log "错误：非 root 用户"
        exit 1
    }
}

# 检查系统兼容性
checkSystem() {
    checkRoot
    if command -v apt >/dev/null 2>&1; then
        PMT="apt"
        CMD_INSTALL="apt install -y"
        CMD_UPDATE="apt update"
    elif command -v yum >/dev/null 2>&1; then
        PMT="yum"
        CMD_INSTALL="yum install -y"
        CMD_UPDATE="yum update -y"
    elif command -v dnf >/dev/null 2>&1; then
        PMT="dnf"
        CMD_INSTALL="dnf install -y"
        CMD_UPDATE="dnf update -y"
    else
        colorEcho $RED "不支持的包管理器"
        log "错误：未检测到支持的包管理器"
        exit 1
    }
    command -v systemctl >/dev/null 2>&1 || {
        colorEcho $RED "系统不支持 systemd"
        log "错误：未检测到 systemd"
        exit 1
    }
}

# 获取 CPU 架构
archAffix() {
    case "$(uname -m)" in
        x86_64|amd64) echo "64" ;;
        aarch64) echo "arm64-v8a" ;;
        armv7*) echo "arm32-v7a" ;;
        mips64*) echo "mips64" ;;
        mips*) echo "mips" ;;
        *) colorEcho $RED "不支持的 CPU 架构：$(uname -m)"; exit 1 ;;
    esac
}

# 检查 V2Ray 状态
checkV2rayStatus() {
    if [[ -f /usr/bin/v2ray/v2ray && -f "$CONFIG_FILE" ]]; then
        systemctl is-active v2ray >/dev/null 2>&1 && return 0 || return 1
    fi
    return 2
}

# 获取用户输入
getData() {
    colorEcho $BLUE "请输入伪装域名（例如 example.com）："
    read -p "域名：" DOMAIN
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        colorEcho $RED "域名格式错误，请输入有效域名！"
        log "错误：无效域名 $DOMAIN"
        exit 1
    fi
    DOMAIN=${DOMAIN,,}
    log "伪装域名：$DOMAIN"

    colorEcho $BLUE "请输入监听端口（默认 443，范围 1-65535）："
    read -p "端口：" PORT
    [[ -z "$PORT" ]] && PORT=443
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        colorEcho $RED "端口必须为 1-65535 的数字！"
        log "错误：无效端口 $PORT"
        exit 1
    fi
    if ss -tuln | grep -q ":$PORT "; then
        colorEcho $RED "端口 $PORT 已被占用，请选择其他端口！"
        log "错误：端口 $PORT 被占用"
        exit 1
    fi
    log "监听端口：$PORT"
}

# 安装依赖
installDependencies() {
    $CMD_UPDATE
    for tool in wget curl unzip tar openssl net-tools socat; do
        command -v "$tool" >/dev/null 2>&1 || {
            $CMD_INSTALL "$tool" || {
                colorEcho $RED "安装依赖 $tool 失败，请检查网络"
                log "错误：安装 $tool 失败"
                exit 1
            }
        }
    done
    log "依赖安装完成"
}

# 安装 Nginx
installNginx() {
    if ! command -v nginx >/dev/null 2>&1; then
        colorEcho $BLUE "安装 Nginx..."
        $CMD_INSTALL nginx || {
            colorEcho $RED "Nginx 安装失败，请检查包管理器配置"
            log "错误：Nginx 安装失败"
            exit 1
        }
        systemctl enable nginx
        log "Nginx 安装成功"
    fi
    # 动态检测 Nginx 配置路径
    if [[ ! -d "$NGINX_CONF_PATH" ]]; then
        NGINX_CONF_PATH="/etc/nginx/sites-available/"
        [[ ! -d "$NGINX_CONF_PATH" ]] && {
            colorEcho $RED "无法确定 Nginx 配置路径，请手动设置"
            log "错误：Nginx 配置路径未找到"
            exit 1
        }
    fi
}

# 获取 TLS 证书
getCert() {
    mkdir -p /etc/v2ray
    chmod 700 /etc/v2ray || {
        colorEcho $RED "设置 /etc/v2ray 权限失败"
        log "错误：设置 /etc/v2ray 权限失败"
        exit 1
    }
    CERT_FILE="/etc/v2ray/${DOMAIN}.pem"
    KEY_FILE="/etc/v2ray/${DOMAIN}.key"

    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
        colorEcho $BLUE "检测到现有证书，跳过获取"
        return
    fi

    systemctl stop nginx
    curl -sL --fail https://get.acme.sh | sh -s email=do.ho@hotmail.com || {
        colorEcho $RED "安装 acme.sh 失败，请检查网络"
        log "错误：acme.sh 安装失败"
        exit 1
    }
    source ~/.bashrc
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 || {
        colorEcho $RED "获取证书失败，请检查域名解析或网络"
        log "错误：证书获取失败"
        exit 1
    }
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
        --key-file "$KEY_FILE" \
        --fullchain-file "$CERT_FILE" || {
        colorEcho $RED "安装证书失败"
        log "错误：证书安装失败"
        exit 1
    }
    chmod 600 "$CERT_FILE" "$KEY_FILE" || {
        colorEcho $RED "设置证书权限失败"
        log "错误：证书权限设置失败"
        exit 1
    }
    log "证书获取成功：$CERT_FILE, $KEY_FILE"
}

# 配置 Nginx
configNginx() {
    mkdir -p "$NGINX_CONF_PATH"
    cat > "${NGINX_CONF_PATH}${DOMAIN}.conf" <<-EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name:\$request_uri;
}

server {
    listen $PORT ssl;
    server_name $DOMAIN;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    location / {
        root /usr/share/nginx/html;
    }
}
EOF
    systemctl restart nginx || {
        colorEcho $RED "Nginx 重启失败：$(systemctl status nginx | tail -n 5)"
        log "错误：Nginx 重启失败"
        exit 1
    }
    log "Nginx 配置完成"
}

# 安装 V2Ray
installV2ray() {
    local ARCH=$(archAffix)
    local V2RAY_VERSION=$(curl -s --fail https://api.github.com/repos/v2fly/v2ray-core/releases/latest | grep tag_name | cut -d\" -f4)
    local DOWNLOAD_LINK="https://github.com/v2fly/v2ray-core/releases/download/${V2RAY_VERSION}/v2ray-linux-${ARCH}.zip"

    if [[ -z "$V2RAY_VERSION" ]]; then
        colorEcho $YELLOW "获取 V2Ray 最新版本失败，使用默认版本 v4.45.0"
        V2RAY_VERSION="v4.45.0"
        DOWNLOAD_LINK="https://github.com/v2fly/v2ray-core/releases/download/${V2RAY_VERSION}/v2ray-linux-${ARCH}.zip"
    fi

    rm -rf /tmp/v2ray && mkdir -p /tmp/v2ray
    for i in {1..3}; do
        curl -L --fail -o /tmp/v2ray/v2ray.zip "$DOWNLOAD_LINK" && break
        [[ $i -eq 3 ]] && {
            colorEcho $RED "下载 V2Ray 失败，经过三次尝试"
            log "错误：V2Ray 下载失败"
            exit 1
        }
        sleep 2
    done
    unzip -o /tmp/v2ray/v2ray.zip -d /tmp/v2ray || {
        colorEcho $RED "解压 V2Ray 失败：$(unzip -t /tmp/v2ray/v2ray.zip 2>&1)"
        log "错误：V2Ray 解压失败"
        exit 1
    }
    mkdir -p /usr/bin/v2ray /etc/v2ray /var/log/v2ray
    cp /tmp/v2ray/{v2ray,v2ctl,geo*} /usr/bin/v2ray/
    chmod +x /usr/bin/v2ray/{v2ray,v2ctl}
    log "V2Ray 安装完成，版本：$V2RAY_VERSION"
}

# 配置 V2Ray（简单 VMess+TLS 示例）
configV2ray() {
    local UUID=$(cat /proc/sys/kernel/random/uuid)
    cat > "$CONFIG_FILE" <<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [{"id": "$UUID", "alterId": 0}]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "$DOMAIN",
        "certificates": [{"certificateFile": "$CERT_FILE", "keyFile": "$KEY_FILE"}]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "blocked"}]
}
EOF
    chmod 600 "$CONFIG_FILE" || {
        colorEcho $RED "设置 V2Ray 配置文件权限失败"
        log "错误：V2Ray 配置文件权限设置失败"
        exit 1
    }
    log "V2Ray 配置完成"
}

# 设置 V2Ray 服务（改进版）
setupService() {
    # 检查服务文件是否已存在，若存在则备份
    if [[ -f "$SERVICE_FILE" ]]; then
        cp "$SERVICE_FILE" "${SERVICE_FILE}.bak" || {
            colorEcho $RED "备份现有服务文件失败"
            log "错误：备份 $SERVICE_FILE 失败"
            exit 1
        }
        colorEcho $BLUE "现有服务文件已备份为 ${SERVICE_FILE}.bak"
    }

    # 创建服务文件
    cat > "$SERVICE_FILE" <<-EOF
[Unit]
Description=V2Ray Service
After=network.target nginx.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/v2ray/v2ray -config $CONFIG_FILE
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载 systemd 配置
    systemctl daemon-reload || {
        colorEcho $RED "systemctl daemon-reload 失败：$(systemctl status 2>&1)"
        log "错误：systemctl daemon-reload 失败"
        exit 1
    }

    # 启用服务（开机自启）
    systemctl enable v2ray || {
        colorEcho $RED "启用 V2Ray 服务失败：$(systemctl status v2ray 2>&1)"
        log "错误：启用 V2Ray 服务失败"
        exit 1
    }
    log "V2Ray 服务已设置为开机自启"

    # 启动服务并验证
    systemctl start v2ray || {
        colorEcho $RED "V2Ray 启动失败：$(systemctl status v2ray | tail -n 5)"
        log "错误：V2Ray 启动失败"
        exit 1
    }
    sleep 2  # 等待服务启动
    systemctl is-active v2ray >/dev/null 2>&1 || {
        colorEcho $RED "V2Ray 服务未运行：$(systemctl status v2ray | tail -n 5)"
        log "错误：V2Ray 服务未运行"
        exit 1
    }
    log "V2Ray 服务启动成功"
}

# 显示配置信息
showInfo() {
    local UUID=$(grep id "$CONFIG_FILE" | head -n1 | cut -d\" -f4)
    colorEcho $BLUE "V2Ray 配置信息："
    echo -e "  IP: $IP"
    echo -e "  端口: $PORT"
    echo -e "  UUID: $UUID"
    echo -e "  协议: VMess"
    echo -e "  传输: TCP+TLS"
    echo -e "  域名: $DOMAIN"
    local LINK="vmess://$(echo -n "{\"v\":\"2\",\"add\":\"$IP\",\"port\":\"$PORT\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"tcp\",\"tls\":\"tls\",\"host\":\"$DOMAIN\"}" | base64 -w 0)"
    echo -e "  链接: $LINK"
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t UTF8 "$LINK"
    else
        colorEcho $YELLOW "未安装 qrencode，无法生成二维码，请安装后重试"
    fi
    log "显示配置信息"
}

# 安装流程
install() {
    checkSystem
    checkV2rayStatus
    [[ $? -eq 0 ]] && {
        colorEcho $RED "V2Ray 已安装并运行，请先停止或卸载"
        exit 1
    }
    installDependencies
    getData
    installNginx
    getCert
    configNginx
    installV2ray
    configV2ray
    setupService
    showInfo
    colorEcho $GREEN "安装完成！"
    log "安装完成"
}

# 更新 V2Ray
update() {
    checkV2rayStatus
    [[ $? -eq 2 ]] && {
        colorEcho $RED "V2Ray 未安装，请先安装"
        exit 1
    }
    installV2ray
    systemctl restart v2ray || {
        colorEcho $RED "V2Ray 重启失败：$(systemctl status v2ray | tail -n 5)"
        log "错误：V2Ray 重启失败"
        exit 1
    }
    colorEcho $GREEN "V2Ray 更新完成！"
    log "V2Ray 更新完成"
}

# 卸载 V2Ray
uninstall() {
    checkV2rayStatus
    [[ $? -eq 2 ]] && {
        colorEcho $RED "V2Ray 未安装，无需卸载"
        exit 1
    }
    systemctl stop v2ray nginx
    systemctl disable v2ray nginx
    rm -rf /usr/bin/v2ray /etc/v2ray "$SERVICE_FILE" "${NGINX_CONF_PATH}${DOMAIN}.conf"
    $CMD_INSTALL -y remove nginx
    [[ -f ~/.acme.sh/acme.sh ]] && ~/.acme.sh/acme.sh --uninstall
    colorEcho $GREEN "V2Ray 卸载完成！"
    log "V2Ray 卸载完成"
}

# 主菜单
menu() {
    clear
    echo "=== V2Ray 一键安装脚本 ==="
    echo "1. 安装 V2Ray (VMess+TLS)"
    echo "2. 更新 V2Ray"
    echo "3. 卸载 V2Ray"
    echo "0. 退出"
    read -p "请选择 [0-3]：" choice
    case $choice in
        1) install ;;
        2) update ;;
        3) uninstall ;;
        0) exit 0 ;;
        *) colorEcho $RED "无效选项" ;;
    esac
}

# 初始化日志
mkdir -p /var/log
touch "$LOG_FILE"
chmod 600 "$LOG_FILE" || {
    colorEcho $RED "设置日志文件权限失败"
    log "错误：日志文件权限设置失败"
    exit 1
}
[[ -w "$LOG_FILE" ]] || {
    colorEcho $RED "日志文件不可写，请检查权限"
    log "错误：日志文件不可写"
    exit 1
}

# 执行
case "$1" in
    install) install ;;
    update) update ;;
    uninstall) uninstall ;;
    *) menu ;;
esac
