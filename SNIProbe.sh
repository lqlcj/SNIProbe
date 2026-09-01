#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# SNIProbe — Reality 域名(SNI)检测工具
# ───────────────────────────────────────────────────────────────────
# 从 linux-menu 的 check_reality_dest_domain 独立出来，用于判断
# 一个域名是否适合做 Reality 的 dest/handshake 站点。
#
# 判定流程（6 步）：
#   1. DNS 解析（IP 数量）
#   2. IP 归属（是否命中 CDN / 云厂商黑名单）
#   3. TCP 443 通断（v4 全测；v6 仅本机有 IPv6 时测）
#   4. TLS 1.3 + X25519 + ALPN（reality 硬性要求）
#   5. 证书 SAN 是否覆盖该域名
#   6. TCP 握手延迟（3 次取最快）
#
# 依赖：curl openssl getent timeout（标准 Linux 工具）
# ═══════════════════════════════════════════════════════════════════

set -o pipefail

G="\033[32m" Y="\033[33m" C="\033[36m" R="\033[31m" B="\033[1m" N="\033[0m"
L="\033[94m" W="\033[97m" D="\033[2m"

CDN_BLACKLIST="Cloudflare|Fastly|Akamai|CloudFront|Amazon|Microsoft|Google|Azure|Incapsula|Imperva"

render_divider(){
  echo -e "  ${D}──────────────────────────────────────────────────────${N}"
}

pause_screen(){
  echo ""
  read -p "按回车返回..." _
}

detect_primary_ipv6(){
  local detected="" local_fallback=""

  if command -v ip >/dev/null 2>&1; then
    detected=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{
      for (i = 1; i <= NF; i++) {
        if ($i == "src") {
          print $(i + 1)
          exit
        }
      }
    }')
    if [ -n "$detected" ]; then
      case "$detected" in
        fe80:*|fc*|fd*) local_fallback="$detected"; detected="" ;;
      esac
    fi

    if [ -z "$detected" ]; then
      detected=$(ip -6 addr show scope global up 2>/dev/null | awk '/inet6 / {
        split($2, parts, "/")
        print parts[1]
        exit
      }')
      if [ -n "$detected" ]; then
        case "$detected" in
          fe80:*|fc*|fd*) [ -z "$local_fallback" ] && local_fallback="$detected"; detected="" ;;
        esac
      fi
    fi
  fi

  if [ -z "$detected" ]; then
    detected=$(curl --proto '=https' --tlsv1.2 -fsS6 --max-time 5 \
      https://api64.ipify.org 2>/dev/null || true)
    case "$detected" in
      *:*) ;;
      *) detected="" ;;
    esac
  fi

  if [ -z "$detected" ]; then
    detected="$local_fallback"
  fi

  printf '%s' "$detected"
}

check_reality_dest_domain(){
  local domain ips ip ipn org cdn_match proto x25 pq alpn cipher
  local v4s v6s vps_has_v6 conn hs1 hs2 hs3
  local cert_san cert_match=0 san san_value suffix
  local any_fail=0 fastest=999 t i testip

  echo ""
  read -p "  请输入要测试的域名（如 www.osaka-u.ac.jp，回车取消）: " domain
  domain=$(echo "$domain" | tr -d ' \t\r\n')
  # 兼容 http:// / https:// 前缀，自动剥离协议与路径
  domain=$(printf '%s' "$domain" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/?#].*$##' | tr -d ' ')
  if [ -z "$domain" ]; then
    return 0
  fi
  if ! printf '%s' "$domain" | grep -qE '^[a-zA-Z0-9._-]+$'; then
    echo -e "${R}  域名格式不合法（仅允许字母、数字、点、横线、下划线）${N}"
    pause_screen
    return 1
  fi

  echo ""
  echo -e "  ${B}${C}›  SNI 域名检测: $domain${N}"
  render_divider
  echo ""

  # 1. DNS 解析
  echo -e "  ${B}[1/6] DNS 解析${N}"
  ips=$(getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u)
  if [ -z "$ips" ]; then
    echo -e "    ${R}✗ DNS 解析失败${N}"
    echo ""
    render_divider
    echo -e "  ${R}✗ 不可用 — DNS 解析失败${N}"
    echo ""
    pause_screen
    return 1
  fi
  ipn=$(echo "$ips" | wc -l | tr -d ' ')
  # 深度测试优先用 IPv4：reality 握手由 VPS 发起，v4-only 机器上测 v6 地址只会误报
  v4s=$(echo "$ips" | grep -v ':' || true)
  v6s=$(echo "$ips" | grep ':' || true)
  ip=$(echo "$v4s" | head -1)
  [ -z "$ip" ] && ip=$(echo "$v6s" | head -1)
  vps_has_v6=$(detect_primary_ipv6 2>/dev/null || true)
  # openssl -connect 的 IPv6 地址必须带方括号
  case "$ip" in
    *:*) conn="[$ip]:443" ;;
    *)   conn="$ip:443" ;;
  esac
  if [ "$ipn" -le 3 ]; then
    echo -e "    ${G}✓${N} 解析到 ${C}${ipn}${N} 个 IP："
  else
    echo -e "    ${Y}△${N} 解析到 ${C}${ipn}${N} 个 IP（>3 个有踩死 IP 风险）："
  fi
  echo "$ips" | sed 's/^/      /'

  # 2. ASN / 归属
  echo ""
  echo -e "  ${B}[2/6] IP 归属（首个 IP）${N}"
  org=$(curl -s --max-time 5 "https://ipinfo.io/$ip/org" 2>/dev/null | tr -d '\n')
  if [ -z "$org" ]; then
    echo -e "    ${Y}? 无法查询 ipinfo.io（VPS 网络受限），跳过${N}"
    org="未知"
  elif echo "$org" | grep -qiE "$CDN_BLACKLIST"; then
    cdn_match=$(echo "$org" | grep -ioE "$CDN_BLACKLIST" | head -1)
    echo -e "    ${R}✗ $org${N}"
    echo -e "    ${R}  → 命中 CDN/云厂商黑名单（${cdn_match}）${N}"
  else
    echo -e "    ${G}✓ $org${N}"
  fi

  # 3. TCP 443 通断（v4 全测；v6 仅在本机有 IPv6 时测，否则测了必失败、纯属误报）
  echo ""
  echo -e "  ${B}[3/6] TCP 443 通断${N}"
  for testip in $v4s; do
    if timeout 3 bash -c "echo > /dev/tcp/$testip/443" 2>/dev/null; then
      echo -e "    ${G}✓${N} $testip"
    else
      echo -e "    ${R}✗${N} $testip"
      any_fail=1
    fi
  done
  if [ -n "$v6s" ]; then
    if [ -n "$vps_has_v6" ]; then
      for testip in $v6s; do
        if timeout 3 bash -c "echo > /dev/tcp/$testip/443" 2>/dev/null; then
          echo -e "    ${G}✓${N} $testip"
        else
          echo -e "    ${R}✗${N} $testip"
          any_fail=1
        fi
      done
    else
      echo -e "    ${D}本机无 IPv6，跳过 $(echo "$v6s" | wc -l | tr -d ' ') 个 v6 地址（不影响判定）${N}"
    fi
  fi

  # 4. TLS 1.3 / X25519 / ALPN —— 分两次握手，才能区分「不支持 1.3」和「不支持 X25519」
  echo ""
  echo -e "  ${B}[4/6] TLS 1.3 + X25519 + ALPN（IP=${ip}）${N}"
  hs1=$(echo | timeout 5 openssl s_client -connect "$conn" -servername "$domain" \
          -tls1_3 -alpn h2,http/1.1 2>/dev/null)
  proto=$(echo "$hs1" | grep -m1 -oE 'TLSv1\.[0-9]+')
  alpn=$(echo "$hs1" | grep -m1 -oE 'ALPN protocol: \S+' | awk '{print $3}')
  cipher=$(echo "$hs1" | grep -m1 -oE 'Cipher\s*:\s*\S+' | awk -F'[: ]+' '{print $NF}')

  if [ "$proto" = "TLSv1.3" ]; then
    echo -e "    ${G}✓${N} Protocol: TLSv1.3"
  else
    echo -e "    ${R}✗${N} Protocol: ${proto:-握手失败} ${R}(目标站点强制 TLS 1.3)${N}"
  fi

  # 只提供 X25519 一个组再握手：能协商成功即支持（比 grep 输出关键字可靠，
  # 不同 openssl 版本对协商组的输出格式不一致）
  x25=no
  if [ "$proto" = "TLSv1.3" ]; then
    hs2=$(echo | timeout 5 openssl s_client -connect "$conn" -servername "$domain" \
            -tls1_3 -groups X25519 2>/dev/null)
    echo "$hs2" | grep -qE 'New, TLSv1\.3|Protocol[[:space:]]*:[[:space:]]*TLSv1\.3' && x25=yes
  fi
  if [ "$x25" = "yes" ]; then
    echo -e "    ${G}✓${N} X25519 密钥交换支持"
  else
    echo -e "    ${R}✗${N} X25519 ${R}不支持（默认密钥交换组）${N}"
  fi

  case "$alpn" in
    h2)        echo -e "    ${G}✓${N} ALPN: h2 (HTTP/2，最现代)" ;;
    http/1.1)  echo -e "    ${Y}△${N} ALPN: http/1.1 (可用但伪装稍弱)" ;;
    "")        echo -e "    ${Y}△${N} ALPN: 未协商" ;;
    *)         echo -e "    ${Y}△${N} ALPN: $alpn" ;;
  esac
  if [ -n "$cipher" ]; then
    echo -e "    ${C}  Cipher: $cipher${N}"
  fi

  # 信息项：抗量子混合组（Chrome 已默认在 ClientHello 里带，dest 支持算伪装加分）
  # 不参与综合判定；本机 openssl < 3.5 不认识该组名时跳过
  pq=skip
  if [ "$proto" = "TLSv1.3" ]; then
    hs3=$(echo | timeout 5 openssl s_client -connect "$conn" -servername "$domain" \
            -tls1_3 -groups X25519MLKEM768 2>&1)
    if echo "$hs3" | grep -qE 'New, TLSv1\.3|Protocol[[:space:]]*:[[:space:]]*TLSv1\.3'; then
      pq=yes
    elif echo "$hs3" | grep -qiE 'no such group|unknown group|unknown option|invalid argument|Error with command|SSL_CONF_cmd|failed to set'; then
      pq=skip
    else
      pq=no
    fi
  fi
  case "$pq" in
    yes)  echo -e "    ${G}✓${N} 抗量子混合组 X25519MLKEM768 ${D}(加分项，更贴近真实 Chrome 流量)${N}" ;;
    no)   echo -e "    ${D}△ 抗量子混合组不支持（信息项，不影响判定）${N}" ;;
    skip) echo -e "    ${D}? 本机 openssl 过旧，无法检测抗量子组（不影响判定）${N}" ;;
  esac

  # 5. 证书 SAN
  echo ""
  echo -e "  ${B}[5/6] 证书 SAN 是否覆盖该域名${N}"
  cert_san=$(echo | timeout 5 openssl s_client -connect "$conn" -servername "$domain" 2>/dev/null \
              | openssl x509 -noout -ext subjectAltName 2>/dev/null \
              | grep -oE 'DNS:[^,]+' | tr -d ' ' | head -10)
  if [ -n "$cert_san" ]; then
    while IFS= read -r san; do
      san_value=${san#DNS:}
      if [ "$san_value" = "$domain" ]; then
        cert_match=1
        break
      fi
      case "$san_value" in
        \*.*)
          suffix=${san_value#\*.}
          case "$domain" in
            *.$suffix) cert_match=1; break ;;
          esac
          ;;
      esac
    done <<EOF
$cert_san
EOF
    if [ "$cert_match" = "1" ]; then
      echo -e "    ${G}✓${N} 证书覆盖该域名"
    else
      echo -e "    ${Y}△${N} 证书 SAN 未明确覆盖："
    fi
    echo "$cert_san" | head -3 | sed 's/^/      /'
  else
    echo -e "    ${Y}△${N} 无法读取证书 SAN"
  fi

  # 6. TCP 握手延迟
  echo ""
  echo -e "  ${B}[6/6] TCP 握手延迟（3 次取最快）${N}"
  for i in 1 2 3; do
    t=$(curl -o /dev/null -s --max-time 4 --resolve "$domain:443:$ip" \
        -w '%{time_connect}' "https://$domain/" 2>/dev/null)
    if [ -n "$t" ]; then
      echo -e "    第 $i 次: ${C}${t}s${N}"
      if awk "BEGIN { exit !($t < $fastest) }" 2>/dev/null; then
        fastest=$t
      fi
    else
      echo -e "    第 $i 次: ${R}失败${N}"
    fi
  done

  # 综合评级
  echo ""
  render_divider
  echo -e "  ${B}综合判定${N}"
  if [ -n "$cdn_match" ]; then
    echo -e "    ${R}✗ 不可用 — 命中 CDN/云厂商黑名单（$cdn_match）${N}"
  elif [ "$proto" != "TLSv1.3" ]; then
    echo -e "    ${R}✗ 不可用 — 不支持 TLS 1.3（硬性要求）${N}"
  elif [ "$x25" != "yes" ]; then
    echo -e "    ${R}✗ 不可用 — 不支持 X25519 密钥交换（硬性要求）${N}"
  elif [ "$any_fail" = "1" ]; then
    echo -e "    ${Y}△ 慎用 — 有 IP 不通，可能成为定时炸弹（参考 tmu.ac.jp 案例）${N}"
  elif [ "$ipn" -gt 3 ]; then
    echo -e "    ${Y}△ 慎用 — IP 数量较多（${ipn} 个），未来踩死 IP 风险偏高${N}"
  elif [ "$alpn" != "h2" ]; then
    echo -e "    ${Y}△ 可用 — 但 ALPN 是 ${alpn:-未协商}，伪装稍弱${N}"
  elif [ "$cert_match" != "1" ]; then
    echo -e "    ${Y}△ 可用 — 但证书 SAN 未覆盖该域名${N}"
  else
    echo -e "    ${G}✓ 完美 — 全部硬指标通过，建议作为目标站点使用${N}"
  fi
  if [ "$fastest" != "999" ]; then
    echo -e "    最快延迟: ${C}${fastest}s${N}"
  fi
  echo ""
  pause_screen
}

main(){
  while true; do
    echo ""
    echo -e "  ${B}${C}SNIProbe — SNI 域名检测工具${N}"
    render_divider
    check_reality_dest_domain
  done
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi