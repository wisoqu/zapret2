#!/bin/bash
# ============================================================================
# start.sh — мастер zapret2 (простая автоматизация под русские реалии)
#
# Один файл запуска. После вопросов программа работает до Ctrl+C:
#   1 — проверить стратегии и подобрать рабочую
#   2 — создать новую стратегию (бета: рандомизатор)
#   3 — использовать существующую стратегию
#
# Запуск:
#   ./start.sh        — интерактивно
#   ./start.sh 2      — сразу создать новую стратегию (бета)
#   ./start.sh 3      — сразу запустить существующую стратегию
#
# Переменные окружения (необязательно):
#   DOMAIN=rutracker.org  — домен проверки
#   SCANLEVEL=quick       — уровень проверки (quick|standard|force)
#   REPEATS=1             — число повторов теста
#   CANDIDATES=5          — сколько кандидатов перебрать в бете
#
# Требования: Linux, root (sudo ./start.sh), nftables, curl, make.
# BSD/Windows: мастер не поддерживает — используйте install_easy.sh и мануал.
# ============================================================================
set -euo pipefail

EXEDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WBASE="$EXEDIR"
NFQWS2="${NFQWS2:-$WBASE/nfq2/nfqws2}"

DOMAIN="${DOMAIN:-rutracker.org}"
SCANLEVEL="${SCANLEVEL:-quick}"
REPEATS="${REPEATS:-1}"
CANDIDATES="${CANDIDATES:-5}"
QNUM=200
NFT_TABLE="zt_start"

say()  { printf '%s\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*" >&2; }
die()  { say ""; say "ОШИБКА: $*"; exit 1; }

# ------------------------------------------------- banner / prereq
banner() {
    say ""
    say "════════════════════════════════════════════"
    say "  ЗАПРЕТ2 — МАСТЕР"
    say "════════════════════════════════════════════"
    say "  Домен проверки: $DOMAIN"
    say "  SCANLEVEL=$SCANLEVEL  REPEATS=$REPEATS  CANDIDATES=$CANDIDATES"
    say ""
}

check_prereq() {
    [ "$(uname -s)" = "Linux" ] \
        || die "мастер работает только под Linux. Для Windows/BSD используйте install_easy.sh и мануал."
    [ "$(id -u)" = "0" ] \
        || die "запускайте от root: sudo ./start.sh"
    command -v nft  >/dev/null 2>&1 || die "не найден nft. Установите nftables (apt install nftables)."
    command -v curl >/dev/null 2>&1 || die "не найден curl. Установите его."
    if [ ! -x "$NFQWS2" ]; then
        say "nfqws2 не найден. Пытаюсь собрать (make)..."
        if ! make -C "$WBASE" 2>&1 | tail -n 15; then
            die "не удалось собрать nfqws2. Проверьте зависимости (cc, make, libnl, luajit) и соберите nfq2 вручную."
        fi
    fi
    [ -x "$NFQWS2" ] || die "nfqws2 всё ещё не найден после make: $NFQWS2"
}

# ------------------------------------------------- nftables
start_fw() {
    nft delete table inet "$NFT_TABLE" 2>/dev/null || true
    nft create table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" post "{type filter hook postrouting priority 101;}"
    nft add rule inet "$NFT_TABLE" post meta mark and 0x40000000 == 0 tcp dport "{80,443}" ct original packets 1-12 queue num $QNUM bypass
    nft add rule inet "$NFT_TABLE" post meta mark and 0x40000000 == 0 udp dport "{443}" ct original packets 1-12 queue num $QNUM bypass
    nft add chain inet "$NFT_TABLE" pre  "{type filter hook prerouting priority -101;}"
    nft add rule inet "$NFT_TABLE" pre meta mark and 0x40000000 == 0 tcp sport "{80,443}" ct reply packets 1-12 queue num $QNUM bypass
    nft add rule inet "$NFT_TABLE" pre meta mark and 0x40000000 == 0 udp sport "{443}" ct reply packets 1-12 queue num $QNUM bypass
    nft add chain inet "$NFT_TABLE" predefrag "{type filter hook output priority -401;}"
    nft add rule inet "$NFT_TABLE" predefrag "mark & 0x40000000 != 0x00000000 notrack"
    sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1 || true
}

stop_fw() {
    nft delete table inet "$NFT_TABLE" 2>/dev/null || true
}

# ------------------------------------------------- tokens / launcher
FPID=""
TESTPID=""
LAUNCHED_PID=""

kill_test_daemon() {
    [ -z "$TESTPID" ] && return 0
    kill "$TESTPID" 2>/dev/null || true
    wait "$TESTPID" 2>/dev/null || true
    TESTPID=""
}

kill_real_daemon() {
    [ -z "$FPID" ] && return 0
    kill "$FPID" 2>/dev/null || true
    wait "$FPID" 2>/dev/null || true
    FPID=""
}

cleanup() {
    kill_test_daemon
    kill_real_daemon
    stop_fw
}

trap cleanup EXIT
trap 'exit 130' INT TERM

# strategy args строка → токены. Символы < и > заменяем на служебные,
# чтобы они не рассматривались как перенаправление.
to_tokens() {
    local s="$1" item
    s=${s//\</$(printf '\x01')}
    s=${s//\>/$(printf '\x02')}
    local toks=()
    for item in $s; do
        [ -z "$item" ] && continue
        item=${item//$(printf '\x01')/<}
        item=${item//$(printf '\x02')/>}
        toks+=("$item")
    done
    [ "${#toks[@]}" = "0" ] && return 0
    printf '%s\0' "${toks[@]}"
}

launch_nfqws2() {
    # $1 = стратегия (строка). После вызова — LAUNCHED_PID = pid
    local args="$1"
    local toks=()
    while IFS= read -r -d '' t; do toks+=("$t"); done < <(to_tokens "$args")
    if [ "${#toks[@]}" = "0" ]; then
        die "стратегия пустая"
    fi
    "$NFQWS2" --qnum="$QNUM" \
        --lua-init=@"$WBASE/lua/zapret-lib.lua" \
        --lua-init=@"$WBASE/lua/zapret-antidpi.lua" \
        "${toks[@]}" >/dev/null 2>&1 &
    LAUNCHED_PID=$!
}

STD_STRAT="--filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5 --lua-desync=multisplit:pos=method+2 --new --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000 --lua-desync=multidisorder:pos=1,midsld --new"

launch_forever() {
    local args="$1"
    say ""
    say "────────────────────────────────────────"
    say "  Запуск zapret2 с выбранной стратегией"
    say "  $NFQWS2 --lua-init=@lua/zapret-lib.lua --lua-init=@lua/zapret-antidpi.lua $args"
    say "────────────────────────────────────────"
    launch_nfqws2 "$args"
    FPID="$LAUNCHED_PID"

    say ""
    say "✅ zapret2 работает. Трафик идёт через стратегию."
    say "   Нажмите Ctrl+C, чтобы остановить."
    say ""

    while kill -0 "$FPID" 2>/dev/null; do
        sleep 0.5
    done

    local code=0
    if ! wait "$FPID" 2>/dev/null; then code=$?; fi
    FPID=""
    say ""
    warn "nfqws2 завершился с кодом $code — стратегия, возможно, не работает."
    say "Откройте сайт в обычном браузере для проверки."
    sleep 5
    exit 1
}

# ------------------------------------------------- режим 3: существующая
mode_existing() {
    say "--- Режим 3: используем существующую стратегию ---"
    say "Стандартная стратегия проекта (fake + multisplit/multidisorder)."
    say ""
    start_fw || die "не удалось применить nftables правила (смотрите вывод выше)"
    launch_forever "$STD_STRAT"
}

# ------------------------------------------------- режим 1: проверка
mode_check() {
    say "--- Режим 1: проверка стратегий ---"
    say "Цель: $DOMAIN"
    say "Запускаю проверку (blockcheck2). Это может занять несколько минут..."
    say "----------------------------------------"

    local tmpout
    tmpout="$(mktemp /tmp/zapret2-wizard-check-XXXXXX.log)"

    env BATCH=1 \
        TEST=standard \
        DOMAINS="$DOMAIN" \
        IPVS=4 \
        ENABLE_HTTP=1 \
        ENABLE_HTTPS_TLS12=1 \
        ENABLE_HTTPS_TLS13=0 \
        ENABLE_HTTP3=0 \
        TLS13= \
        HTTP3= \
        SKIP_DNSCHECK=1 \
        REPEATS="$REPEATS" \
        PARALLEL=0 \
        SCANLEVEL="$SCANLEVEL" \
        bash "$WBASE/blockcheck2.sh" >"$tmpout" 2>&1 || true

    tail -n 40 "$tmpout"

    local line args
    line="$(sed -n '/^\* SUMMARY/,$p' "$tmpout" 2>/dev/null \
        | grep -E " ipv4 $DOMAIN : nfqws2 " | head -n 1 || true)"

    if [ -z "$line" ]; then
        warn "Не найдена работающая стратегия. Использую стандартную встроенную."
        say "Проверьте интернет-доступ и позже выполните blockcheck2.sh вручную."
        args="$STD_STRAT"
    else
        args="$(printf '%s' "$line" \
            | sed -E "s/^[^ ]+ ipv4 [^ ]+ : nfqws2 //" \
            | sed -E "s/^--uid [^ ]+ --fwmark=[^ ]+ --qnum=[^ ]+ --lua-init=\"[^\"]*\" --lua-init=@[^ ]+ --lua-init=@[^ ]+ //")"
        if [ -z "$args" ]; then
            warn "Не удалось разобрать стратегию. Использую стандартную встроенную."
            args="$STD_STRAT"
        else
            say ""
            say "Выбрана рабочая стратегия из теста ($DOMAIN):"
            say "  $(printf '%s' "$args" | cut -d' ' -f1-6)..."
        fi
    fi

    rm -f "$tmpout"

    say ""
    start_fw || die "не удалось применить nftables правила"
    launch_forever "$args"
}

# ------------------------------------------------- режим 2: рандомизатор (бета)
gen_candidate() {
    local kind=$((RANDOM % 10))
    local fool=$((RANDOM % 3))
    local reps=$((RANDOM % 3 + 1))
    case "$kind" in
        0|1|2|3|4|5|6|7)
            local seq=$((RANDOM % 9000 + 2000))
            local ttl=$((RANDOM % 12 + 1))
            local fool_s="tcp_md5"
            case "$fool" in
                0) fool_s="tcp_md5" ;;
                1) fool_s="badsum" ;;
                2) fool_s="ip4_ttl=$ttl" ;;
            esac
            local s="--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:$fool_s:tcp_seq=-$seq:repeats=$reps"
            case $((RANDOM % 4)) in
                0) s="$s --lua-desync=multisplit:pos=1" ;;
                1) s="$s --lua-desync=multidisorder:pos=1,midsld" ;;
                2) s="$s --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip4_ttl=$ttl" ;;
                3) : ;;
            esac
            printf '%s --new' "$s"
            ;;
        8|9)
            local fool_s="tcp_md5"
            case "$fool" in
                0) fool_s="tcp_md5" ;;
                1) fool_s="badsum" ;;
                2) fool_s="ip4_ttl=$((RANDOM % 12 + 1))" ;;
            esac
            printf -- "--filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=fake:blob=fake_default_http:$fool_s:repeats=$reps --lua-desync=multisplit:pos=method+2 --new"
            ;;
    esac
}

mode_random() {
    say "--- Режим 2: создаём новую стратегию (бета) ---"
    say "Цель: $DOMAIN"
    say "Случайно генерирую $CANDIDATES кандидатов и проверяю каждый..."
    say "⚠️  Бета: стратегия не гарантирована."
    say ""

    start_fw || die "не удалось применить nftables правила"

    local found=""
    for i in $(seq 1 "$CANDIDATES"); do
        local cand
        cand="$(gen_candidate)"
        say "--- кандидат $i/$CANDIDATES ---"
        say "  $cand"
        launch_nfqws2 "$cand"
        TESTPID="$LAUNCHED_PID"
        sleep 1.5
        if curl -sS --connect-timeout 5 --max-time 8 -o /dev/null "https://$DOMAIN/"; then
            say "  ✅ работает"
            found="$cand"
            kill_test_daemon
            break
        else
            say "  ✗ не работает"
            kill_test_daemon
        fi
    done

    if [ -z "$found" ]; then
        warn "Ни один кандидат не сработал. Использую стандартную встроенную стратегию."
        say "Попробуйте позже, увеличьте CANDIDATES или используйте режим 1."
        found="$STD_STRAT"
    fi

    say ""
    say "--- Выбранная стратегия ---"
    say "  $(printf '%s' "$found" | cut -d' ' -f1-8)..."
    launch_forever "$found"
}

# ------------------------------------------------- меню
MAIN_MODE=""

menu() {
    say "Выберите действие:"
    say "  1 — Проверить стратегии и подобрать рабочую"
    say "  2 — Создать новую стратегию (бета: рандомизатор)"
    say "  3 — Использовать существующую стратегию"
    while true; do
        printf "Введите цифру (1/2/3): "
        if ! read -r MAIN_MODE; then
            say ""
            die "ввод закрыт. Используйте: ./start.sh 1|2|3"
        fi
        case "$MAIN_MODE" in
            1|2|3) return 0 ;;
            "") say "Введите 1, 2 или 3" ;;
            *) say "Неизвестная цифра. Введите 1, 2 или 3" ;;
        esac
    done
}

main() {
    local mode="${1:-}"
    if [ -n "$mode" ] && [ "$mode" != "1" ] && [ "$mode" != "2" ] && [ "$mode" != "3" ]; then
        die "неизвестная цифра: $mode (1/2/3)"
    fi

    banner
    check_prereq

    if [ -z "$mode" ]; then
        menu
        mode="$MAIN_MODE"
    fi

    case "$mode" in
        1) mode_check ;;
        2) mode_random ;;
        3) mode_existing ;;
        *) die "неизвестная цифра: $mode" ;;
    esac
}

main "$@"
