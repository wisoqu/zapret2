<#
==========================================================================
start.ps1 — мастер zapret2 для Windows (простая автоматизация)
==========================================================================

Единственный файл запуска. После вопросов программа работает до Ctrl+C:

  1 — Проверить стратегии и подобрать рабочую
  2 — Создать новую стратегию (бета: рандомизатор)
  3 — Использовать существующую стратегию

Запуск:
  .\start.ps1            — вопросы
  .\start.ps1 2          — сразу запустить бета-рандомизатор
  .\start.ps1 3          — сразу запустить существующую стратегию

Переменные окружения (необязательно):
  DOMAIN=rutracker.org   — домен для проверки
  CANDIDATES=5           — сколько кандидатов перебрать в бете
  REPEATS=1              — число повторов теста (пока зарезервировано)

Требуется: Windows 10/11 (x64), PowerShell 5.1+, curl.exe (Windows 10+
имеет в.winspec), winws2.exe — ищется рекурсивно относительно папки скрипта
(binaries\windows-x86_64\winws2.exe и т.п.). Запускать от администратора.

ВНИМАНИЕ: режим проверки и бета генерируют трафик к домену — это быстрые
тесты, как и у blockcheck2 (проверяются только первый пакет и ответы).
==========================================================================
#>

$ErrorActionPreference = 'Stop'

$Domain    = if ($env:DOMAIN)    { $env:DOMAIN }    else { 'rutracker.org' }
$Candidates = if ($env:CANDIDATES) { [int]$env:CANDIDATES } else { 5 }
$Repeats   = if ($env:REPEATS)    { [int]$env:REPEATS }    else { 1 }

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step {
    param([string]$Text, [string]$Color = 'White')
    Write-Host $Text -ForegroundColor $Color
}
function Err-Exit {
    param([string]$Msg)
    Write-Host ''
    Write-Host "ОШИБКА: $Msg" -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------- helpers
function Find-Winws2 {
    $candidates = @(
        'binaries\windows-x86_64\winws2.exe',
        'binaries\windows-x86\winws2.exe',
        'binaries\windows-x64\winws2.exe',
        'binaries\windows-i386\winws2.exe',
        'bin\winws2.exe',
        'nfq2\winws2.exe',
        'winws2.exe'
    )
    foreach ($rel in $candidates) {
        $full = Join-Path $ScriptRoot $rel
        if (Test-Path -LiteralPath $full) { return $full }
    }
    $found = Get-ChildItem -LiteralPath $ScriptRoot -Recurse -Filter 'winws2.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

function Find-LuaFile {
    param([string]$Name)
    $rel = Join-Path 'lua' $Name
    $full = Join-Path $ScriptRoot $rel
    if (Test-Path -LiteralPath $full) { return $full }
    $found = Get-ChildItem -LiteralPath $ScriptRoot -Recurse -Filter $Name -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ------------------------------------------------- standard strategy
$StdStrategy = @(
    '--filter-tcp=80','--filter-l7=http','--payload=http_req',
    '--lua-desync=fake:blob=fake_default_http:tcp_md5',
    '--lua-desync=multisplit:pos=method+2',
    '--new',
    '--filter-tcp=443','--filter-l7=tls','--payload=tls_client_hello',
    '--lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000',
    '--lua-desync=multidisorder:pos=1,midsld',
    '--new'
)

$Alternatives = @(
    @(  # badsum для TLS
        '--filter-tcp=443','--filter-l7=tls','--payload=tls_client_hello',
        '--lua-desync=fake:blob=fake_default_tls:badsum',
        '--new'
    ),
    @(  # пустой фейк + multidisorder
        '--filter-tcp=443','--filter-l7=tls','--payload=tls_client_hello',
        '--lua-desync=fake:blob=0x00000000:tcp_md5',
        '--lua-desync=multidisorder:pos=1,midsld',
        '--new'
    )
)

# ------------------------------------------------- launcher
$script:Winws2Exe = $null
$script:LuaLib  = $null
$script:LuaAnti = $null

function Launch-Winws2 {
    param([string[]]$StrategyArgs)
    if (-not $script:Winws2Exe) { Err-Exit 'Путь к winws2.exe не найден. Откройте задачу 3/2 и проверьте наличие binaries\windows-x86_64\winws2.exe.' }

    $luaLib  = Find-LuaFile 'zapret-lib.lua'
    $luaAnti = Find-LuaFile 'zapret-antidpi.lua'
    if (-not $luaLib -or -not $luaAnti) { Err-Exit 'Lua-файлы (zapret-lib.lua, zapret-antidpi.lua) не найдены рядом со скриптом.' }

    $args = @(
        '--wf-tcp-out=80,443',
        '--wf-udp-out=443',
        "--lua-init=@$luaLib",
        "--lua-init=@$luaAnti"
    ) + $StrategyArgs

    $proc = Start-Process -FilePath $script:Winws2Exe -ArgumentList $args -WindowStyle Normal -PassThru
    return $proc
}

function Test-Strategy {
    param([string[]]$Strategy)
    $proc = Launch-Winws2 $Strategy
    Start-Sleep -Seconds 1.5
    $ok = $false
    try {
        $null = curl.exe -sS --connect-timeout 5 --max-time 12 -o NUL "https://$Domain/" 2>$null
        $ok = ($LASTEXITCODE -eq 0)
    } catch { $ok = $false }
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    return $ok
}

# ------------------------------------------------- random candidate (бета)
function Get-Candidate {
    $kind = Get-Random 0 9
    if ($kind -le 7) {
        # TLS fake family
        $seq  = Get-Random 2000 11000
        $ttl  = Get-Random 1 13
        $reps = Get-Random 1 4
        $foolPick = Get-Random 0 2
        $fools = @('tcp_md5','badsum',"ip4_ttl=$ttl")
        $fool = $fools[$foolPick]
        $s = @(
            '--filter-tcp=443','--filter-l7=tls','--payload=tls_client_hello',
            "--lua-desync=fake:blob=fake_default_tls:${fool}:tcp_seq=-${seq}:repeats=${reps}"
        )
        $split = Get-Random 0 3
        if ($split -eq 0) {
            $s += '--lua-desync=multisplit:pos=1'
        } elseif ($split -eq 1) {
            $s += '--lua-desync=multidisorder:pos=1,midsld'
        } elseif ($split -eq 2) {
            $s += '--payload=empty'
            $s += '--out-range=s1<d1'
            $s += "--lua-desync=pktmod:ip4_ttl=${ttl}"
        }
        $s += '--new'
        return $s
    } else {
        # HTTP fake family
        $reps = Get-Random 1 2
        $foolPick = Get-Random 0 2
        $fools = @('tcp_md5','badsum',"ip4_ttl=$(Get-Random 1 13)")
        $fool = $fools[$foolPick]
        return @(
            '--filter-tcp=80','--filter-l7=http','--payload=http_req',
            "--lua-desync=fake:blob=fake_default_http:${fool}:repeats=${reps}",
            '--lua-desync=multisplit:pos=method+2',
            '--new'
        )
    }
}

# ------------------------------------------------- modes
function Mode-Existing {
    Write-Step "--- Режим 3: существующая стратегия ---" 'Green'
    Write-Step "Стандартная стратегия проекта (fake + multisplit/multidisorder)."
    Write-Host ''
    Launch-Forever $StdStrategy
}

function Mode-Check {
    Write-Step "--- Режим 1: проверка стратегий ---" 'Green'
    Write-Step "Цель: $Domain"
    Write-Step "Проверяю стандартную стратегию..."
    if (Test-Strategy $StdStrategy) {
        Write-Step "✅ работает" 'Green'
        Launch-Forever $StdStrategy
        return
    }
    Write-Step "✗ стандартная не работает. Пробую варианты..." 'Yellow'
    foreach ($alt in $Alternatives) {
        Write-Step "  $($alt -join ' ')"
        if (Test-Strategy $alt) {
            Write-Step "✅ работает" 'Green'
            Launch-Forever $alt
            return
        }
        Write-Step "  ✗ не работает" 'Yellow'
    }
    Write-Step "Ни одна из стратегий не прошла проверку. Использую стандартную." 'Yellow'
    Write-Step "Проверьте подключение к интернету или $Domain вручную." 'Yellow'
    Launch-Forever $StdStrategy
}

function Mode-Random {
    Write-Step "--- Режим 2: создаём новую стратегию (бета) ---" 'Green'
    Write-Step "Цель: $Domain"
    Write-Step "Случайно генерирую $Candidates кандидатов и проверяю каждый..."
    Write-Step "⚠️  Бета: стратегия не гарантирована." 'Yellow'
    Write-Host ''
    $found = $null
    for ($i = 1; $i -le $Candidates; $i++) {
        $cand = Get-Candidate
        Write-Step "--- кандидат $i/$Candidates ---"
        Write-Step "  $($cand -join ' ')"
        if (Test-Strategy $cand) {
            Write-Step "  ✅ работает" 'Green'
            $found = $cand
            break
        } else {
            Write-Step "  ✗ не работает" 'Yellow'
        }
    }
    if (-not $found) {
        Write-Step "Ни один кандидат не сработал. Использую стандартную." 'Yellow'
        $found = $StdStrategy
    }
    Write-Host ''
    Write-Step "--- Выбранная стратегия ---" 'Green'
    Write-Step "  $($found -join ' ')"
    Launch-Forever $found
}

# ----------------------------------------------------- foreground launch
function Launch-Forever {
    param([string[]]$Strategy)
    $proc = Launch-Winws2 $Strategy
    Write-Host ''
    Write-Step "────────────────────────────────────────" 'White'
    Write-Step "  winws2 запущен с выбранной стратегией" 'White'
    Write-Step "  $script:Winws2Exe" 'White'
    Write-Step "  Нажмите Ctrl+C, чтобы остановить." 'White'
    Write-Step "────────────────────────────────────────" 'White'
    Write-Host ''
    try {
        while ($true) {
            if ($proc.HasExited) { break }
            Start-Sleep -Milliseconds 500
        }
    } finally {
        if (-not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host ''
    Write-Step "winws2 завершился." 'Yellow'
    exit 1
}

# ------------------------------------------------- menu and main
function Show-Banner {
    Write-Host ''
    Write-Step "════════════════════════════════════════════" 'Cyan'
    Write-Step "  ЗАПРЕТ2 — МАСТЕР (Windows)" 'Cyan'
    Write-Step "════════════════════════════════════════════" 'Cyan'
    Write-Step "  Домен проверки: $Domain"
    Write-Step "  CANDIDATES=$Candidates  REPEATS=$Repeats"
    Write-Host ''
}

function Get-Mode {
    Write-Step "Выберите действие:"
    Write-Step "  1 — Проверить стратегии и подобрать рабочую"
    Write-Step "  2 — Создать новую стратегию (бета: рандомизатор)"
    Write-Step "  3 — Использовать существующую стратегию"
    while ($true) {
        $mode = Read-Host "Введите цифру (1/2/3): "
        if ($mode -in @('1', '2', '3')) { return $mode }
        Write-Step "Неизвестная цифра. Введите 1, 2 или 3" 'Yellow'
    }
}

$mode = ''
if ($args.Count -ge 1 -and $args[0]) {
    $mode = "$($args[0])"
    if ($mode -notin @('1', '2', '3')) { Err-Exit "неизвестная цифра: $mode (1/2/3)" }
}

Show-Banner

if (-not (Test-IsAdmin)) {
    Err-Exit "Запускайте от администратора (права админа требуются winws2/WinDivert)."
}
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Write-Step "curl.exe не найден. Проверки режимов 1 и 2 будут невозможны (режим 3 работает)." 'Yellow'
}

if (-not $mode) {
    $mode = Get-Mode
}

$script:Winws2Exe = Find-Winws2
if (-not $script:Winws2Exe) {
    Err-Exit "winws2.exe не найден. Поместите binaries\windows-x86_64\winws2.exe рядом со скриптом (или в любом подкаталоге)."
}

switch ($mode) {
    '1' { Mode-Check }
    '2' { Mode-Random }
    '3' { Mode-Existing }
}
