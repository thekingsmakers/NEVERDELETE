# ============================================
# ZERO TRUST GITHUB WHITELIST ENFORCER
# Bulletproof Edition v3
# Fixes: Downloads whitelist BEFORE blocking
# Run as SYSTEM via Task Scheduler or Intune
# ============================================

$WhitelistURL = "https://raw.githubusercontent.com/thekingsmakers/NEVERDELETE/refs/heads/main/whitelist.txt"
$Prefix       = "ZT-White"
$LogDir       = "C:\ZeroTrust"
$LogFile      = "$LogDir\whitelist.log"
$BackupDir    = "$LogDir\backups"
$BlockPage    = "$LogDir\blocked.html"
$CachedList   = "$LogDir\whitelist_cache.txt"
$ADPorts      = @(88, 135, 389, 445, 636, 3268, 3269)
$ADPortsUDP   = @(88, 123, 389)
$RPCDynamic   = "49152-65535"

# GitHub IPs needed to bootstrap the download
# These are GitHub's current IP ranges for raw.githubusercontent.com
$GitHubBootstrapIPs = @(
    "185.199.108.0/22",
    "140.82.112.0/20",
    "143.55.64.0/20",
    "192.30.252.0/22"
)

# DNS needed to resolve GitHub before we lock DNS down
$BootstrapDNS = @("8.8.8.8", "1.1.1.1")

# ============================================
# SETUP
# ============================================
foreach ($dir in @($LogDir, $BackupDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "OK"    { Write-Host $entry -ForegroundColor Green }
        default { Write-Host $entry }
    }
}

Write-Log "============================================"
Write-Log "Zero Trust Whitelist Enforcer v3 starting"
Write-Log "============================================"

# ============================================
# ADMIN CHECK
# ============================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "Must run as Administrator or SYSTEM." "ERROR"
    exit 1
}
Write-Log "Admin check passed." "OK"

# ============================================
# STEP 1 — TEMPORARILY OPEN OUTBOUND
# Remove all ZT rules and set Allow so we
# can reach GitHub to download the whitelist
# ============================================
Write-Log "STEP 1: Temporarily opening outbound to download whitelist..."

# Remove existing ZT rules
$oldRules = Get-NetFirewallRule -DisplayName "$Prefix-*" -ErrorAction SilentlyContinue
if ($oldRules) {
    $oldRules | Remove-NetFirewallRule
    Write-Log "Removed $($oldRules.Count) old ZT rules."
}

# Temporarily allow outbound so GitHub is reachable
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
Write-Log "Outbound temporarily set to ALLOW for download." "WARN"

# Re-enable any previously disabled built-in rules so DNS works
Get-NetFirewallRule -Enabled False -Direction Outbound -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -notlike "$Prefix-*" } |
    Set-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue

Write-Log "Built-in rules re-enabled for download phase."

# ============================================
# STEP 2 — DOWNLOAD WHITELIST FROM GITHUB
# Retry up to 5 times
# ============================================
Write-Log "STEP 2: Downloading whitelist from GitHub..."

$lines      = $null
$maxRetries = 5
$downloaded = $false

for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
    try {
        Write-Log "  Attempt $attempt of $maxRetries..."

        # Force TLS 1.2 (required by GitHub)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $response = Invoke-WebRequest `
            -Uri $WhitelistURL `
            -UseBasicParsing `
            -TimeoutSec 30 `
            -ErrorAction Stop

        if ($response.StatusCode -eq 200 -and $response.Content.Length -gt 10) {
            $lines      = $response.Content -split "`n"
            $downloaded = $true

            # Save to local cache so we can use it if GitHub is unreachable next time
            Set-Content -Path $CachedList -Value $response.Content -Encoding UTF8
            Write-Log "  Downloaded $($lines.Count) lines. Cached to $CachedList." "OK"
            break
        } else {
            Write-Log "  Empty or invalid response (status $($response.StatusCode))." "WARN"
        }
    } catch {
        Write-Log "  Attempt $attempt failed: $($_.Exception.Message)" "WARN"
        if ($attempt -lt $maxRetries) {
            Write-Log "  Waiting 10 seconds before retry..."
            Start-Sleep -Seconds 10
        }
    }
}

# ============================================
# STEP 3 — FALLBACK TO CACHED WHITELIST
# If GitHub unreachable, use last known good list
# ============================================
if (-not $downloaded) {
    if (Test-Path $CachedList) {
        Write-Log "STEP 3: GitHub unreachable. Loading cached whitelist from $CachedList..." "WARN"
        $lines      = Get-Content $CachedList -Encoding UTF8
        $downloaded = $true
        Write-Log "Loaded $($lines.Count) lines from cache." "OK"
    } else {
        Write-Log "STEP 3: No cache found. Cannot proceed safely." "ERROR"
        Write-Log "Re-applying block as safety measure..."
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
        exit 1
    }
}

# ============================================
# STEP 4 — PARSE WHITELIST
# ============================================
Write-Log "STEP 4: Parsing whitelist..."

$AllowedIPs   = [System.Collections.Generic.List[string]]::new()
$AllowedFQDNs = [System.Collections.Generic.List[string]]::new()
$DCIPs        = [System.Collections.Generic.List[string]]::new()
$DNSIPs       = [System.Collections.Generic.List[string]]::new()

foreach ($rawLine in $lines) {
    $line = $rawLine.Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line.StartsWith("#"))               { continue }

    if ($line.StartsWith("IP:DC:")) {
        $DCIPs.Add($line.Replace("IP:DC:", "").Trim())
    } elseif ($line.StartsWith("IP:DNS:")) {
        $DNSIPs.Add($line.Replace("IP:DNS:", "").Trim())
    } elseif ($line.StartsWith("IP:")) {
        $AllowedIPs.Add($line.Replace("IP:", "").Trim())
    } else {
        $AllowedFQDNs.Add($line)
    }
}

Write-Log "Parsed: $($AllowedFQDNs.Count) FQDNs | $($AllowedIPs.Count) IPs | $($DCIPs.Count) DCs | $($DNSIPs.Count) DNS"

# ============================================
# STEP 5 — RESOLVE FQDNs TO IPs
# DNS is still open at this point (outbound = Allow)
# ============================================
Write-Log "STEP 5: Resolving FQDNs to IPs (outbound still open)..."

$ResolvedIPs = [System.Collections.Generic.List[string]]::new()
$FailedFQDNs = [System.Collections.Generic.List[string]]::new()

foreach ($fqdn in $AllowedFQDNs) {
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($fqdn) |
            Select-Object -ExpandProperty IPAddressToString
        if ($resolved.Count -gt 0) {
            foreach ($ip in $resolved) { $ResolvedIPs.Add($ip) }
            Write-Log "  OK: $fqdn -> $($resolved -join ', ')"
        } else {
            $FailedFQDNs.Add($fqdn)
            Write-Log "  WARN: No IPs for $fqdn" "WARN"
        }
    } catch {
        $FailedFQDNs.Add($fqdn)
        Write-Log "  WARN: Could not resolve ${fqdn}: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "Resolved: $($ResolvedIPs.Count) IPs from $($AllowedFQDNs.Count) FQDNs."
if ($FailedFQDNs.Count -gt 0) {
    Write-Log "$($FailedFQDNs.Count) FQDNs failed to resolve and will NOT be allowed." "WARN"
}

# Merge all allowed IPs
$AllAllowedIPs = ($ResolvedIPs + $AllowedIPs + $DCIPs + $DNSIPs + $GitHubBootstrapIPs) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Sort-Object -Unique

Write-Log "Total unique IPs/ranges to allow: $($AllAllowedIPs.Count)" "OK"

# Safety check
if ($AllAllowedIPs.Count -lt 5) {
    Write-Log "ABORT: Fewer than 5 IPs resolved. Whitelist may be empty." "ERROR"
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
    exit 1
}

# ============================================
# STEP 6 — BACKUP FIREWALL
# ============================================
Write-Log "STEP 6: Backing up firewall..."
try {
    $stamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $backup = "$BackupDir\fw_$stamp.wfw"
    netsh advfirewall export $backup | Out-Null
    Write-Log "Backup saved: $backup" "OK"
} catch {
    Write-Log "Backup failed (non-fatal): $_" "WARN"
    $backup = "none"
}

# ============================================
# STEP 7 — NOW LOCK DOWN
# Apply block THEN add specific allow rules
# Order matters: rules are added before block takes effect
# ============================================
Write-Log "STEP 7: Applying Zero Trust lockdown..."

# 7a — Set default BLOCK
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
Write-Log "Default outbound: BLOCK applied." "OK"

# 7b — Loopback
New-NetFirewallRule `
    -DisplayName "$Prefix-Loopback" `
    -Direction Outbound `
    -RemoteAddress "127.0.0.1","::1" `
    -Action Allow -Profile Any | Out-Null
Write-Log "Loopback allowed."

# 7c — DNS (locked to whitelist DNS servers only)
if ($DNSIPs.Count -gt 0) {
    New-NetFirewallRule `
        -DisplayName "$Prefix-DNS-UDP" `
        -Direction Outbound -Protocol UDP `
        -RemotePort 53 -RemoteAddress $DNSIPs `
        -Action Allow -Profile Any | Out-Null

    New-NetFirewallRule `
        -DisplayName "$Prefix-DNS-TCP" `
        -Direction Outbound -Protocol TCP `
        -RemotePort 53 -RemoteAddress $DNSIPs `
        -Action Allow -Profile Any | Out-Null

    Write-Log "DNS allowed to: $($DNSIPs -join ', ')" "OK"
} else {
    Write-Log "No DNS IPs in whitelist." "WARN"
}

# 7d — HTTPS + HTTP to whitelisted IPs (chunked, 100 per rule)
$chunkSize = 100
$chunkNum  = 1
for ($i = 0; $i -lt $AllAllowedIPs.Count; $i += $chunkSize) {
    $chunk = $AllAllowedIPs[$i..([Math]::Min($i + $chunkSize - 1, $AllAllowedIPs.Count - 1))]

    New-NetFirewallRule `
        -DisplayName "$Prefix-Allow-HTTPS-$chunkNum" `
        -Direction Outbound -Protocol TCP `
        -RemotePort 443 -RemoteAddress $chunk `
        -Action Allow -Profile Any | Out-Null

    New-NetFirewallRule `
        -DisplayName "$Prefix-Allow-HTTP-$chunkNum" `
        -Direction Outbound -Protocol TCP `
        -RemotePort 80 -RemoteAddress $chunk `
        -Action Allow -Profile Any | Out-Null

    $chunkNum++
}
Write-Log "HTTPS/HTTP rules created for $($AllAllowedIPs.Count) IPs in $($chunkNum - 1) chunks." "OK"

# 7e — GitHub ranges always allowed (so future whitelist updates work)
New-NetFirewallRule `
    -DisplayName "$Prefix-Allow-GitHub-Bootstrap" `
    -Direction Outbound -Protocol TCP `
    -RemotePort 443 -RemoteAddress $GitHubBootstrapIPs `
    -Action Allow -Profile Any | Out-Null
Write-Log "GitHub IP ranges permanently allowed for whitelist updates." "OK"

# 7f — Bootstrap DNS always allowed (for resolving GitHub)
New-NetFirewallRule `
    -DisplayName "$Prefix-Allow-Bootstrap-DNS" `
    -Direction Outbound -Protocol UDP `
    -RemotePort 53 -RemoteAddress $BootstrapDNS `
    -Action Allow -Profile Any | Out-Null
Write-Log "Bootstrap DNS (8.8.8.8, 1.1.1.1) allowed for GitHub resolution." "OK"

# 7g — AD ports for DC IPs only
foreach ($dc in $DCIPs) {
    foreach ($port in $ADPorts) {
        New-NetFirewallRule `
            -DisplayName "$Prefix-AD-TCP-$port-$dc" `
            -Direction Outbound -Protocol TCP `
            -RemotePort $port -RemoteAddress $dc `
            -Action Allow -Profile Any | Out-Null
    }
    foreach ($port in $ADPortsUDP) {
        New-NetFirewallRule `
            -DisplayName "$Prefix-AD-UDP-$port-$dc" `
            -Direction Outbound -Protocol UDP `
            -RemotePort $port -RemoteAddress $dc `
            -Action Allow -Profile Any | Out-Null
    }
    New-NetFirewallRule `
        -DisplayName "$Prefix-AD-RPC-$dc" `
        -Direction Outbound -Protocol TCP `
        -RemotePort $RPCDynamic -RemoteAddress $dc `
        -Action Allow -Profile Any | Out-Null
    Write-Log "AD ports opened for DC: $dc" "OK"
}

# ============================================
# STEP 8 — DISABLE BROAD BUILT-IN ALLOW RULES
# ============================================
Write-Log "STEP 8: Disabling broad built-in allow-all outbound rules..."
$killed = 0

$allOutbound = Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
foreach ($rule in $allOutbound) {
    if ($rule.DisplayName -like "$Prefix-*") { continue }
    try {
        $pf = $rule | Get-NetFirewallPortFilter    -ErrorAction SilentlyContinue
        $af = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $xf = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue

        if (($pf.RemotePort -eq "Any") -and
            ($af.RemoteAddress -eq "Any") -and
            ($xf.Program -eq "Any" -or $xf.Program -eq "*")) {
            $rule | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
            Write-Log "  Disabled: $($rule.DisplayName)"
            $killed++
        }
    } catch {
        # Non-fatal, continue
    }
}
Write-Log "Disabled $killed broad allow-all rules." "OK"

# ============================================
# STEP 9 — CREATE USER BLOCK PAGE
# ============================================
Write-Log "STEP 9: Creating user block notification page..."
$blockHtml = @'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Access Blocked - IT Security</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: "Segoe UI", Arial, sans-serif;
    background: #0f0f1a;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #1a1a2e;
    border: 2px solid #e63946;
    border-radius: 14px;
    padding: 52px 60px;
    max-width: 580px;
    width: 90%;
    text-align: center;
    box-shadow: 0 0 60px rgba(230,57,70,0.25);
  }
  .shield { font-size: 72px; margin-bottom: 20px; }
  h1 { color: #e63946; font-size: 30px; margin-bottom: 14px; letter-spacing: 1px; }
  .subtitle { color: #888; font-size: 15px; margin-bottom: 24px; line-height: 1.6; }
  .domain-box {
    background: #0d0d1a;
    border: 1px solid #333;
    border-radius: 8px;
    padding: 12px 20px;
    font-family: "Courier New", monospace;
    font-size: 15px;
    color: #e63946;
    margin: 20px 0;
    word-break: break-all;
  }
  .info { color: #aaa; font-size: 14px; line-height: 1.7; margin-bottom: 28px; }
  .contact {
    background: #16213e;
    border-radius: 8px;
    padding: 16px 24px;
    font-size: 13px;
    color: #7a8ba6;
    margin-top: 24px;
  }
  .contact strong { color: #a8c0e0; }
  .footer { margin-top: 22px; font-size: 11px; color: #444; }
</style>
</head>
<body>
<div class="card">
  <div class="shield">&#128683;</div>
  <h1>ACCESS BLOCKED</h1>
  <p class="subtitle">This website is not on the approved list and has been blocked by your organisation's IT security policy.</p>
  <div class="domain-box" id="blocked-domain">Restricted Site</div>
  <p class="info">
    If you need access to this site for work purposes,<br>
    please contact your IT administrator and request<br>
    it to be added to the approved list.
  </p>
  <div class="contact">
    <strong>IT Support:</strong> Contact your system administrator<br>
    <strong>Policy:</strong> Zero Trust Network Access<br>
    <strong>Action:</strong> This attempt has been logged
  </div>
  <div class="footer">Enforced by Zero Trust Security Policy &mdash; All blocked attempts are recorded</div>
</div>
<script>
  try {
    var h = window.location.hostname;
    if (h) document.getElementById("blocked-domain").textContent = h;
  } catch(e) {}
</script>
</body>
</html>
'@
Set-Content -Path $BlockPage -Value $blockHtml -Encoding UTF8
Write-Log "Block page written to $BlockPage" "OK"

# ============================================
# STEP 10 — BLOCK PAGE LISTENER
# Serves block page on 127.0.0.1:80 so users
# see a proper page instead of a timeout error
# ============================================
Write-Log "STEP 10: Registering block page listener..."

$listenerCmd = "-NonInteractive -WindowStyle Hidden -Command `"`$l=New-Object Net.HttpListener;`$l.Prefixes.Add('http://127.0.0.1:8080/');`$l.Start();while(`$l.IsListening){try{`$c=`$l.GetContext();`$r=`$c.Response;`$b=[IO.File]::ReadAllBytes('C:\ZeroTrust\blocked.html');`$r.ContentType='text/html';`$r.ContentLength64=`$b.Length;`$r.OutputStream.Write(`$b,0,`$b.Length);`$r.OutputStream.Close()}catch{}}`""

$existingTask = Get-ScheduledTask -TaskName "ZT-BlockPage" -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName "ZT-BlockPage" -Confirm:$false
}

$tAction   = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $listenerCmd
$tTrigger  = New-ScheduledTaskTrigger -AtStartup
$tSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$tPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask `
    -TaskName "ZT-BlockPage" `
    -Action $tAction `
    -Trigger $tTrigger `
    -Settings $tSettings `
    -Principal $tPrincipal `
    -Force | Out-Null

Start-ScheduledTask -TaskName "ZT-BlockPage" -ErrorAction SilentlyContinue
Write-Log "Block page listener started on 127.0.0.1:8080" "OK"

# Allow local listener traffic
New-NetFirewallRule `
    -DisplayName "$Prefix-Allow-BlockPage-Listener" `
    -Direction Outbound `
    -Protocol TCP `
    -RemoteAddress "127.0.0.1" `
    -RemotePort 8080 `
    -Action Allow -Profile Any | Out-Null

# ============================================
# STEP 11 — LOCK HOSTS FILE
# ============================================
Write-Log "STEP 11: Locking hosts file against tampering..."
try {
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $acl  = Get-Acl $hostsPath
    $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Users", "Write,Delete", "Deny")
    $acl.AddAccessRule($deny)
    Set-Acl $hostsPath $acl
    Write-Log "Hosts file locked." "OK"
} catch {
    Write-Log "Could not lock hosts file: $_" "WARN"
}

# ============================================
# STEP 12 — ENABLE FIREWALL LOGGING
# ============================================
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogAllowed True `
    -LogBlocked True `
    -LogMaxSizeKilobytes 32767 `
    -LogFileName "C:\ZeroTrust\firewall.log"
Write-Log "Firewall logging enabled." "OK"

# ============================================
# FLUSH DNS
# ============================================
ipconfig /flushdns | Out-Null
Write-Log "DNS cache flushed." "OK"

# ============================================
# FINAL SUMMARY
# ============================================
$totalRules = (Get-NetFirewallRule -DisplayName "$Prefix-*" -ErrorAction SilentlyContinue).Count
Write-Log "============================================"
Write-Log "COMPLETE." "OK"
Write-Log "Rules applied      : $totalRules"
Write-Log "IPs allowed        : $($AllAllowedIPs.Count)"
Write-Log "FQDNs resolved     : $($AllowedFQDNs.Count - $FailedFQDNs.Count) / $($AllowedFQDNs.Count)"
Write-Log "Built-in disabled  : $killed"
Write-Log "Cache file         : $CachedList"
Write-Log "Block page         : $BlockPage"
Write-Log "Log                : $LogFile"
Write-Log "Firewall log       : C:\ZeroTrust\firewall.log"
Write-Log "Restore command    : netsh advfirewall import '$backup'"
Write-Log "============================================"
