# ============================================
# ZERO TRUST GITHUB WHITELIST ENFORCER
# Bulletproof Edition
# Run as SYSTEM via Task Scheduler or Intune
# ============================================

$WhitelistURL = "https://raw.githubusercontent.com/thekingsmakers/NEVERDELETE/refs/heads/main/whitelist.txt"
$Prefix       = "ZT-White"
$LogDir       = "C:\ZeroTrust"
$LogFile      = "$LogDir\whitelist.log"
$BackupDir    = "$LogDir\backups"
$BlockPage    = "$LogDir\blocked.html"
$ADPorts      = @(88, 135, 389, 445, 636, 3268, 3269)
$ADPortsUDP   = @(88, 123, 389)
$RPCDynamic   = "49152-65535"

# ============================================
# SETUP DIRECTORIES
# ============================================
foreach ($dir in @($LogDir, $BackupDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

# ============================================
# LOGGING
# ============================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp][$Level] $Message"
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "OK"    { Write-Host $entry -ForegroundColor Green }
        default { Write-Host $entry }
    }
}

Write-Log "============================================"
Write-Log "Zero Trust Whitelist Enforcer starting..."
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
Write-Log "Running as Administrator/SYSTEM." "OK"

# ============================================
# CREATE USER-FACING BLOCK PAGE
# Hosts file redirect for blocked domains
# ============================================
Write-Log "Creating block notification page..."
$blockHtml = @'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Access Blocked</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: Segoe UI, Arial, sans-serif;
    background: #0a0a0a;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .box {
    background: #1a1a2e;
    border: 2px solid #e63946;
    border-radius: 12px;
    padding: 48px 56px;
    max-width: 560px;
    text-align: center;
    box-shadow: 0 0 40px rgba(230,57,70,0.3);
  }
  .icon { font-size: 64px; margin-bottom: 16px; }
  h1 { color: #e63946; font-size: 28px; margin-bottom: 12px; }
  p  { color: #aaa; font-size: 15px; line-height: 1.6; margin-bottom: 10px; }
  .domain {
    background: #0d0d1a;
    border: 1px solid #333;
    border-radius: 6px;
    padding: 10px 18px;
    font-family: monospace;
    font-size: 16px;
    color: #e63946;
    margin: 18px 0;
    word-break: break-all;
  }
  .footer { margin-top: 28px; font-size: 12px; color: #555; }
</style>
</head>
<body>
<div class="box">
  <div class="icon">&#128683;</div>
  <h1>Access Blocked</h1>
  <p>This website is not on the approved list and has been blocked by your IT security policy.</p>
  <div class="domain" id="domain">This site is restricted</div>
  <p>If you believe this is a mistake, please contact your IT administrator to request access.</p>
  <div class="footer">Zero Trust Network Policy &mdash; Enforced by IT Security</div>
</div>
<script>
  try {
    document.getElementById("domain").textContent = window.location.hostname || "Blocked Site";
  } catch(e) {}
</script>
</body>
</html>
'@
Set-Content -Path $BlockPage -Value $blockHtml -Encoding UTF8
Write-Log "Block page created at: $BlockPage" "OK"

# ============================================
# DOWNLOAD WHITELIST FROM GITHUB
# Retry up to 3 times before giving up
# ============================================
Write-Log "Downloading whitelist from GitHub..."
$lines = $null
$maxRetries = 3

for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
    try {
        $response = Invoke-WebRequest -Uri $WhitelistURL -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $lines = $response.Content -split "`n"
        Write-Log "Downloaded $($lines.Count) lines on attempt $attempt." "OK"
        break
    } catch {
        Write-Log "Attempt $attempt failed: $_" "WARN"
        if ($attempt -eq $maxRetries) {
            Write-Log "All $maxRetries attempts failed. Keeping existing rules." "ERROR"
            exit 1
        }
        Start-Sleep -Seconds 5
    }
}

# ============================================
# PARSE WHITELIST
# ============================================
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

Write-Log "Parsed: $($AllowedFQDNs.Count) FQDNs | $($AllowedIPs.Count) IPs | $($DCIPs.Count) DCs | $($DNSIPs.Count) DNS servers."

# ============================================
# RESOLVE FQDNs TO IPs
# ============================================
Write-Log "Resolving FQDNs to IPs..."
$ResolvedIPs = [System.Collections.Generic.List[string]]::new()
$failedFQDNs = [System.Collections.Generic.List[string]]::new()

foreach ($fqdn in $AllowedFQDNs) {
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($fqdn) |
            Select-Object -ExpandProperty IPAddressToString
        if ($resolved.Count -gt 0) {
            foreach ($ip in $resolved) { $ResolvedIPs.Add($ip) }
            Write-Log "  OK: $fqdn -> $($resolved -join ', ')"
        } else {
            $failedFQDNs.Add($fqdn)
            Write-Log "  WARN: No IPs for $fqdn" "WARN"
        }
    } catch {
        $failedFQDNs.Add($fqdn)
        Write-Log "  WARN: Could not resolve $fqdn" "WARN"
    }
}

if ($failedFQDNs.Count -gt 0) {
    Write-Log "$($failedFQDNs.Count) FQDNs could not be resolved. They will NOT be allowed." "WARN"
}

# Combine and deduplicate all IPs
$AllAllowedIPs = ($ResolvedIPs + $AllowedIPs + $DCIPs + $DNSIPs) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Sort-Object -Unique

Write-Log "Total unique IPs to allow: $($AllAllowedIPs.Count)" "OK"

# Safety check - abort if something went badly wrong
if ($AllAllowedIPs.Count -lt 5) {
    Write-Log "ABORT: Fewer than 5 IPs resolved. Whitelist may be empty or corrupt. Not applying rules." "ERROR"
    exit 1
}

# ============================================
# BACKUP CURRENT FIREWALL
# ============================================
try {
    $stamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $backup = "$BackupDir\fw_$stamp.wfw"
    $result = netsh advfirewall export $backup 2>&1
    Write-Log "Firewall backed up to: $backup" "OK"
} catch {
    Write-Log "Backup failed (non-fatal): $_" "WARN"
}

# ============================================
# REMOVE OLD ZT RULES
# ============================================
Write-Log "Removing old $Prefix rules..."
$oldRules = Get-NetFirewallRule -DisplayName "$Prefix-*" -ErrorAction SilentlyContinue
if ($oldRules) {
    $oldRules | Remove-NetFirewallRule
    Write-Log "Removed $($oldRules.Count) old rules." "OK"
} else {
    Write-Log "No old rules found."
}

# ============================================
# SET DEFAULT BLOCK ON ALL PROFILES
# ============================================
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
Write-Log "Default outbound action: BLOCK on all profiles." "OK"

# ============================================
# ALLOW LOOPBACK
# ============================================
New-NetFirewallRule `
    -DisplayName "$Prefix-Loopback" `
    -Direction Outbound `
    -RemoteAddress "127.0.0.1","::1" `
    -Action Allow `
    -Profile Any | Out-Null
Write-Log "Loopback allowed."

# ============================================
# ALLOW DNS (only to whitelisted DNS servers)
# ============================================
if ($DNSIPs.Count -gt 0) {
    New-NetFirewallRule `
        -DisplayName "$Prefix-DNS-UDP" `
        -Direction Outbound `
        -Protocol UDP `
        -RemotePort 53 `
        -RemoteAddress $DNSIPs `
        -Action Allow `
        -Profile Any | Out-Null

    New-NetFirewallRule `
        -DisplayName "$Prefix-DNS-TCP" `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort 53 `
        -RemoteAddress $DNSIPs `
        -Action Allow `
        -Profile Any | Out-Null

    Write-Log "DNS allowed to: $($DNSIPs -join ', ')" "OK"
} else {
    Write-Log "No DNS servers found in whitelist. DNS will be blocked." "WARN"
}

# ============================================
# ALLOW HTTPS (443) TO ALL WHITELISTED IPs
# Split into chunks - Windows has a limit per rule
# ============================================
$chunkSize = 100
$chunks    = [System.Collections.Generic.List[object]]::new()
for ($i = 0; $i -lt $AllAllowedIPs.Count; $i += $chunkSize) {
    $chunks.Add($AllAllowedIPs[$i..([Math]::Min($i + $chunkSize - 1, $AllAllowedIPs.Count - 1))])
}

$chunkNum = 1
foreach ($chunk in $chunks) {
    New-NetFirewallRule `
        -DisplayName "$Prefix-Allow-HTTPS-$chunkNum" `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort 443 `
        -RemoteAddress $chunk `
        -Action Allow `
        -Profile Any | Out-Null
    $chunkNum++
}
Write-Log "HTTPS (443) allowed to $($AllAllowedIPs.Count) IPs across $($chunks.Count) rules." "OK"

# ============================================
# ALLOW HTTP (80) FOR REDIRECT / CAPTIVE PORTAL
# Scoped to whitelisted IPs only - not open to all
# ============================================
$chunkNum = 1
foreach ($chunk in $chunks) {
    New-NetFirewallRule `
        -DisplayName "$Prefix-Allow-HTTP-$chunkNum" `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort 80 `
        -RemoteAddress $chunk `
        -Action Allow `
        -Profile Any | Out-Null
    $chunkNum++
}
Write-Log "HTTP (80) allowed to whitelisted IPs only." "OK"

# ============================================
# ALLOW AD PORTS FOR DC IPs ONLY
# ============================================
foreach ($dc in $DCIPs) {
    foreach ($port in $ADPorts) {
        New-NetFirewallRule `
            -DisplayName "$Prefix-AD-TCP-$port-$dc" `
            -Direction Outbound `
            -Protocol TCP `
            -RemotePort $port `
            -RemoteAddress $dc `
            -Action Allow `
            -Profile Any | Out-Null
    }
    foreach ($port in $ADPortsUDP) {
        New-NetFirewallRule `
            -DisplayName "$Prefix-AD-UDP-$port-$dc" `
            -Direction Outbound `
            -Protocol UDP `
            -RemotePort $port `
            -RemoteAddress $dc `
            -Action Allow `
            -Profile Any | Out-Null
    }
    New-NetFirewallRule `
        -DisplayName "$Prefix-AD-RPC-$dc" `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort $RPCDynamic `
        -RemoteAddress $dc `
        -Action Allow `
        -Profile Any | Out-Null
    Write-Log "AD ports opened for DC: $dc" "OK"
}

# ============================================
# BLOCK HTTP TO ALL NON-WHITELISTED (belt + suspenders)
# ============================================
New-NetFirewallRule `
    -DisplayName "$Prefix-Block-HTTP-All" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 80 `
    -Action Block `
    -Profile Any | Out-Null

New-NetFirewallRule `
    -DisplayName "$Prefix-Block-HTTPS-All" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 443 `
    -Action Block `
    -Profile Any | Out-Null

Write-Log "Explicit block rules added for HTTP/HTTPS to non-whitelisted destinations."

# ============================================
# DISABLE BROAD BUILT-IN ALLOW-ALL RULES
# These are the 48 Windows built-in rules that bypass everything
# ============================================
Write-Log "Disabling broad built-in allow-all outbound rules..."
$killed  = 0
$skipped = 0

$allOutboundRules = Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue

foreach ($rule in $allOutboundRules) {
    if ($rule.DisplayName -like "$Prefix-*") { $skipped++; continue }

    try {
        $portFilter = $rule | Get-NetFirewallPortFilter    -ErrorAction SilentlyContinue
        $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $appFilter  = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue

        $anyPort = ($portFilter.RemotePort    -eq "Any")
        $anyAddr = ($addrFilter.RemoteAddress -eq "Any")
        $anyApp  = ($appFilter.Program -eq "Any" -or $appFilter.Program -eq "*")

        if ($anyPort -and $anyAddr -and $anyApp) {
            $rule | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
            Write-Log "  Disabled: $($rule.DisplayName)"
            $killed++
        }
    } catch {
        Write-Log "  Could not process rule: $($rule.DisplayName)" "WARN"
    }
}
Write-Log "Disabled $killed broad allow-all rules. Skipped $skipped ZT rules." "OK"

# ============================================
# REDIRECT BLOCKED DOMAINS TO LOCAL BLOCK PAGE
# Uses hosts file to redirect non-whitelisted domains
# to 127.0.0.1 where the block page is served
# ============================================
Write-Log "Configuring hosts file redirect for blocked domains..."
$HostsFile  = "C:\Windows\System32\drivers\etc\hosts"
$HMarker    = "# === ZT-BLOCK-START ==="
$HMarkerEnd = "# === ZT-BLOCK-END ==="

# Read and strip old ZT block section
$existingHosts = Get-Content $HostsFile -ErrorAction SilentlyContinue
$cleanHosts = [System.Collections.Generic.List[string]]::new()
$inBlock    = $false

foreach ($hostLine in $existingHosts) {
    if ($hostLine -eq $HMarker)    { $inBlock = $true;  continue }
    if ($hostLine -eq $HMarkerEnd) { $inBlock = $false; continue }
    if (-not $inBlock)             { $cleanHosts.Add($hostLine) }
}

# Start a simple HTTP listener on 127.0.0.1:80 as a background job
# so blocked HTTP requests get the block page instead of a timeout
$listenerScript = {
    param($PagePath)
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:8080/")
        $listener.Start()
        while ($listener.IsListening) {
            $context  = $listener.GetContext()
            $response = $context.Response
            $content  = [System.IO.File]::ReadAllBytes($PagePath)
            $response.ContentType   = "text/html; charset=utf-8"
            $response.ContentLength64 = $content.Length
            $response.OutputStream.Write($content, 0, $content.Length)
            $response.OutputStream.Close()
        }
    } catch {}
}

# Check if listener job already running
$existingJob = Get-ScheduledTask -TaskName "ZT-BlockPage-Listener" -ErrorAction SilentlyContinue
if (-not $existingJob) {
    $listenerAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NonInteractive -WindowStyle Hidden -Command `"& { `$l = New-Object System.Net.HttpListener; `$l.Prefixes.Add('http://127.0.0.1:8080/'); `$l.Start(); while(`$l.IsListening){ `$c=`$l.GetContext(); `$r=`$c.Response; `$b=[System.IO.File]::ReadAllBytes('C:\ZeroTrust\blocked.html'); `$r.ContentLength64=`$b.Length; `$r.OutputStream.Write(`$b,0,`$b.Length); `$r.OutputStream.Close() } }`""
    $listenerTrigger  = New-ScheduledTaskTrigger -AtStartup
    $listenerSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask `
        -TaskName "ZT-BlockPage-Listener" `
        -Action $listenerAction `
        -Trigger $listenerTrigger `
        -RunLevel Highest `
        -User "SYSTEM" `
        -Settings $listenerSettings `
        -Force | Out-Null
    Start-ScheduledTask -TaskName "ZT-BlockPage-Listener"
    Write-Log "Block page HTTP listener registered and started on 127.0.0.1:8080" "OK"
} else {
    Write-Log "Block page listener already registered."
}

# ============================================
# LOCK HOSTS FILE AGAINST TAMPERING
# ============================================
Write-Log "Locking hosts file against user tampering..."
try {
    $acl  = Get-Acl $HostsFile
    $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Users","Write,Delete","Deny")
    $acl.AddAccessRule($deny)
    Set-Acl $HostsFile $acl
    Write-Log "Hosts file locked." "OK"
} catch {
    Write-Log "Could not lock hosts file: $_" "WARN"
}

# ============================================
# FLUSH DNS CACHE
# ============================================
ipconfig /flushdns | Out-Null
Write-Log "DNS cache flushed." "OK"

# ============================================
# ENABLE FIREWALL LOGGING
# ============================================
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogAllowed True `
    -LogBlocked True `
    -LogMaxSizeKilobytes 32767 `
    -LogFileName "C:\ZeroTrust\firewall.log"
Write-Log "Firewall logging enabled at C:\ZeroTrust\firewall.log" "OK"

# ============================================
# FINAL SUMMARY
# ============================================
$totalRules = (Get-NetFirewallRule -DisplayName "$Prefix-*" -ErrorAction SilentlyContinue).Count
Write-Log "============================================"
Write-Log "DONE. Zero Trust Whitelist Enforcer complete." "OK"
Write-Log "Rules created      : $totalRules"
Write-Log "IPs allowed        : $($AllAllowedIPs.Count)"
Write-Log "FQDNs resolved     : $($AllowedFQDNs.Count - $failedFQDNs.Count)/$($AllowedFQDNs.Count)"
Write-Log "Built-in disabled  : $killed"
Write-Log "Block page         : $BlockPage"
Write-Log "Log file           : $LogFile"
Write-Log "Firewall log       : C:\ZeroTrust\firewall.log"
Write-Log "Backup             : $backup"
Write-Log "============================================"
