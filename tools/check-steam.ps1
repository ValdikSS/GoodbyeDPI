<#
.SYNOPSIS
  Shows which IPs of a Steam hostname are reachable, and whether the hostname
  in the TLS handshake (SNI) makes a difference.

.DESCRIPTION
  Collects the IPs the name resolves to (system resolver plus plain DNS to
  1.1.1.1, 8.8.8.8 and 9.9.9.9), then for each IP connects twice, three times:
    - with the Steam hostname as SNI
    - with a neutral hostname as SNI (www.example.com)
  The neutral request is only used to see whether the TLS handshake gets
  through, certificate errors are ignored (-k) and nothing is sent to the
  server besides a GET /.

  Reading the result:
    steam OK,  neutral OK   -> this IP is reachable
    steam FAIL, neutral OK  -> blocked by hostname (what goodbyedpi can help with)
    steam FAIL, neutral FAIL-> IP/port unreachable (goodbyedpi cannot help)

  Run it once without goodbyedpi and once with it running; the "steam FAIL,
  neutral OK" rows should flip to OK.

.EXAMPLE
  .\tools\check-steam.ps1
  .\tools\check-steam.ps1 -HostName steamcommunity.com
  .\tools\check-steam.ps1 -Ip 23.15.142.182 -Tries 25
#>
param(
    [string]$HostName = "store.steampowered.com",
    [int]$Tries = 3,
    [int]$TimeoutSeconds = 6,
    # Test only this IP (skips DNS). Use with a larger -Tries to compare presets.
    [string]$Ip
)

$ips = [System.Collections.Generic.HashSet[string]]::new()

function Add-Ips($records) {
    $records | Where-Object Type -eq 'A' | ForEach-Object { [void]$ips.Add($_.IPAddress) }
}

if ($Ip) {
    [void]$ips.Add($Ip)
} else {
    try { Add-Ips (Resolve-DnsName $HostName -Type A -DnsOnly -ErrorAction Stop) } catch {}
    foreach ($round in 1..3) {
        foreach ($server in "1.1.1.1", "8.8.8.8", "9.9.9.9") {
            try { Add-Ips (Resolve-DnsName $HostName -Type A -Server $server -DnsOnly -ErrorAction Stop) } catch {}
        }
        Start-Sleep -Milliseconds 700
    }
}

if ($ips.Count -eq 0) {
    Write-Host "Could not resolve $HostName at all (DNS problem)."
    exit 1
}

function Test-Sni($ip, $sni) {
    $ok = 0
    foreach ($i in 1..$Tries) {
        # TLS handshake completing is enough; any HTTP status counts as reachable
        $code = curl.exe -k -s -o NUL -m $TimeoutSeconds --resolve "${sni}:443:$ip" `
                    -w "%{http_code}" "https://$sni/" 2>$null
        if ($code -and $code -ne "000") { $ok++ }
    }
    return $ok
}

Write-Host "$HostName resolves to $($ips.Count) IP(s). $Tries tries each.`n"

$rows = foreach ($ip in ($ips | Sort-Object)) {
    $steam = Test-Sni $ip $HostName
    $neutral = Test-Sni $ip "www.example.com"
    $verdict = if ($steam -eq $Tries) { "reachable" }
               elseif ($neutral -eq $Tries) { "BLOCKED BY HOSTNAME" }
               elseif ($steam -eq 0 -and $neutral -eq 0) { "IP unreachable" }
               else { "unstable" }
    [pscustomobject]@{
        IP      = $ip
        Steam   = "$steam/$Tries"
        Neutral = "$neutral/$Tries"
        Verdict = $verdict
    }
}

$rows | Format-Table -AutoSize
