<#
.SYNOPSIS
  Signs goodbyedpi.exe and goodbyedpi-tui.exe with a self-signed code signing certificate.

.DESCRIPTION
  Creates the certificate in your CurrentUser\My store the first time (5 years,
  RSA 3072 / SHA-256), then reuses it. The private key never leaves your
  machine and is not exported. Only the public certificate is written to
  goodbyedpi-selfsigned.cer, which is what trust-selfsigned.ps1 imports.

  No timestamp server is contacted, so nothing leaves your machine.
  WinDivert.dll and WinDivert64.sys are not touched.

.EXAMPLE
  .\tools\sign-selfsigned.ps1 -Folder .\dist
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Folder
)

$ErrorActionPreference = "Stop"
$subject = "CN=GoodbyeDPI fork (self-signed)"

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object { $_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating a new self-signed code signing certificate..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(5)
}

foreach ($name in "goodbyedpi.exe", "goodbyedpi-tui.exe") {
    $path = Join-Path $Folder $name
    if (-not (Test-Path $path)) {
        Write-Warning "$path not found, skipped"
        continue
    }
    $result = Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256
    Write-Host ("{0,-22} {1}" -f $name, $result.Status)
}

$cer = Join-Path (Split-Path -Parent $PSScriptRoot) "goodbyedpi-selfsigned.cer"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Write-Host "Public certificate: $cer"
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host "Until the certificate is trusted, the signature shows as untrusted (see trust-selfsigned.ps1)."
