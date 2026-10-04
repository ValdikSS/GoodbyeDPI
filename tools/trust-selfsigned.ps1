<#
.SYNOPSIS
  Makes this machine trust the self-signed certificate made by sign-selfsigned.ps1.

.DESCRIPTION
  Imports goodbyedpi-selfsigned.cer into the LOCAL MACHINE "Trusted Root
  Certification Authorities" and "Trusted Publishers" stores. Run as
  Administrator.

  This is a security setting: anything signed with this certificate will be
  trusted on this machine. The private key exists only in your user profile,
  but only do this on a machine you control. Undo it with:
      .\tools\trust-selfsigned.ps1 -Remove
#>
param(
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell."
}

$cer = Join-Path (Split-Path -Parent $PSScriptRoot) "goodbyedpi-selfsigned.cer"
if (-not (Test-Path $cer)) {
    throw "$cer not found. Run sign-selfsigned.ps1 first."
}

$thumb = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $cer).Thumbprint

foreach ($store in "Root", "TrustedPublisher") {
    if ($Remove) {
        Get-ChildItem "Cert:\LocalMachine\$store" | Where-Object Thumbprint -eq $thumb | Remove-Item
        Write-Host "Removed from LocalMachine\$store"
    } else {
        Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
        Write-Host "Added to LocalMachine\$store"
    }
}
