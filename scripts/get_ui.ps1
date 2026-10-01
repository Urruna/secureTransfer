# ============================================================================
#  SecureTransfer - download the latest Windows UI package from GitHub Releases
#
#  Usage (PowerShell, run from anywhere):
#      powershell -ExecutionPolicy Bypass -File scripts\get_ui.ps1
#      powershell -ExecutionPolicy Bypass -File scripts\get_ui.ps1 -Token ghp_xxx
#      powershell -ExecutionPolicy Bypass -File scripts\get_ui.ps1 -Dest D:\demo
#
#  Notes:
#    * The repository is private, so a GitHub token (repo scope) is required;
#      the script also reads the GH_TOKEN environment variable.
#    * Output: <Dest>\securityTransfer\  (run run_ui.bat inside it)
# ============================================================================
param(
    [string]$Token = $env:GH_TOKEN,
    [string]$Dest = "dist",
    [string]$Repo = "Urruna/secureTransfer",
    [string]$AssetName = "securityTransfer-ui-win64.zip"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{ "User-Agent" = "secureTransfer-get-ui"; Accept = "application/vnd.github+json" }
if ($Token) { $headers["Authorization"] = "token $Token" }

Write-Host "[1/3] Query latest release of $Repo ..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
$asset = $release.assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1
if (-not $asset) { throw "Asset '$AssetName' not found in release $($release.tag_name)" }
Write-Host ("      tag = {0}, size = {1} MB" -f $release.tag_name, [math]::Round($asset.size / 1MB, 2))

$destPath = Join-Path (Get-Location) $Dest
New-Item -ItemType Directory -Force -Path $destPath | Out-Null
$zipPath = Join-Path $destPath $AssetName

Write-Host "[2/3] Download ..."
$downloadHeaders = @{ "User-Agent" = $headers["User-Agent"]; Accept = "application/octet-stream" }
if ($Token) { $downloadHeaders["Authorization"] = "token $Token" }
Invoke-WebRequest -Uri $asset.url -Headers $downloadHeaders -OutFile $zipPath

$sha = (Get-FileHash $zipPath -Algorithm SHA256).Hash
Write-Host ("      downloaded: {0} ({1} MB)" -f $zipPath, [math]::Round((Get-Item $zipPath).Length / 1MB, 2))
Write-Host ("      SHA-256   : {0}" -f $sha)

Write-Host "[3/3] Extract ..."
if (Test-Path (Join-Path $destPath "securityTransfer")) {
    Remove-Item (Join-Path $destPath "securityTransfer") -Recurse -Force
}
Expand-Archive -Path $zipPath -DestinationPath $destPath -Force
Remove-Item $zipPath -Force

$appDir = Join-Path $destPath "securityTransfer"
Write-Host ""
Write-Host "Done. Next steps:"
Write-Host ("  1. copy {0}\configs\keys.conf.example to keys.conf and fill K_master" -f $appDir)
Write-Host ("  2. double-click {0}\run_ui.bat" -f $appDir)
