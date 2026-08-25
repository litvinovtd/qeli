$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$expectedVersion = '0.14.1'
$expectedHash = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
$expectedSigner = 'WireGuard LLC'
$expectedThumbprint = 'DF98E075A012ED8C86FBCF14854B8F9555CB3D45'
$expectedLicenseHash = '9AAF948856CE8845A762121306039EF09D0EEB4D9E4F4C355647D4081E818087'
$paths = @(
    (Join-Path $repo 'native-libs\third-party\windows-x64\wintun.dll'),
    (Join-Path $repo 'qeli-win\QeliWin\wintun\wintun.dll')
)

foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "missing pinned driver: $path"
    }
    $item = Get-Item -LiteralPath $path
    if ($item.VersionInfo.FileVersion -ne $expectedVersion) {
        throw "${path}: Wintun version '$($item.VersionInfo.FileVersion)', expected '$expectedVersion'"
    }
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($hash -ne $expectedHash) {
        throw "${path}: SHA-256 $hash, expected $expectedHash"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "${path}: Authenticode is $($signature.Status): $($signature.StatusMessage)"
    }
    if (($signature.SignerCertificate.Subject -notlike "*$expectedSigner*") -or
        ($signature.SignerCertificate.Thumbprint -ne $expectedThumbprint)) {
        throw "${path}: unexpected signer '$($signature.SignerCertificate.Subject)' / $($signature.SignerCertificate.Thumbprint)"
    }
    Write-Host "OK Wintun ${expectedVersion}: $path"
}


$licensePaths = @(
    (Join-Path $repo 'native-libs\third-party\windows-x64\wintun-LICENSE.txt'),
    (Join-Path $repo 'qeli-win\QeliWin\wintun\LICENSE.txt')
)
foreach ($path in $licensePaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "missing Wintun prebuilt-binaries license: $path"
    }
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($hash -ne $expectedLicenseHash) {
        throw "${path}: license SHA-256 $hash, expected $expectedLicenseHash"
    }
    if (-not (Select-String -LiteralPath $path -Pattern '^Prebuilt Binaries License$' -Quiet)) {
        throw "${path}: not the Wintun Prebuilt Binaries License"
    }
    Write-Host "OK Wintun license: $path"
}
