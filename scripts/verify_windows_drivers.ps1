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

# The official WinDivert 2.2.2-A archive contains an unsigned user-space DLL.
# Pin its bytes; authenticate the kernel driver separately. Do not require a
# signature that upstream does not ship on the DLL.
$winDivertCopies = @(
    (Join-Path $repo 'native-libs\third-party\windows-x64\windivert'),
    (Join-Path $repo 'qeli-win\QeliWin\windivert')
)
$winDivertHashes = @{
    'WinDivert.dll' = 'C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2'
    'WinDivert64.sys' = '8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2'
    'LICENSE.txt' = 'C00A04BF0DCCA8F775DA2825A52AB3BD8A5F815F8087078DAEBE0D751F542812'
    'NOTICE.txt' = '27CF88D5FF9C7E76CE95377FF9C0B933472E5775879BAF112F5DF368F733C637'
}
foreach ($directory in $winDivertCopies) {
    foreach ($name in $winDivertHashes.Keys) {
        $path = Join-Path $directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "missing pinned WinDivert file: $path"
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $expected = $winDivertHashes[$name]
        # The application notice is intentionally a short redistribution notice;
        # the canonical source/provenance note has different text.
        if (($name -eq 'NOTICE.txt') -and ($directory -eq $winDivertCopies[1])) {
            $expected = '8018C935CCC84A5407CA3A9DC6C1613B75FED999B5092E05BF133136F6EDA785'
        }
        if ($hash -ne $expected) {
            throw "${path}: WinDivert SHA-256 $hash, expected $expected"
        }
    }
    $driver = Join-Path $directory 'WinDivert64.sys'
    if ((Get-Item -LiteralPath $driver).VersionInfo.FileVersion -ne '2.2') {
        throw "${driver}: unexpected WinDivert file version"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $driver
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "${driver}: Authenticode is $($signature.Status): $($signature.StatusMessage)"
    }
    if ($signature.SignerCertificate.Thumbprint -ne '043589F75FCE2795E7F2CC3E526D46784D5DDAB3') {
        throw "${driver}: unexpected WinDivert signer $($signature.SignerCertificate.Thumbprint)"
    }
    Write-Host "OK WinDivert 2.2.2-A driver, DLL and notices: $directory"
}
