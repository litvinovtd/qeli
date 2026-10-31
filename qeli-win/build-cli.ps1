param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist/cli'),
    [string]$NativeCorePath = $env:QeliNativeCorePath
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $NativeCorePath) { $NativeCorePath = Join-Path $PSScriptRoot 'QeliWin/native/qeli.dll' }
$NativeCorePath = [IO.Path]::GetFullPath($NativeCorePath)
if (-not (Test-Path -LiteralPath $NativeCorePath -PathType Leaf)) { throw 'Native core is missing' }
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'Output directory already exists; choose a new path' }
$parent = Split-Path -Parent $destination
[IO.Directory]::CreateDirectory($parent) | Out-Null
$staging = Join-Path $parent ('.qeli-cli-build-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null
Push-Location $repo
try {
    # global.json selects the exact reviewed SDK. Do not substitute another installed SDK.
    & dotnet build scripts/embedded_license_reader/Reader.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Metadata reader build failed' }
    $reader = Join-Path $repo 'scripts/embedded_license_reader/bin/Release/net10.0/Reader.dll'
    $project = [xml](Get-Content -Raw (Join-Path $PSScriptRoot 'QeliCli/QeliCli.csproj'))
    $version = [string]$project.Project.PropertyGroup.Version
    $epoch = & git show -s --format=%ct HEAD
    if ($LASTEXITCODE -ne 0 -or $epoch -notmatch '^\d+$') { throw 'Cannot determine committed package timestamp' }
    foreach ($variant in @('net-required', 'standalone')) {
        $selfContained = if ($variant -eq 'standalone') { 'true' } else { 'false' }
        $output = Join-Path $staging $variant
        & dotnet publish qeli-win/QeliCli/QeliCli.csproj -c Release -r win-x64 --self-contained $selfContained "-p:QeliNativeCorePath=$NativeCorePath" -o $output
        if ($LASTEXITCODE -ne 0) { throw "CLI publication failed: $variant" }
        & python -B scripts/check_windows_embedded_licenses.py --repo $repo --directory $output --entry-assembly qeli-cli.dll --native-core $NativeCorePath --reader $reader
        if ($LASTEXITCODE -ne 0) { throw "CLI original resource admission failed: $variant" }
        $fixture = Join-Path $staging 'validate.ini'
        [IO.File]::WriteAllText($fixture, "[qeli]`nserver = 192.0.2.1:443`nuser = fixture`npass = fixture`n", [Text.UTF8Encoding]::new($false))
        & (Join-Path $output 'qeli-cli.exe') config validate --config $fixture --json
        if ($LASTEXITCODE -ne 0) { throw "CLI/native parser compatibility failed: $variant" }
        Remove-Item -LiteralPath $fixture
        $archive = Join-Path $staging "qeli-cli-windows-x64-$variant.zip"
        & python -B scripts/package_windows_cli.py --source $output --output $archive --variant $variant --version $version --epoch $epoch
        if ($LASTEXITCODE -ne 0) { throw "CLI archive verification failed: $variant" }
    }
    [IO.Directory]::Move($staging, $destination)
    Write-Output "Built CLI packages: $destination"
} finally {
    Pop-Location
    if (Test-Path -LiteralPath $staging) {
        $resolved = (Get-Item -LiteralPath $staging).FullName
        if ((Split-Path -Parent $resolved) -ne $parent -or (Split-Path -Leaf $resolved) -notlike '.qeli-cli-build-*') { throw 'Unsafe staging cleanup target' }
        if ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked staging cleanup refused' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
