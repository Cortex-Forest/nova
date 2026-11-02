param(
    [Parameter(Mandatory = $true)]
    [string]$NetworkSeedFile,
    [Parameter(Mandatory = $true)]
    [string]$ConsensusSeedFile,
    [Parameter(Mandatory = $true)]
    [string]$SeedNodeId,
    [Parameter(Mandatory = $true)]
    [string]$SeedHostPort,
    [string]$TemplatePath,
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($TemplatePath)) {
    $TemplatePath = Join-Path $repo "deploy\akash\testnet-validator-1-sdl.template.yaml"
}
$NetworkSeedFile = (Resolve-Path -LiteralPath $NetworkSeedFile).Path
$ConsensusSeedFile = (Resolve-Path -LiteralPath $ConsensusSeedFile).Path
$TemplatePath = (Resolve-Path -LiteralPath $TemplatePath).Path

$expectedNodeId = "84f09573fd20a672b497cbfdbc198c604f39016365db19a56a5597351ec50f51"
$expectedConsensus = "ef1998838a628a74ad586b438554ab66c3ec04092d2e5a8318728c2c32650e86"
if ($SeedNodeId -notmatch "^[0-9a-f]{64}$") {
    throw "SeedNodeId must be 64 lowercase hex"
}
if ($SeedHostPort -notmatch "^[A-Za-z0-9.-]+:[0-9]{1,5}$") {
    throw "SeedHostPort must be <hostname>:<port>"
}

$keygen = Join-Path $repo "target\debug\yazimao-keygen.exe"
if (-not (Test-Path -LiteralPath $keygen)) {
    & cargo build -p nova-keygen --bin yazimao-keygen --locked
    if ($LASTEXITCODE -ne 0) {
        throw "yazimao-keygen build failed"
    }
}
& $keygen check-seed --seed-file $NetworkSeedFile --expect-pubkey $expectedNodeId
if ($LASTEXITCODE -ne 0) {
    throw "Network seed does not match Validator-1 NodeId"
}
& $keygen check-seed --seed-file $ConsensusSeedFile --expect-pubkey $expectedConsensus
if ($LASTEXITCODE -ne 0) {
    throw "Consensus seed does not match Validator-1 public key"
}

$networkSeed = (Get-Content -Raw -LiteralPath $NetworkSeedFile).Trim()
$consensusSeed = (Get-Content -Raw -LiteralPath $ConsensusSeedFile).Trim()
if ($networkSeed -notmatch "^[0-9a-f]{64}$" -or
    $consensusSeed -notmatch "^[0-9a-f]{64}$") {
    throw "Seed files must contain strict lowercase hex64"
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $root = Join-Path $env:TEMP ("nova-validator-1-secret-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $root | Out-Null
    $OutputPath = Join-Path $root "testnet-validator-1.sdl.yaml"
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite rendered SDL: $OutputPath"
}

$template = Get-Content -Raw -LiteralPath $TemplatePath
$rendered = $template.Replace("__SEED_NODE_ID__", $SeedNodeId).
    Replace("__SEED_HOST_PORT__", $SeedHostPort).
    Replace("__NETWORK_SEED_HEX__", $networkSeed).
    Replace("__VALIDATOR_SEED_HEX__", $consensusSeed)
if ($rendered -match "__[A-Z0-9_]+__") {
    throw "Rendered SDL still contains placeholders"
}
[IO.File]::WriteAllText($OutputPath, $rendered, $utf8NoBom)
try {
    $security = New-Object System.Security.AccessControl.FileSecurity
    $security.SetAccessRuleProtection($true, $false)
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $security.AddAccessRule($rule)
    Set-Acl -LiteralPath $OutputPath -AclObject $security
} catch {
    Remove-Item -LiteralPath $OutputPath -Force
    throw "Could not restrict rendered SDL permissions: $($_.Exception.Message)"
}

[pscustomobject]@{
    status = "RENDERED"
    output_path = ([IO.Path]::GetFullPath($OutputPath))
    output_sha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    validator_id = "f1e5f1e34bfbffd92e1b9ca6c5fd1daa9fc948b3b1e6a27a72394ef94011de99"
    validator_node_id = $expectedNodeId
    seed_peer = "$SeedNodeId@$SeedHostPort"
    contains_provider_visible_secrets = $true
    handling = "LOCAL_TEMP_ONLY_DO_NOT_COMMIT_OR_SHARE"
} | ConvertTo-Json -Depth 4
