$ErrorActionPreference = 'Stop'
$localDir = Join-Path (Split-Path $PSScriptRoot -Parent) '.local'
$privatePath = Join-Path $localDir 'auth-private.pem'
$publicPath = Join-Path $localDir 'auth-public.pem'
$envPath = Join-Path $localDir 'auth-local.ps1'
$clientPath = Join-Path $localDir 'client-keys.ps1'
if ((Test-Path -LiteralPath $privatePath) -or (Test-Path -LiteralPath $publicPath) -or
    (Test-Path -LiteralPath $envPath) -or (Test-Path -LiteralPath $clientPath)) {
    throw 'Local Auth files already exist. Refusing to overwrite keys or credentials.'
}
New-Item -ItemType Directory -Path $localDir -Force | Out-Null
& java (Join-Path $PSScriptRoot 'GenerateLocalKey.java') $privatePath $publicPath
if ($LASTEXITCODE -ne 0) { throw 'RSA key generation failed.' }
function New-Key {
    $bytes = New-Object byte[] 48
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
function Get-Hash([string]$value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value)) }
    finally { $sha.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}
$bff = New-Key
$project = New-Key
$interview = New-Key
$settings = @(
    "`$env:AUTH_ISSUER='http://127.0.0.1:18080'",
    "`$env:AUTH_AUDIENCE='devfield-user-api-local'",
    "`$env:AUTH_PRIVATE_KEY_PATH='$privatePath'",
    "`$env:AUTH_PUBLIC_KEY_PATH='$publicPath'",
    "`$env:AUTH_WEB_VERIFY_URL='http://127.0.0.1:13000/verify-email'",
    "`$env:AUTH_MAIL_FROM='devfield-local@example.test'",
    "`$env:AUTH_SMTP_HOST='127.0.0.1'",
    "`$env:AUTH_SMTP_PORT='1025'",
    "`$env:AUTH_BFF_KEY_SHA256='$(Get-Hash $bff)'",
    "`$env:AUTH_PROJECT_KEY_SHA256='$(Get-Hash $project)'",
    "`$env:AUTH_INTERVIEW_KEY_SHA256='$(Get-Hash $interview)'"
)
[System.IO.File]::WriteAllLines($envPath, $settings)
[System.IO.File]::WriteAllLines($clientPath, @(
    "`$env:DEVFIELD_BFF_SERVICE_KEY='$bff'",
    "`$env:DEVFIELD_PROJECT_SERVICE_KEY='$project'",
    "`$env:DEVFIELD_INTERVIEW_SERVICE_KEY='$interview'"
))
Write-Output 'Local Auth keys and environment files created under ignored .local/.'
