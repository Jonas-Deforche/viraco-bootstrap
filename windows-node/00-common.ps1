# C:\Viraco\bootstrap\00-common.ps1

Set-StrictMode -Version Latest

function Require-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

  if (-not $isAdmin) {
    throw "Run PowerShell as Administrator."
  }
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Get-ViracoPaths {

  $base   = "C:\Viraco"
  $logs   = "$base\logs"
  $config = "$base\config"

  Ensure-Dir $base
  Ensure-Dir $logs
  Ensure-Dir $config

  return @{
    Base     = $base
    Logs     = $logs
    NodeJson = "$config\node.json"
  }
}

function New-Logger([string]$Name) {

  $p = Get-ViracoPaths

  $file = Join-Path `
    $p.Logs `
    ("{0}-{1}.log" -f $Name,(Get-Date).ToString("yyyyMMdd"))

  return @{
    Name = $Name
    File = $file
  }
}

function Write-Log($Logger,$Level,$Msg) {

  $ts = (Get-Date).ToString("s")
  $line = "[$ts][$($Logger.Name)][$Level] $Msg"

  Write-Host $line
  Add-Content $Logger.File $line
}

function Log-Info($L,$M){ Write-Log $L "INFO"  $M }
function Log-Warn($L,$M){ Write-Log $L "WARN"  $M }
function Log-Err ($L,$M){ Write-Log $L "ERROR" $M }

function Download-File($Logger,$Url,$Dest){

  Log-Info $Logger "Downloading $Url"

  Ensure-Dir (Split-Path $Dest)

  Invoke-WebRequest `
    -Uri $Url `
    -OutFile $Dest `
    -UseBasicParsing
}

function Has-Winget {
  return [bool](Get-Command winget -ErrorAction SilentlyContinue)
}

function Read-NodeConfig($Logger,$Path){

  if (-not $Path) { return $null }

  if (-not (Test-Path $Path)){
    throw "Config not found: $Path"
  }

  try {
    Get-Content $Path -Raw | ConvertFrom-Json
  }
  catch {
    Log-Err $Logger "Invalid JSON in $Path"
    throw
  }
}
