<#
  Checks every PowerShell script for Windows PowerShell 5.1 compatibility
  (the version every Windows guest has): syntax, commands and .NET types,
  using PSScriptAnalyzer's Windows Server 2019 profile. Exits 1 on problems.

    pwsh -NoProfile -File tools/lint_powershell.ps1
#>
param([string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path)
$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber
}
Import-Module PSScriptAnalyzer

$profile51 = 'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
$settings = @{
    IncludeRules = @('PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes')
    Rules = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @($profile51) }
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @($profile51) }
    }
}
# Modules the profile does not include but the scripts legitimately use on their hosts.
$external = '^(Get|New|Set|Start|Stop|Remove|Checkpoint|Restore|Enable|Connect|Copy|Invoke)-(VM|VHD|VMFirmware|VMKeyProtector|VMTPM|VMIntegrationService|VMHost|VMScript|VMGuestFile|Snapshot|Cluster|Datastore|Folder|ResourcePool|NetworkAdapter|VIServer|PowerCLIConfiguration|Pester|PesterConfiguration)$|^(Describe|It|Restore-VMSnapshot|Set-PowerCLIConfiguration)$'

$problems = 0
$files = Get-ChildItem -Path (Join-Path $Root 'patchlab_internal/ps'), (Join-Path $Root 'examples/windows') -Recurse -Filter *.ps1
foreach ($f in $files) {
    # Placeholders filled in by PatchLab Internal at run time.
    $text = (Get-Content -Raw -Path $f.FullName).Replace('__TIMEOUT__', '60').Replace('__PAYLOAD__', '')
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errors)
    foreach ($e in $errors) { $problems++; "{0}:{1} parse error: {2}" -f $f.Name, $e.Extent.StartLineNumber, $e.Message }
    foreach ($d in Invoke-ScriptAnalyzer -ScriptDefinition $text -Settings $settings) {
        if ($d.RuleName -eq 'PSUseCompatibleCommands' -and $d.Extent.Text -match $external) { continue }
        $problems++
        "{0}:{1} [{2}] {3}" -f $f.Name, $d.Line, $d.RuleName, ($d.Message -split "`n")[0]
    }
}
"checked $($files.Count) scripts: $problems problem(s)"
if ($problems) { exit 1 }
