# Test stand-ins for the ScheduledTasks module (not available off Windows): "running"
# a task starts its action as a background process.
$global:PLTasks = @{}
function New-ScheduledTaskAction { param($Execute, $Argument) [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) 'principal' }
function New-ScheduledTaskSettingsSet { param($ExecutionTimeLimit, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries) 'settings' }
function Register-ScheduledTask { param($TaskName, $TaskPath, $Action, $Principal, $Settings, [switch]$Force) $global:PLTasks[$TaskName] = @{ Action = $Action } }
function Start-ScheduledTask { param($TaskName, $TaskPath)
  $a = $global:PLTasks[$TaskName].Action
  $global:PLTasks[$TaskName].Proc = Start-Process -FilePath $a.Execute -ArgumentList $a.Argument -PassThru -NoNewWindow }
function Get-ScheduledTask { param($TaskName, $TaskPath)
  $p = $global:PLTasks[$TaskName].Proc; [pscustomobject]@{ State = $(if ($p.HasExited) { 'Ready' } else { 'Running' }) } }
function Stop-ScheduledTask { param($TaskName, $TaskPath) $global:PLTasks[$TaskName].Proc.Kill($true) }
function Unregister-ScheduledTask { param($TaskName, $TaskPath, $Confirm) $global:PLTasks.Remove($TaskName) }
