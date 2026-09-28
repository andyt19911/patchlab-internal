# Reports why Windows wants a reboot (empty list = none pending).
$reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    $reasons += 'Component Based Servicing'
}
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
    $reasons += 'Windows Update'
}
$sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
if ($sm -and $sm.PendingFileRenameOperations) { $reasons += 'Pending file rename operations' }
try {
    $ccm = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName CCM_ClientUtilities `
        -MethodName DetermineIfRebootPending -ErrorAction Stop
    if ($ccm.RebootPending -or $ccm.IsHardRebootPending) { $reasons += 'ConfigMgr client' }
} catch {
    Write-Verbose 'no ConfigMgr client on this machine'
}
'@@PLJSON ' + (ConvertTo-Json -InputObject @($reasons) -Compress)
