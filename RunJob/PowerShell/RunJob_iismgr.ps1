if (!(Test-Path ".\RunJob.exe")) {
    "Cannot find RunJob.exe"
    return
}#if
$session = New-PSSession -ConfigurationName RunJob
if (!$?) {
    "Cannot create JEA session."
    return
}#
$winstation = (Get-Process -Id $pid).SI
.\RunJob /WindowStationPermission /User LocalIISAdmin
Invoke-Command $session {
    param($winstation)
    iismgr $winstation
} -ArgumentList $winstation
Remove-PSSession $session

