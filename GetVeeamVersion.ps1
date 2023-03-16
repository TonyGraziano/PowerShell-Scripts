$path = "Program Files\Veeam\Backup and Replication\Backup\Packages\VeeamDeploymentDll.dll" 
$disks = gwmi win32_logicaldisk -Filter "DriveType='3'"
foreach ($drive in $disks) {
    $thisIterationPath = "$($drive.DeviceID)\$path"
    if (Test-Path -Path $thisIterationPath) {
        $VEEAM = (Get-Item $thisIterationPath).VersionInfo;
        $VEEAM.ProductVersion
    }
}
