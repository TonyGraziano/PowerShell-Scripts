$scriptBlock = {
    if ((Get-Service Umbrella_RC).Status -eq "Running") {
        Get-Process "*dnscrypt*" | Stop-Process -Force
        Get-Service "*umbrella*" | Restart-Service -Force
    }
}

# Run the script block 
$job = Start-Job -ScriptBlock $scriptBlock 

# Delay for N seconds
Start-Sleep -Seconds 10

# Get the status of the service and check to see if it is stuck in the "StopPending" state

if ((Get-Service Umbrella_RC).status -eq 'Stoppending') {
    $UID  = $service.processId
    $service = Get-CimInstance -class win32_service | Where-Object name -contains "Umbrella_RC" | select name, processid
    $service.processId
    taskkill /pid $UID
    start-sleep -Seconds 10
    net start Umbrella_RC
}

$job | remove-job 

start-sleep -seconds 10

$nslookup = nslookup www.google.com

if ($nslookup -match 'Address:  127.0.0.1'){
    get-service Umbrella_RC
    get-process *dns*
    $nslookup
    write-host "DNS IS RESOLVING TO PROPER ADDRESS" -ForegroundColor Green
    Write-host "UMBRELLA_RC RESTART COMPLETED" -ForegroundColor Green
} else{
     get-service Umbrella_RC
     get-process *dns*
     nslookup www.google.com

     write-host "SOMETHING IS WRONG, CHECK ABOVE INFORMATION" -foregroundcolor red
}
