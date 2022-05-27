if ((Get-Service Umbrella_RC).Status -eq 'Running') {
    get-process *dnscrypt* | Stop-process -force
    get-service *umbrella* | restart-service -force
    start-sleep -Seconds 10
    #If Umbrella is running this first portion is going to hard snap the dnscryptproxy and then force stop both Umbrella_RC and dnscryptproxy
}else{
    write-host "NOT RUNNING/NOT INSTALLED" -foregroundcolor red
    Write-host "COMPLETED" -ForegroundColor Green
    #If the first portion does not detect Umbrella then it will display that something is not installed
}
if (((Get-Service Umbrella_RC).Status -eq 'Running') -and (get-process *dnscrypt*)) {
    get-service *umbrella*
    get-process *dnscrypt*
    nslookup www.google.com
    #Regardless of first two outcome this will display the current state of Umbrella_Rc and dnscryptproxy and then show what server this WS is pointing to with nslookup
}else{
    write-host "SOMETHING ISNT RUNNING" -foregroundcolor red
    write-host "SERVICE: $((Get-Service *Umbrella_RC*).Status)" 
    write-host "PROCESS: $(Get-Process *dnscrypt*)" 
    #If Umbrella_RC or dnscryptproxy aren't running this will output text saying that something isnt running and then display the current state of the service/process
}
