$service = Get-CimInstance -class win32_service | Where-Object name -contains "Umbrella_RC" | select name, processid
$service.processId
