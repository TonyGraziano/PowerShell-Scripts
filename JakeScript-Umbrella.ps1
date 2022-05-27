enum UmbrellaServiceStatus {
    BOTH_DOWN
    UMBRELLA_SERVICE_DOWN
    DNS_CRYPT_PROCESS_DOWN
    NO_LOCAL_DNS_SERVER
}

function Display-UmbrellaServiceStatus(
    $status
) {
    switch -Wildcard ($status) {
        BOTH_DOWN {
            Write-Host "Both DNS-Crypt and Umbrella services are down."
            continue
        }
        DNS_CRYPT_UP_ONLY {
            Write-Host "DNS-Crypt service is up, Umbrella service is down."
            continue
        }
            
        UMBRELLA_UP_ONLY {
            Write-Host "Umbrella service is up, DNS-Crypt service is down."
            continue
        }
        UMBRELLA_UP_AND_DNS_CRYPT_UP {
            Write-Host "Both DNS-Crypt and Umbrella services are up."
            continue
        }
        default {
            Write-Host "Unknown status."
            continue
        }
    }
}

function Get-UmbrellaServiceStatus() {
    #Initialize the return value
    $status = BOTH_DOWN
    
    if (!Check-UmbrellaService) {
        $status = UMBRELLA_SERVICE_DOWN
    } elseif (!(Get-Process "*dnscrypt*")) {
        $status = DNS_CRYPT_PROCESS_DOWN
    } elseif (!Check-DNSCryptProxy) {
        $status = NO_LOCAL_DNS_SERVER
    }

    return $status
}

function Check-UmbrellaService() {
    # For this test to return true, the following conditions must be met
    # 1. The Umbrella RC Service status is "Running"

    if ((Get-Service Umbrella_RC).Status -eq 'Running') {
        return true
    } else {
        return false
    }
}
function Check-DNSForward() {
    $Results = Get-DnsClientServerAddress -AddressFamily IPv4 | Where {$_.ServerAddresses -ne $null}

    foreach ($result in $Results) {
    
        if ($result.ServerAddresses.Count -eq 0) {
            Write-Host "No DNS Servers set for nic" $result
            continue
        }

        if ($result.ServerAddresses.Count -gt 1) {
            Write-Host "Multiple DNS Servers set for nic" $result
            # Fail condition for how DNSCryptProxy Works
            return $false
        }
        
        if ($result.ServerAddresses[0].ToString -ne "127.0.0.1" 
            || $result.ServerAddresses[0].ToString -ne "::1"
            || $result.ServerAddresses[0].ToString -ne "192.168.1.1") 
        {
            continue
        }
    }

    return $true
}

function Check-DNSCryptProxy() {
    # Our success criteria is that the dnscryptproxy process is running
    # AND the DNS server we are pointing to is "127.0.0.1" OR "::1"
    # If both of these conditions are met, we return true
    if (Check-UmbrellaService -and Check-DNSForward) {
        return true
    } else {
        return false
    }
}




Display-UmbrellaServiceStatus(Get-UmbrellaServiceStatus)
