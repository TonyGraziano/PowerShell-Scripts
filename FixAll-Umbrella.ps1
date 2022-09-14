function IsDNSServerLocalHost() {
    $nslookup = nslookup.exe www.google.com
    $lines = $nslookup.Split([Environment]::NewLine)

    if ($lines.Count -gt 1) {
        $ip = $lines[1].Split(" ")[2]
        if ($ip -eq "127.0.0.1") {
            return $true
        }
    }

    return $false
}

function Get-LocalDNSStatus {
    param(
        [int]$retries = 3,
        [int]$retryIntervalSeconds = 5
    )

    for ($i = 0; $i -lt $retries; $i++) {
        if (IsDNSServerLocalHost) {
            # We have found that the DNS Server is localhost after our retries
            # Return true
            return $true;
        }

        Start-Sleep -Seconds $retryIntervalSeconds
    }

    # After our retries, it is still not localhost
    # We will need to do a rip and replace
    # Return false
    return $false;
}
