if ((test-path c:\temp\RingCentral) -eq $false){
    new-item -type directory C:\temp\RingCentral
  }

  start-sleep -seconds 5

  # Download the lastest version to destination folder
  $filename = "RingCentralInstaller.msi"
  Invoke-WebRequest -Uri "https://app.ringcentral.com/download/RingCentral-x64.msi" -OutFile "C:\temp\RingCentral\$($filename)"

  # Execute install quietly
  msiexec /i "C:\Temp\RingCentral\$($filename)" /q /norestart
