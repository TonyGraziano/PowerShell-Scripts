$xmldata = (Invoke-WebRequest -Uri 'https://downloads.nordlayer.com/win/releases/rss.xml' -UseBasicParsing).content

if ($xmldata){
    $xmldata -match 'https://downloads.nordlayer.com/win/releases/NordLayerSetup_.+\.msi' | Out-Null
    $matches[0]
}
 $uri = $matches[0]

 if ((test-path c:\temp\nord) -eq $false){
    new-item -type directory C:\temp\nord
  }

$filename = $uri.split('/')[-1]

Invoke-WebRequest -Uri $($uri) -UseBasicParsing -OutFile "C:\Temp\nord\$($filename)"

msiexec /i "C:\Temp\nord\$($filename)" /passive /norestart
