# Pulling the website for the path to the different file (URL) verisons
$xmldata = (Invoke-WebRequest -Uri 'https://downloads.nordlayer.com/win/releases/rss.xml' -UseBasicParsing).content

# Taking the contents of the XML file to see if anything matches the string (all the MSI files)
if ($xmldata){
    $xmldata -match 'https://downloads.nordlayer.com/win/releases/NordLayerSetup_.+\.msi' | Out-Null
    $matches[0]
}

$uri = $matches[0]

if ($uri) {
  # This creates the destination folder for the file if it doesn't exist
  if ((test-path c:\temp\nord) -eq $false){
    new-item -type directory C:\temp\nord
  }

  # Get file name from split URL
  $filename = $uri.split('/')[-1]

  # Download the lastest version to destination folder
  Invoke-WebRequest -Uri $($uri) -UseBasicParsing -OutFile "C:\Temp\nord\$($filename)"

  # Execut install quietly
  msiexec /i "C:\Temp\nord\$($filename)" /q /norestart
}
