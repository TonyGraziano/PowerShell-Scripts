$a = (Get-WmiObject -Class Win32_Product | where {$_.name -like '*MiCollab*'}).identifyingnumber

if ($a){
  # getwmiobject returned something
  MsiExec.exe /X "$($a)" /q /norestart
}else{
  # getwmiobject didnt return anything
  write-host "Product Not Found"
}
