Get-CimInstance -Class win32_softwareFeature | {$_.lastuse -like "*"} | select productname,lastuse | Sort-Object lastuse -unique

$outtbl = @()
$Prs =Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 
Foreach($pr in $prs){
  $x = Get-WmiObject -Namespace ROOT\CIMV2 -Class Win32_SoftwareFeature |?{$_.lastuse -like "*"} | select productname,lastuse 
  Foreach($x in $x){
  $t = New-Object PSObject -Property @{
   Displayname         = $pr.DisplayName
   DisplayVersion      = $pr.DisplayVersion
   Publisher           = $pr.Publisher
   InstallDate         = $pr.InstallDate
   Productname         = $x.productname
   lastuse             = $x.lastuse
  }
  }
  $outtbl += $t
}

$outtbl | Sort-Object lastuse -unique


