<#
======================================================================================================
 
 Created on:    19.04.2021
 Created by:    Mattias Melkersen
 Version:       0.1  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Configure Lenovo BIOS

 This script is provided As Is
 Compatible with Windows 10 and later
======================================================================================================

#>
$GithubConf = "https://raw.githubusercontent.com/mmelkersen/EndpointManager/main/BIOS/BiosConfiguration.csv"
$Logfile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\BIOS_Settings.log" 

Function Write_Log
	{
	param(
	$Message_Type, 
	$Message
	)
		$MyDate = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)  
		Add-Content $LogFile  "$MyDate - $Message_Type : $Message"  
	} 

[String]$Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer

$BIOS = (Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\wmi).CurrentSetting | Where-Object {$_ -ne ""} | Sort-Object
Write_Log -Message_Type "INFO" -Message "Read current BIOS Settings." 

Write_Log -Message_Type "INFO" -Message "Getting BIOS cloud configuration"
$BIOSCSV = (New-Object System.Net.WebClient).DownloadString($GithubConf)
Write_Log -Message_Type "INFO" -Message "Config to apply "$BIOSCSV


$bios = gwmi -class Lenovo_SetBiosSetting -namespace root\wmi 
ForEach($Settings in $BIOSCSV)
	{
		$MySetting = $Settings.Setting
		$NewValue = $Settings.Value		
		
		Write_Log -Message_Type "INFO" -Message "Change to do: $MySetting - $NewValue"  
	
		If (($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq 2) -or ($IsPasswordSet -eq 3))
			{					
				$Execute_Change_Action = $bios.SetBiosSetting("$MySetting,$NewValue,$MyPassword,ascii,$Language")								
				$Change_Return_Code = $Execute_Change_Action.return				
				If(($Change_Return_Code) -eq "Success")        				
					{
						Write_Log -Message_Type "INFO" -Message "New value for $MySetting is $NewValue"  
						Write_Log -Message_Type "SUCCESS" -Message "The setting has been setted"  						
					}
				Else
					{
						Write_Log -Message_Type "ERROR" -Message "Can not change setting $MySetting (Return code $Change_Return_Code)"  						
					}
			}
		Else
			{
				$Execute_Change_Action = $BIOS.SetBiosSetting("$MySetting,$NewValue") 			
				$Change_Return_Code = $Execute_Change_Action.return			
				If(($Change_Return_Code) -eq "Success")        								
					{
						Write_Log -Message_Type "INFO" -Message "New value for $MySetting is $NewValue"  	
						Write_Log -Message_Type "SUCCESS" -Message "The setting has been setted"  												
					}
				Else
					{
						Write_Log -Message_Type "ERROR" -Message "Can not change setting $MySetting (Return code $Change_Return_Code)"  											
					}								
			}
	}

Stop-Transcript