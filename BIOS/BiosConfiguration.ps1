<#
======================================================================================================
 
 Created on:    20.04.2021
 Created by:    Mattias Melkersen
 Version:       0.1  
 Mail:          mm@mindcore.dk
 twitter:       @mmelkersen
 Function:      Configure Lenovo BIOS with dynamic config on Github

 Borrowed script parts from Damien https://github.com/damienvanrobaeys/Lenovo_Intune_BIOS_Settings/blob/master/BIOS_Settings_For_Lenovo.ps1
 This script is provided As Is
 Compatible with Windows 10 and later
======================================================================================================

#>

[string]$GithubConf = "https://raw.githubusercontent.com/mmelkersen/EndpointManager/main/BIOS/BiosConfiguration.csv"
[string]$Logfile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\BIOS_Settings.log" 
[string]$MyPassword = 
[string]$Language = "us"

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
Write_Log -Message_Type "INFO" -Message "Testing if hardware "$Manufacturer
If ($Manufacturer -eq "LENOVO")
    {
        $BIOS = (Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\wmi).CurrentSetting | Where-Object {$_ -ne ""} | Sort-Object
        Write_Log -Message_Type "INFO" -Message "Read current BIOS Settings." 

        Write_Log -Message_Type "INFO" -Message "Getting BIOS cloud configuration"
        $BIOSCSV = (New-Object System.Net.WebClient).DownloadString($GithubConf)

        $CharArray =$BIOSCSV.Split(";")
        $myArray = $CharArray | Select-Object -Skip 1

        Write_Log -Message_Type "INFO" -Message "Config to apply "$BIOSCSV

        $Script:IsPasswordSet = (gwmi -Class Lenovo_BiosPasswordSettings -Namespace root\wmi).PasswordState					
        If (($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq 2) -or ($IsPasswordSet -eq 3))
            {
                Write_Log -Message_Type "INFO" -Message "A password is configured"  
                If($MyPassword -eq "")
                    {
                        Write_Log -Message_Type "WARNING" -Message "No password has been sent to the script"
                        Write-Host "Failed: BIOS is password protected"  	
                        Break
                    }
                ElseIf($Language -eq "")
                    {
                        Write_Log -Message_Type "WARNING" -Message "No language has been sent to the script"  	
                        Write_Log -Message_Type "WARNING" -Message "The default language will be US" 
                        $Script:Language = 'us'
                    }			
            }	

        $bios = gwmi -class Lenovo_SetBiosSetting -namespace root\wmi 
        ForEach($Settings in $myArray.Split('',[System.StringSplitOptions]::RemoveEmptyEntries))
            {
                Write_Log -Message_Type "INFO" -Message "Change to do: $Settings"  
            
                If (($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq 2) -or ($IsPasswordSet -eq 3))
                    {					
                        Write_Log -Message_Type "INFO" -Message "executing with password $Settings,*****,ascii,$Language"
                        $Execute_Change_Action = $bios.SetBiosSetting("$Settings,$MyPassword,ascii,$Language")								
                        $Change_Return_Code = $Execute_Change_Action.return				
                        If(($Change_Return_Code) -eq "Success")        				
                            {
                                Write_Log -Message_Type "INFO" -Message "executing with password"
                                Write_Log -Message_Type "INFO" -Message "New value for $Settings"  
                                Write_Log -Message_Type "SUCCESS" -Message "The setting has been set"
                                    						
                            }
                        Else
                            {
                                Write_Log -Message_Type "INFO" -Message "executing with password"
                                Write_Log -Message_Type "ERROR" -Message "Can not change setting $Settings (Return code $Change_Return_Code)" 
                                Write-Host "Failed: BIOS is password protected"  						
                            }
                    }
                Else
                    {
                        $Execute_Change_Action = $BIOS.SetBiosSetting("$Settings") 			
                        $Change_Return_Code = $Execute_Change_Action.return			
                        If(($Change_Return_Code) -eq "Success")        								
                            {
                                Write_Log -Message_Type "INFO" -Message "New value for $Settings"  	
                                Write_Log -Message_Type "SUCCESS" -Message "The setting has been set"  
                                Write-Host "Success: Changed BIOS" 												
                            }
                        Else
                            {
                                Write_Log -Message_Type "ERROR" -Message "Can not change setting $Settings (Return code $Change_Return_Code)"
                                Write-Host "Failed: To change BIOS"  											
                            }								
                    }         
                
            }
    

        $Save_BIOS = (gwmi -class Lenovo_SaveBiosSettings -namespace root\wmi)
        If (($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq 2) -or ($IsPasswordSet -eq 3))
            {	
            $Execute_Save_Change_Action = $SAVE_BIOS.SaveBiosSettings("$MyPassword,ascii,$Language")	
            $Save_Change_Return_Code = $Execute_Save_Change_Action.return			
            If(($Save_Change_Return_Code) -eq "Success")
                {
                    Write_Log -Message_Type "SUCCESS" -Message "BIOS settings have been saved"  
                    Write-Host "Success: Changed BIOS"																	
                }
            Else
                {
                    Write_Log -Message_Type "ERROR" -Message "An issue occured while saving changes - $Save_Change_Return_Code"  
                    Write-Host "Failed: To change BIOS" 																				
                }
            }
        Else
            {
            $Execute_Save_Change_Action = $SAVE_BIOS.SaveBiosSettings()	
            $Save_Change_Return_Code = $Execute_Save_Change_Action.return			
            If(($Save_Change_Return_Code) -eq "Success")
                {
                    Write_Log -Message_Type "SUCCESS" -Message "BIOS settings have been saved"  																	
                }
            Else
                {
                    Write_Log -Message_Type "ERROR" -Message "An issue occured while saving changes - $Save_Change_Return_Code"  																				
                }		
            }
        }
    Else
    {
        Write_Log -Message_Type "INFO" -Message "Hardware running script was not a "$Manufacturer
        Write-Host "NOT RUN: Hardware not Lenovo"
    }
    Write_Log -Message_Type "INFO" -Message "Script finished"
    Write_Log -Message_Type ""