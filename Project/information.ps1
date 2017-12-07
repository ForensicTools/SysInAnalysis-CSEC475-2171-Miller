#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.

while(($Option=Read-Host "System Information`nPlease Enter an option") -ne "back"){
    switch($Option)
    {
        "-h"{"`n             -d -Displays select statements 1-18`n
             -s -Prompts user for a number 1-22 to display specified information`n
             -f -Prompts user for the name of a file, If the file exists the path is displayed`n
             -a -Displays all Aliases`n
             -v -Displays viewable directories other than the C:\ Drive`n
             csv -output information to csv`n
             clear -clears the powershell screen`n
             back -Return to last section
             "}
        "clear"{clear}
    
        "-d"{
            "`n`r`t`t`t`t`t`t`t`tWindows Description:"
            Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tProcessor Information:" 
            Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tRAM information:"
            Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Format-Table -wrap –AutoSize
            Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tDisk Information:"
            Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Format-Table -wrap –AutoSize
            Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Format-Table -wrap –AutoSize
            Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tDomain Information:"
            Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tUser Information:"
            Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tUserEventLog:"
            Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tStartup Programs:"
            Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tScheduled Tasks:"
            Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tNetwork Information:"
            Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Format-Table -wrap –AutoSize

            Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tDNS Cache Information:"
            Get-DnsClientCache | select Name,Entry,Data,Section | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tPrinter Information:"
            Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tList Of Software:"
            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -wrap –AutoSize

            "`n`r`t`t`t`t`t`t`t`tProcess' List:"
            Get-Process | select processname,path,id | Format-Table -AutoSize  

            "`n`r`t`t`t`t`t`t`t`tDriverList:"
            Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize  

            "`n`r`t`t`t`t`t`t`t`tDocuments and Downloads:" 
            Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime
            Get-ChildItem -Path C:\Users\$env:username\Downloads\ | select mode, name, length, lastwritetime 

            "`n`r`t`t`t`t`t`t`t`t.exe Files:"
            Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length | format-table -AutoSize 
        
            "`n`r`t`t`t`t`t`t`t`tUSB Information:"
            %{Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object friendlyname, mfg,driver, compatibleids, service | Format-table -AutoSize -wrap}
            

        }
    
        "-s"{
                 while(($Select=Read-Host "Which information would you like displayed?") -ne "back")
                 {
                    switch($Select.split(","))
                    {
                         "-h"{
                                "`nSection Numbers`n
                                 1-Windows Discription`n
                                 2-Processor Information`n
                                 3-RAM Information`n
                                 4-Disk Information`n
                                 5-Domain Information`n
                                 6-User Information`n
                                 7-User Event Log`n
                                 8-Startup Programs`n
                                 9-Scheduled Tasks`n
                                 10-Network Information`n
                                 11-DNS Cache Information`n
                                 12-Printer Information`n
                                 13-List Of Software`n
                                 14-Process List`n
                                 15-Driver List`n
                                 16-Usb information`n
                                 17-Documents and Downloads`n
                                 18-files with exe extensions`n
                                 19-files with specified extension`n
                                 20-security event log, Administrative access needed`n
                                 21-system event log, Administrative access needed`n
                                 22-User Failed login attempts, Administrative access needed`n
                                 23-usb history
                                 back -back to System Information`n
                                 clear -clears the powershell screen
                                 "
                            }
                         "clear"{clear}

                         1  {
                                "`n`r`t`t`t`t`t`t`t`tWindows Description:"
                                Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Format-Table –wrap -AutoSize   
                            }
                         2  {
                                "`n`r`t`t`t`t`t`t`t`tProcessor Information:"
                                Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Format-Table –wrap –AutoSize 
                            }
                         3  {
                                "`n`r`t`t`t`t`t`t`t`tRAM information:"
                                Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Format-Table –wrap –AutoSize
                                Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Format-Table –wrap –AutoSize
                            }
                         4  {
                                "`n`r`t`t`t`t`t`t`t`tDisk Information:"
                                Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Format-Table –wrap –AutoSize
                                Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Format-Table –wrap –AutoSize
                                Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Format-Table –wrap –AutoSize
                            }
                         5  {
                                "`n`r`t`t`t`t`t`t`t`tDomain Information:"
                                Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Format-Table –wrap –AutoSize
                            }
                         6  {
                                "`n`r`t`t`t`t`t`t`t`tUser Information:"
                                Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Format-Table –wrap –AutoSize
                            }
                         7  {
                                "`n`r`t`t`t`t`t`t`t`tUserEventLog:"
                                Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Format-Table –wrap –AutoSize
                            }
                         8  {
                                "`n`r`t`t`t`t`t`t`t`tStartup Programs:"
                                Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Format-Table –wrap –AutoSize
                            }
                        9  {
                                "`n`r`t`t`t`t`t`t`t`tScheduled Tasks:"
                                Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Format-Table –wrap –AutoSize
                            }
                        10  {
                                "`n`r`t`t`t`t`t`t`t`tNetwork Information:"
                                Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Format-Table –wrap –AutoSize
                                Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Format-Table –wrap –AutoSize
                            }
                        11  {
                                "`n`r`t`t`t`t`t`t`t`tDNS Cache Information:"
                                Get-DnsClientCache | select Name,Entry,Data,Section | Format-Table –wrap –AutoSize
                            }
                        12  {
                                "`n`r`t`t`t`t`t`t`t`tPrinter Information:"
                                Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Format-Table -wrap –AutoSize
                            }
                        13  {
                                "`n`r`t`t`t`t`t`t`t`tList Of Software:"
                                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -wrap –AutoSize
                            }
                        14  {
                                "`n`r`t`t`t`t`t`t`t`tProcess' List:"
                                Get-Process | select processname,path,id | Format-Table -AutoSize  
                            }
                        15  {
                                "`n`r`t`t`t`t`t`t`t`tDriverList:"
                                Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize  
                            }
                        
                        16{
                                "`n`r`t`t`t`t`t`t`t`tUSB Information:"
                                Get-ItemProperty -Path ’HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*’ | Select-Object friendlyname,mfg,driver,hardwareid,compatibleids,service
                                gwmi cim_logicaldisk | ? drivetype -eq 2
                            }
                        17  {
                                "`n`r`t`t`t`t`t`t`t`tDocuments and Downloads:" 
                                Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime
                                Get-ChildItem -Path C:\Users\$env:username\Downloads\ | select mode, name, length, lastwritetime 
                            }
                        18  {
                                "`n`r`t`t`t`t`t`t`t`t.exe Files:"
                                Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length | format-table -AutoSize 
                            }
                        19  {
                                $exten=Read-Host "Please enter an extension to search for"
                                "`n`r`t`t`t`t`t`t`t`t.$($exten) Files:"
                                Get-ChildItem -Path C:\Users\ -Filter *.$exten -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime | format-table -AutoSize 
                            }
                        20  {Get-EventLog -LogName Security|Format-Table -wrap}
                        21  {Get-EventLog -LogName System|Format-Table -wrap}
                        22  {GET-EVENTLOG -Logname Security | where { $_.EntryType -eq 'FailureAudit' } | Select-Object EventID,TimeGenerated,MachineName,Message | Sort-Object TimeGenerated -Descending|Format-Table -wrap -AutoSize }
                        23  {%{Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object friendlyname, mfg,driver, compatibleids, service | Format-table -AutoSize -wrap}
            }
                        default{"Not a valid option"}
                    }
                 }
    
        }
        "-f"{
                $find=Read-Host "What file would you like to find?"
                Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | ? {$_.Name -like "$($find)*"} | format-table -wrap -autosize
              }

        "-a"{get-childitem -path Alias:}

        "-v"{psdrive | write-host}

        "csv"{
        
                while(($Option=Read-Host "System Information csv`nPlease Enter an option") -ne "back"){
                switch($Option)
                              {
                                "-h"{"-d -Displays select statements 1-18`n
                                -s -Prompts user for a number 1-22 to display specified information`n
                                -f -Prompts user for the name of a file, If the file exists the path is displayed`n
                                -a -Displays all Aliases`n
                                -v -Displays viewable directories other than the C:\ Drive`n
                                clear -clears the powershell screen`n
                                back -returns to previous selection
                                "}

                                "clear"{clear}

                                "-a"{$OutPut=Read-Host "Select an output file path and name"
                                    ls Alias: >> $OutPut}
                                
                                "-v"{$OutPut=Read-Host "Select an output file path and name"
                                    psdrive >> $OutPut}

                                "-f"{$OutPut = Read-Host "Select an output file path and name"
                                    $find=Read-Host "What file would you like to find?"
                                    Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($find)*"} >> $OutPut
                                    }

                                "-d"{
                                                $OutPut=Read-Host "Select an output file path and name"
                                                "Windows Description" >> $OutPut
                                                Get-CimInstance Win32_OperatingSystem | Select-Object localDateTime,LastBootUpTime,CurrentTimeZone,
                                                RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,
                                                Version,ServicePackMajorVersion,InstallDate,BuildNumber >> $OutPut
                                                
                                                "Processor Description" >> $OutPut
                                                Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,
                                                SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,
                                                NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass >> $OutPut

                                                "Memory Description">> $OutPut
                                                Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,
                                                Tag,Capacity,CimClass >> $OutPut
                                                Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,
                                                Manufacturer >> $OutPut

                                                "Disk Information">> $OutPut
                                                Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,
                                                UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,
                                                Path >> $OutPut
                                                Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,
                                                IsOffline,IsShadowCopy,Size >> $OutPut
                                                Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,
                                                SerialNumber >> $OutPut

                                                "Domain Information" >> $OutPut
                                                Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,
                                                DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,
                                                TotalPhysicalMemory >> $OutPut

                                                "User Information" >> $OutPut
                                                Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,
                                                FullName,Description,SID,Enabled >> $OutPut

                                                "User Event Log" >> $OutPut
                                                Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon >> $OutPut

                                                "Startup Programs" >> $OutPut
                                                Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location >> $OutPut

                                                "Scheduled Tasks" >> $OutPut
                                                Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions >> $OutPut

                                                "Network Information" >> $OutPut
                                                Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,
                                                InterfaceDescription,SystemName,SlotNumber >> $OutPut
                                                Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,
                                                DHCPServer,DNSDomain,Description,DefaultGateway >> $OutPut

                                                "DNS Cache Information" >> $OutPut
                                                Get-DnsClientCache | select Name,Entry,Data,Section >> $OutPut

                                                "Printer Information" >> $OutPut
                                                Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor >> $OutPut

                                                "List of Software" >> $OutPut
                                                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, 
                                                Publisher, InstallDate >> $OutPut

                                                "List of Process'" >> $OutPut
                                                Get-Process | select processname,path,id >> $OutPut

                                                "Drivers List" >> $OutPut
                                                Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer >> $OutPut

                                                "Documents and Downloads" >> $OutPut
                                                Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime >> $OutPut
                                                Get-ChildItem -Path C:\Users\$env:username\Downloads\ | select mode, name, length, lastwritetime >> $OutPut

                                                "exe files" >> $OutPut
                                                Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length >> $OutPut
                                        
                                                "USB Information:">> $OutPut
                                                %{Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object friendlyname, mfg,driver, compatibleids, service | Format-table -AutoSize -wrap} >> $OutPut
                                        }
                                  "-s"{
                                    $OutPut=Read-Host "Select output file path and name"
                                    while(($Select=Read-Host "Which information would you like displayed?") -ne "back")
                                        {
                                            switch($Select.split(","))
                                            {
                                            "-h"{
                                            "`nSection Numbers`n
                                            1-Windows Discription`n
                                            2-Processor Information`n
                                            3-RAM Information`n
                                            4-Disk Information`n
                                            5-Domain Information`n
                                            6-User Information`n
                                            7-User Event Log`n
                                            8-Startup Programs`n
                                            9-Scheduled Tasks`n
                                            10-Network Information`n
                                            11-DNS Cache Information`n
                                            12-Printer Information`n
                                            13-List Of Software`n
                                            14-Process List`n
                                            15-Driver List`n
                                            16-Usb Information`n
                                            17-Documents and Downloads`n
                                            18-files with exe extensions`n
                                            19-files with specified extension`n
                                            20-security event log`n
                                            21-system event log`n
                                            22-User Failed login attempts`n
                                            back -back to System Information`n
                                            clear -clears the powershell screen
                                            "
                                            }
                                          "clear"{clear}

                                         1  {
                                             
                                             Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,
                                             BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber >> $OutPut
                                            }
                                         2  {
                                             
                                             Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,
                                             OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,
                                             SerialNumber,CimClass >> $OutPut
                                            }
                                         3  {
                                             
                                             Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass >> $OutPut
                                             Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer >> $OutPut
                                            }
                                         4  {
                                             
                                             Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,
                                             FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path >> $OutPut
                                             Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,
                                             IsShadowCopy,Size >> $OutPut
                                             Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber >> $OutPut
                                            }
                                         5  {
                                             
                                             Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,
                                             workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory >> $OutPut
                                            }
                                         6  {
                                             
                                             Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,
                                             Description,SID,Enabled >> $OutPut
                                            }
                                         7  {
                                             
                                             Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon >> $OutPut
                                            }
                                         8  {
                                           
                                            Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location >> $OutPut
                                            }
                                         9  {
                                            
                                            Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions >> $OutPut
                                            }
                                        10  {
                                            
                                            Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber >> $OutPut
                                            Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway >> $OutPut
                                            }
                                        11  {
                                            
                                            Get-DnsClientCache | select Name,Entry,Data,Section >> $OutPut
                                            }
                                        12  {
                                            
                                            Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor >> $OutPut
                                            }
                                        13  {
                                            
                                            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate >> $OutPut
                                            }
                                        14  {
                                            
                                            Get-Process | select processname,path,id >> $OutPut
                                            }
                                        15  {
                                            
                                            Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer >> $OutPut
                                            }
                                        16  {
                                            
                                            Get-ItemProperty -Path ’HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*’ | Select-Object friendlyname,mfg,driver,hardwareid,compatibleids,service >> $OutPut
                                            gwmi cim_logicaldisk | ? drivetype -eq 2 >> $OutPut
                                            }
                                        17  {
                                            
                                            Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime >> $OutPut
                                            Get-ChildItem -Path C:\Users\$env:username\Downloads\ | select mode, name, length, lastwritetime >> $OutPut
                                            }
                                        18  {
                                            
                                            Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length >> $OutPut
                                            }
                                        19  {
                                            $exten=Read-Host "Please enter an extension to search for"
                                            
                                            Get-ChildItem -Path C:\Users\ -Filter *.$exten -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime >> $OutPut
                                            }
                                        20  {
                                            Get-EventLog -LogName Security >> $OutPut}
                                        21  {
                                            Get-EventLog -LogName System >> $OutPut}
                                        22  {
                                            GET-EVENTLOG -Logname Security | where { $_.EntryType -eq 'FailureAudit' } | Select-Object EventID,TimeGenerated,MachineName,Message | Sort-Object TimeGenerated -Descending|Format-Table -wrap >> $OutPut}
                                        
                                        23 {
                                        %{Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object friendlyname, mfg,driver, compatibleids, service | Format-table -AutoSize -wrap}>>$OutPut}
                                        
                                        default{"Not a valid option"}
                                        }
                                }
                                 
                             }

             }
            }
        }
    default{"Not a valid option"}
    }
}