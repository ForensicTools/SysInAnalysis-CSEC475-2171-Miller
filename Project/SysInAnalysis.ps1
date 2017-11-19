#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.

while(($Option=Read-Host "System Information`nPlease Enter an option") -ne "back"){
    switch($Option)
    {
        "-h"{"`t`t`t Display All -Displays select statements 1-17`n
             select -Prompts user for a number 1-18 to display specified information`n
             find -Prompts user for the name of a file, If the file exists the path is displayed`n
             list aliases -Displays all Aliases`n
             vobj -Displays viewable directories other than the C:\ Drive`n
             quit -ends program
             "}
    
        "Display All"{
            "`n`r`t`t`t`t`t`t`t`tWindows Description:"
            Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tProcessor Information:"
            Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tRAM information:"
            Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Format-Table –AutoSize
            Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tDisk Information:"
            Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Format-Table –AutoSize
            Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Format-Table –AutoSize
            Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tDomain Information:"
            Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tUser Information:"
            Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tUserEventLog:"
            Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tStartup Programs:"
            Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tScheduled Tasks:"
            Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tNetwork Information:"
            Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Format-Table –AutoSize

            Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tDNS Cache Information:"
            Get-DnsClientCache | select Name,Entry,Data,Section | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tPrinter Information:"
            Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tList Of Software:"
            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize

            "`n`r`t`t`t`t`t`t`t`tProcess' List:"
            Get-Process | select processname,path,id | Format-Table -AutoSize

            "`n`r`t`t`t`t`t`t`t`tDriverList:"
            Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize

            "`n`r`t`t`t`t`t`t`t`tDocuments and Downloads:" 
            Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime
            Get-ChildItem -Path C:\Users\$env:username\Downloads\ | select mode, name, length, lastwritetime 

            "`n`r`t`t`t`t`t`t`t`t.exe Files:"
            Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length | format-table -autosize
        }
    
        "select"{
                 while(($Select=Read-Host "Which information would you like displayed?") -ne "back")
                 {
                    switch($Select)
                    {
                         "-h"{
                                "`t`t`t`t`t`t`t`t`tSection Numbers`n
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
                                 16-Documents and Downloads`n
                                 17-files with exe extensions`n
                                 18-files with specified extension`n
                                 back -back to System Information
                                 "
                            }


                         1  {
                                "`n`r`t`t`t`t`t`t`t`tWindows Description:"
                                Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Format-Table –AutoSize
                            }
                         2  {
                                "`n`r`t`t`t`t`t`t`t`tProcessor Information:"
                                Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Format-Table –AutoSize
                            }
                         3  {
                                "`n`r`t`t`t`t`t`t`t`tRAM information:"
                                Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Format-Table –AutoSize
                                Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Format-Table –AutoSize
                            }
                         4  {
                                "`n`r`t`t`t`t`t`t`t`tDisk Information:"
                                Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Format-Table –AutoSize
                                Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Format-Table –AutoSize
                                Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Format-Table –AutoSize
                            }
                         5  {
                                "`n`r`t`t`t`t`t`t`t`tDomain Information:"
                                Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Format-Table –AutoSize
                            }
                         6  {
                                "`n`r`t`t`t`t`t`t`t`tUser Information:"
                                Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Format-Table –AutoSize
                            }
                         7  {
                                "`n`r`t`t`t`t`t`t`t`tUserEventLog:"
                                Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Format-Table –AutoSize
                            }
                         8  {
                                "`n`r`t`t`t`t`t`t`t`tStartup Programs:"
                                Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Format-Table –AutoSize
                            }
                        9  {
                                "`n`r`t`t`t`t`t`t`t`tScheduled Tasks:"
                                Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Format-Table –AutoSize
                            }
                        10  {
                                "`n`r`t`t`t`t`t`t`t`tNetwork Information:"
                                Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Format-Table –AutoSize
                                Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Format-Table –AutoSize
                            }
                        11  {
                                "`n`r`t`t`t`t`t`t`t`tDNS Cache Information:"
                                Get-DnsClientCache | select Name,Entry,Data,Section | Format-Table –AutoSize
                            }
                        12  {
                                "`n`r`t`t`t`t`t`t`t`tPrinter Information:"
                                Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Format-Table –AutoSize
                            }
                        13  {
                                "`n`r`t`t`t`t`t`t`t`tList Of Software:"
                                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize
                            }
                        14  {
                                "`n`r`t`t`t`t`t`t`t`tProcess' List:"
                                Get-Process | select processname,path,id | Format-Table -AutoSize
                            }
                        15  {
                                "`n`r`t`t`t`t`t`t`t`tDriverList:"
                                Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize
                            }
                        16  {
                                "`n`r`t`t`t`t`t`t`t`tDocuments and Downloads:" 
                                Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime
                                Get-ChildItem -Path C:\Users\$env:username\Downloads\ | select mode, name, length, lastwritetime 
                            }
                        17  {
                                "`n`r`t`t`t`t`t`t`t`t.exe Files:"
                                Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length | format-table -autosize
                            }
                        18  {
                                $exten=Read-Host "Please enter an extension to search for"
                                "`n`r`t`t`t`t`t`t`t`t.$($exten) Files:"
                                Get-ChildItem -Path C:\Users\ -Filter *.$exten -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime | format-table -autosize
                            }
                        default{"Not a valid option"}
                    }
                 }
    
        }
        "find"{
                $find=Read-Host "What file would you like to find?"
                Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($find)*"}
              }

        "list aliases"{ls Alias:}

        "vobj"{psdrive}

        "csv"{
        
                while(($Option=Read-Host "System Information csv`nPlease Enter an option") -ne "back"){
                switch($Option)
                              {
                                "-h"{"`t`t`t Display All -Displays select statements 1-17`n
                                select -Prompts user for a number 1-18 to display specified information`n
                                find -Prompts user for the name of a file, If the file exists the path is displayed`n
                                list aliases -Displays all Aliases`n
                                vobj -Displays viewable directories other than the C:\ Drive`n
                                back -ends program
                                "}
                                "Output All"{
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
                                                Get-Disk >> $OutPut| select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,
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
                                        }
                                  "select output"{
                                    while(($Select=Read-Host "Which information would you like displayed?") -ne "back")
                                        {
                                            switch($Select)
                                            {
                                            "-h"{
                                            "`t`t`t`t`t`t`t`t`tSection Numbers`n
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
                                            16-Documents and Downloads`n
                                            17-files with exe extensions`n
                                            18-files with specified extension`n
                                            back -back to System Information
                                            "
                                            }


                                         1  {
                                             $OutPut=Read-Host "Enter an output name and path"
                                             Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,
                                             BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Export-CSV -Path $OutPut
                                            }
                                         2  {
                                             $OutPut=Read-Host "Enter an output name and path"
                                             Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,
                                             OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,
                                             SerialNumber,CimClass | Export-Csv -Path $OutPut
                                            }
                                         3  {
                                             $OutPut=Read-Host "Enter an output name and path"
                                             Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Export-Csv -path $OutPut
                                             Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Export-Csv -path $OutPut
                                            }
                                         4  {
                                             $OutPut=Read-Host "Enter an output name and path"
                                             Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,
                                             FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Export-Csv -path $OutPut
                                             Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,
                                             IsShadowCopy,Size | Export-Csv -Path $OutPut
                                             Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Export-Csv -path $OutPut
                                            }
                                         5  {
                                             $OutPut=Read-Host "Enter an output name and path"
                                             Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,
                                             workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Export-Csv -path $OutPut
                                            }
                                         6  {
                                             $OutPut=Read-Host "Enter an output name and path"
                                             Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,
                                             Description,SID,Enabled | Export-Csv -path $OutPut
                                            }
                                         7  {
                                             $OutPut=Read-Host "Enter an output name and path"
                                             Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Export-Csv -path $OutPut
                                            }
                                         8  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | export-csv -path $OutPut
                                            }
                                         9  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Export-Csv -Path $OutPut
                                            }
                                        10  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Export-Csv -Path $OutPut
                                            Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Export-Csv -Path $OutPut
                                            }
                                        11  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-DnsClientCache | select Name,Entry,Data,Section | Export-Csv -Path $OutPut
                                            }
                                        12  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Export-Csv -Path $OutPut
                                            }
                                        13  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path $OutPut
                                            }
                                        14  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-Process | select processname,path,id | Export-Csv -Path $OutPut
                                            }
                                        15  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Export-Csv -Path $OutPut
                                            }
                                        16  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime | Export-Csv -Path $OutPut
                                            Get-ChildItem -Path C:\Users\$env:username\Downloads\ | select mode, name, length, lastwritetime | Export-Csv -Path $OutPut
                                            }
                                        17  {
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length | Export-Csv -Path $OutPut
                                            }
                                        18  {
                                            $exten=Read-Host "Please enter an extension to search for"
                                            $OutPut=Read-Host "Enter an output name and path"
                                            Get-ChildItem -Path C:\Users\ -Filter *.$exten -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime | Export-Csv -Path $OutPut
                                            }
                                        default{"Not a valid option"}
                                        }
                                }
                                 
                             }

             }

        #default{"Not a valid option"}
    }
    }
    }
}