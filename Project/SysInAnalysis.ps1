#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.

#No arguments for current users information printed to screen.
#use csv as an argument to print out csv files.

#Section Numbers
#1-Windows Discription
#2-Processor Information
#3-RAM Information
#4-Disk Information
#5-Domain Information
#6-User Information
#7-User Event Log
#8-Startup Programs
#9-Scheduled Tasks
#10-Network Information
#11-DNS Cache Information
#12-Printer Information
#13-List Of Software
#14-Process List
#15-Driver List
#16-Documents and Downloads (If a user is provided)

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
#Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | #FL * | Format-Table –AutoSize

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
#Get-PrinterDriver | Select #Name,DriverVersion,HardwareID,Manufacturer,HardwareID,PrinterEnvironment,Pr#intProcessor,provider

"`n`r`t`t`t`t`t`t`t`tList Of Software:"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tProcess' List:"
Get-Process | select processname,path,id | Format-Table -AutoSize

"`n`r`t`t`t`t`t`t`t`tDriverList:"
Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize

"`n`r`t`t`t`t`t`t`t`tDocuments and Downloads:" 

Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime

Get-ChildItem -Path C:\Users\$env:username\downloads | select mode, name, length, lastwritetime 

"`n`r`t`t`t`t`t`t`t`t.exe Files:"
Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length | format-table -autosize



if($args.contains("csv") ) {
Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysWindDesc.txt' -NoTypeInformation

Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysProcessorInfo.txt' -NoTypeInformation

Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysMemory.txt' -NoTypeInformation

Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysMemArray.txt' -NoTypeInformation

Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysDisk.txt' -NoTypeInformation

Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysPartition.txt' -NoTypeInformation

Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysPhysicalDisk.txt' -NoTypeInformation

Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysDomain.txt' -NoTypeInformation

Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysUserInfo.txt' -NoTypeInformation

Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysEvents.txt' -NoTypeInformation

#Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | #FL * | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall #2017\CSEC 475\Scripts\Project\csvfiles\SysInAnalysis.txt' -#NoTypeInformation

Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysStartProgs.txt' -NoTypeInformation

Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysTasks.txt' -NoTypeInformation

Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysNetAd.txt' -NoTypeInformation

Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysNetInfo.txt' -NoTypeInformation

Get-DnsClientCache | select Name,Entry,Data,Section | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysDNS.txt' -NoTypeInformation

Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysPrinter.txt' -NoTypeInformation

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysSoftware.txt' -NoTypeInformation

Get-Process | select processname,path,id | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysProcesses.txt' -NoTypeInformation

Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysDrivers.txt' -NoTypeInformation

Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysDocuments.txt' -NoTypeInformation


Get-ChildItem -Path C:\Users\$env:username\downloads | select mode, name, length, lastwritetime | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysDownloads.txt' -NoTypeInformation

Get-ChildItem -Path C:\Users\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, Length | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\csvfiles\SysEXEFiles.txt' -NoTypeInformation

}