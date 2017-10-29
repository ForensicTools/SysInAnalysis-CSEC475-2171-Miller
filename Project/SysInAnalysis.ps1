#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.

#Get-CimInstance Win32_(name of device/type/etc) | FL *
#Gives all possible fields
#Note-Including a colon(:) prevents script from continuing past point

#No arguments for everything but document and download files.
#One argument, needs to be the User for Document and Downloads information.
#Two arguments print to csv file, Argument 1 User, Argument 2 csv

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


if($args.count -eq 0) {
"`n`r`t`t`t`t`t`t`t`tWindows Description"
Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tProcessor Information"
Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tRAM information"
Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Format-Table –AutoSize
Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tDisk Information"
Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Format-Table –AutoSize
Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Format-Table –AutoSize
Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tDomain Information"
Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tUser Information"
Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tUserEventLog"
Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Format-Table –AutoSize
#Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | #FL * | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tStartup Programs"
Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tScheduled Tasks"
Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tNetwork Information"
Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Format-Table –AutoSize

Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tDNS Cache Information"
Get-DnsClientCache | select Name,Entry,Data,Section | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tPrinter Information"
Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Format-Table –AutoSize
#Get-PrinterDriver | Select #Name,DriverVersion,HardwareID,Manufacturer,HardwareID,PrinterEnvironment,Pr#intProcessor,provider

"`n`r`t`t`t`t`t`t`t`tList Of Software"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tProcess' List"
Get-Process | select processname,path,id | Format-Table -AutoSize

"`n`r`t`t`t`t`t`t`t`tDriverList"
Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize


}




if($args.count -eq 1) {
"`n`r`t`t`t`t`t`t`t`tWindows Description"
Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tProcessor Information"
Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tRAM information"
Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Format-Table –AutoSize
Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tDisk Information"
Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Format-Table –AutoSize
Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Format-Table –AutoSize
Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tDomain Information"
Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tUser Information"
Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tUserEventLog"
Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Format-Table –AutoSize
#Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | #FL * | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tStartup Programs"
Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tScheduled Tasks"
Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tNetwork Information"
Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Format-Table –AutoSize

Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tDNS Cache Information"
Get-DnsClientCache | select Name,Entry,Data,Section | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tPrinter Information"
Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Format-Table –AutoSize
#Get-PrinterDriver | Select #Name,DriverVersion,HardwareID,Manufacturer,HardwareID,PrinterEnvironment,Pr#intProcessor,provider

"`n`r`t`t`t`t`t`t`t`tList Of Software"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize

"`n`r`t`t`t`t`t`t`t`tProcess' List"
Get-Process | select processname,path,id | Format-Table -AutoSize

"`n`r`t`t`t`t`t`t`t`tDriverList"
Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Format-Table -AutoSize

"`n`r`t`t`t`t`t`t`t`tDocuments and Downloads"
$s = 'C:\Users\';$d = '\Documents\';$FullPath = $s + $args[0] + $d
Get-ChildItem -Force $FullPath

$f = 'C:\Users\';$l = '\Downloads\';$FPD = $f + $args[0] + $l
Get-ChildItem -Force $FPD
}




if($args.count -eq 2) {
if($args[1] -eq "csv") {

"`n`r`t`t`t`t`t`t`t`tWindows Description" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-CimInstance Win32_OperatingSystem | select-object LocalDateTime,LastBootUpTime,CurrentTimeZone,RegisteredUser,CSName,Description,Caption,OSArchitecture,BootDevice,SystemDirectory,SerialNumber,Version,ServicePackMajorVersion,InstallDate,BuildNumber | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

"`n`r`t`t`t`t`t`t`t`tProcessor Information" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-CimInstance Win32_Processor | select-object DeviceID,Name,Description,CreationClassName,SystemCreationClassName,OtherFamilyDescription,Manufacturer,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors,PartNumber,ProcessorId,SerialNumber,CimClass | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tRAM information" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-CimInstance Win32_PhysicalMemory | select-object Caption,Manufacturer,Model,PartNumber,SerialNumber,Tag,Capacity,CimClass | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-WmiObject Win32_PhysicalMemoryArray | select-object MemoryDevices,MaxCapacity,Manufacturer | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tDisk Information" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-Disk | select-object DiskNumber,PartitionStyle,OperationalStatus,HealthStatus,BusType,OfflineReason,UniqueId,FirmwareVersion,Model,NumberOfPartitions,PhysicalSectorSize,SerialNumber,Signature,Size,Path | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-Partition | select DiskNumber,PartitionNumber,Type,OperationalStatus,IsActive,IsBoot,IsHidden,IsOffline,IsShadowCopy,Size | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-PhysicalDisk | select ClassName,OperationalStatus,HealthStatus,BusType,MediaType,OperationalDetail,SerialNumber | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tDomain Information`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-CimInstance Win32_ComputerSystem | select-object Name,PrimaryOwnerContact,UserName,Description,DNSHostName,Domain,workgroup,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tUser Information`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-LocalUser | select-object Name,ObjectClass,PrincipleSource,LastLogon,PasswordRequired,PasswordLastSet,FullName,Description,SID,Enabled | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tUserEventLog`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

#Get-EventLog -ComputerName "." System -Source Microsoft-Windows-Winlogon | #FL * | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall #2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tStartup Programs`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-CimInstance Win32_StartupCommand | select-object Name,User,Caption,UserSID,Location | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tScheduled Tasks`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-ScheduledTask | select Author,TaskName,Date,State,TaskPath,Triggers,Actions | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tNetwork Information`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-NetAdapterHardwareInfo | Select Name,ifDesc,Bus,Device,Slot,Caption,Description,InterfaceDescription,SystemName,SlotNumber | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-CimInstance Win32_NetworkAdapterConfiguration | select MACAddress,IPAddress,DHCPLEaseObtained,DHCPLeaseExpires,DHCPServer,DNSDomain,Description,DefaultGateway | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tDNS Cache Information`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-DnsClientCache | select Name,Entry,Data,Section | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tPrinter Information`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-Printer | Select Name,PrinterStatus,Type,DeviceType,DataType,DriverName,PortName,PrintProcessor | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

#Get-PrinterDriver | Select #Name,DriverVersion,HardwareID,Manufacturer,HardwareID,PrinterEnvironment,Pr#intProcessor,provider | Export-Csv -Path C:\Users\#$env:username'\Documents#\School\Fall 2017\CSEC 475\Scripts\Project#\SysInAnalysis.txt' -#NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tList Of Software`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tProcess' List`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-Process | select processname,path,id | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tDriverList`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-WmiObject Win32_PnpSignedDriver | select DeviceName,DriverVersion,Manufacturer | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


"`n`r`t`t`t`t`t`t`t`tDocuments and Downloads`n" | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

Get-ChildItem -Path C:\Users\$env:username\Documents\ | select mode, name, length, lastwritetime | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation


Get-ChildItem -Path C:\Users\$env:username\downloads | select mode, name, length, lastwritetime | Export-Csv -Path C:\Users\$env:username'\Documents\School\Fall 2017\CSEC 475\Scripts\Project\SysInAnalysis.txt' -NoTypeInformation

}}


