#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.

$output="C:\Users\$($env:USERNAME)\Desktop\log.txt" #Change this to where the out files path should be as well as the name of the log

Register-WmiEvent -Class win32_VolumeChangeEvent -SourceIdentifier volumeChange 
write-host (get-date -format s) " Beginning script..."

do{
$newEvent = Wait-Event -SourceIdentifier volumeChange 
$eventType = $newEvent.SourceEventArgs.NewEvent.EventType 
$eventTypeName = switch($eventType)
{
1 {"Configuration changed"}
2 {"Device arrival"}
3 {"Device removal"}
4 {"docking"}
}

"$(get-date -format s) Event detected = "+$eventTypeName >> $output

$drive=gwmi win32_diskdrive | ?{$_.interfacetype -eq "USB"} | %{gwmi -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($_.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"} |  %{gwmi -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($_.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"} | %{$_.deviceid}

if ($eventType -eq 2)
{
$driveLetter = $newEvent.SourceEventArgs.NewEvent.DriveName
$driveLabel = ([wmi]"Win32_LogicalDisk='$driveLetter'").VolumeName
"$(get-date -format s) Drive name ="+ $driveLetter >> $output 
"$(get-date -format s) Drive label = "+$driveLabel >> $output

if ($driveLetter -eq $drive)
{

"`nDevice Information" >> $output
GET-WMIOBJECT win32_diskdrive | Where { $_.InterfaceType –eq ‘USB’ } | Select-Object SystemName,caption,DeviceID,manufacturer,MediaType,Partitions,size,status | Format-Table -AutoSize -Wrap >> $output
"`nFiles" >> $output
Get-ChildItem -Path $drive -recurse -ErrorAction SilentlyContinue -Force -OutBuffer 1000 | Format-table -AutoSize -wrap >> $output
"`nHash" >> $output
Get-ChildItem -Path $drive -recurse -ErrorAction SilentlyContinue -Force -OutBuffer 1000 | Get-FileHash | Format-Table -AutoSize -Wrap >> $output
"`n`n`n" >> $output
start-sleep -seconds 3

}
}
Remove-Event -SourceIdentifier volumeChange
} while (1-eq1)
Unregister-Event -SourceIdentifier volumeChange