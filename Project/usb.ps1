#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.
#Use this command without quotes in the powershell window to hide the usb script "powershell.exe -WindowStyle Hidden -ExecutionPolicy Unrestricted .\usb.ps1"

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
    }

    "$(get-date -format s) Event detected = "+$eventTypeName 

    if ($eventType -eq 2)
    {
        $drive=gwmi win32_diskdrive | ?{$_.interfacetype -eq "USB"} | %{gwmi -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($_.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"} |  %{gwmi -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($_.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"} | %{$_.deviceid}
        $driveLetter = $newEvent.SourceEventArgs.NewEvent.DriveName
        #$driveLabel = ([wmi]"Win32_LogicalDisk='$driveLetter'").VolumeName
        "$(get-date -format s) Drive name ="+ $driveLetter  
        "$(get-date -format s) Drive label = "+$driveLabel  

        for($i=0;$i -lt $drive.Length;$i++){
        if ($driveLetter -eq $drive.split()[$i])
        {

            #This portion is used to output the currently inserted usb drives, the files on the usb drive that was most recently inserted and the hashes of files on the usb.
            
            ###The device information portion places the specified fields into a file
            "`nDevice Information" >> $output
            GET-WMIOBJECT win32_diskdrive | Where { $_.InterfaceType –eq ‘USB’ } | Select-Object SystemName,caption,DeviceID,manufacturer,MediaType,
            Partitions,size,status | Format-Table -AutoSize -Wrap >> $output
            
            ###The Files portion parses the usb drive and places the name, length, last write time and mode into the file specified on line 5.
            "`nFiles" >> $output
            Get-ChildItem -Path $driveLetter -recurse -ErrorAction Ignore | Format-table -AutoSize -wrap >> $output
            
            ###The Hash portion parses the usb drive and places the hash algorithm and hash value into the file specified on line 5.
            "`nHash" >> $output
                                                                    <#
                                                                      If a usb is inserted and the hash algorithm seems like it can't proceed, The get-filehash function
                                                                      might be stuck on a file. The below file extensions are some types that take longer to hash or have 
                                                                      waited a reasonable amount of time without advancing. Any additional extensions can be added below 
                                                                      in the Where-Object{...} field. This will remove those files with the extension from the output
                                                                    #>
            Get-ChildItem -Path $driveletter -recurse | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd',
            '.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Get-FileHash <#-Algorithm #> | Format-Table -wrap -autosize >> $output   
                                                              <#
                                                                To change the hashing algorithm 
                                                                remove the block comment above in Get-FileHash
                                                                add one of the supported types after -Algorithm
                                                                [md5,sha1,sha256,sha384,sha512,MacTripleDES,RIPEMD160]
                                                                
                                                              #>  
            "`n`n`n" >> $output
            ##################
            
            #This Portion is used to display the information from the block above into the powershell screen, The same comments apply
            "`nDevice Information"
            GET-WMIOBJECT win32_diskdrive | Where { $_.InterfaceType –eq ‘USB’ } | Select-Object SystemName,caption,DeviceID,manufacturer,
            MediaType,Partitions,size,status | Format-Table -AutoSize -Wrap 
            "`nFiles" 
            Get-ChildItem -Path $driveLetter -recurse -ErrorAction Ignore -Force -OutBuffer 1000 | Format-table -AutoSize -wrap 
            "`nHash"
            Get-ChildItem -Path $driveletter -recurse | Where-Object{'.dmp', '.vmem','.vmss','.nvram',
            '.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Get-FileHash |Format-Table -wrap -autosize 
            
            "`n`n`n"

            start-sleep -seconds 3
        }
        }
        }
            Remove-Event -SourceIdentifier volumeChange
        } while (1 -eq 1)
            Unregister-Event -SourceIdentifier volumeChange