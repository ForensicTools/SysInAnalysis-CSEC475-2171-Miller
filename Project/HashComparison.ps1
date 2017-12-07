#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.

while(($Option=Read-Host "Hash`nPlease Enter an option, -h for the help menu`n`t") -ne "back"){
   Switch ($Option)
   {
    "-h"{"    -a -Hash Comparison of all files user has permission to starting at C:\Users\`n`t
    -p -Specify a path and do a hash comparison of all files within that and all accessible subdirectories`n`t`t
    -s -Search a system for a hash value that matches the input file`n`t`t
    -c -Compares the hash value of two files based on a requested format`n`t
    csv -output information into a csv file`n
    [File Name] -Search system for the file, display the hash value in the requested format`n
        -Supported Hash Algorithms SHA1,SHA256,SHA384,SHA512,MACTripleDES,MD5,RIPEMD160`n
    clear -clears the powershell screen`n
    back -returns to SysInAnalysis script or ends if only HashComparison was used
    "}  
        "clear"{clear}


        "-a" {
             $Algo=Read-Host "Please enter a supported algorithm"
             Measure-Command{

                if($Algo -eq '')
                {
                        $All = Get-ChildItem -Path C:\Users -Recurse -File | Where-Object{'.dmp', '.vmem','.vmss','.nvram',
                        '.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Group {($_|Get-FileHash).Hash} -OutBuffer 1000 | Where Count -gt 1
                }
                
                elseif($Algo -ne '')
                {
                    $All = Get-ChildItem -Path C:\Users -Recurse -File | Where-Object{'.dmp', '.vmem','.vmss','.nvram',
                    '.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Group {($_|Get-FileHash -Algorithm $Algo).Hash} -OutBuffer 1000 | Where Count -gt 1
                }


                foreach($FileGroup in $All)
                {
                    Write-Host "These files share hash $($FileGroup.Name)"
                    $FileGroup.Group.FullName |Write-Host
                }
              }
          } 


        "-p" {
             $All=Get-ChildItem -Path (Read-Host "Please Choose a Path") -Recurse -File -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram',
             '.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Group {($_|Get-FileHash).Hash} -OutBuffer 1000 | Where Count -gt 1
             foreach($FileGroup in $All)
             {
                Write-Host "These files share hash $($FileGroup.Name)"
                $FileGroup.Group.FullName |Write-Host
             }
           }

        "-s" {
           $File=Read-Host "Please Enter a file"
           $HashedFile=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File)*"} | Get-FileHash 
           $HashedFile
           $All=Get-ChildItem -Path C:\Users\ -Recurse -File -ErrorAction ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Group {($_|Get-FileHash).Hash} 
           foreach($Item in $all)
           {
             if($($HashedFile).Hash -eq $Item.Name)
               {
                  Write-Host "These files share the same hash $($Item.Name)"
                  $Item.Group.FullName | Write-Host
               }
           }           
                       
          }
        "-c" {
            $File1=Read-Host "`tEnter First file"
            $File2=Read-Host "`tEnter Second file"
            $Algo=Read-Host "`tEnter an algorithm to use"
            if($Algo -eq "")
            {
                $HashedFile1=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File1)*"} | Get-FileHash
                $HashedFile2=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File2)*"} | Get-FileHash
                $HashedFile1
                $HashedFile2
                compare-object $HashedFile2 $HashedFile1 -property Hash -PassThru -IncludeEqual -ExcludeDifferent:$ShowMatches.IsPresent |	Select-Object Path, Hash, 
                algorithm,@{Name="Matched Hash";Expression={If($_.SideIndicator -eq "=="){"Matched to $($HashedFile1.Path)"}}}
            }
            else
            {
                $HashedFile1=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File1)*"} | Get-FileHash -Algorithm $Algo
                $HashedFile2=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File2)*"} | Get-FileHash -Algorithm $Algo
                $HashedFile1
                $HashedFile2
                compare-object $HashedFile2 $HashedFile1 -property Hash -PassThru -IncludeEqual -ExcludeDifferent:$ShowMatches.IsPresent |	Select-Object Path, 
                Hash, algorithm,@{Name="Matched Hash";Expression={If($_.SideIndicator -eq "=="){"Matched to $($HashedFile1.Path)"}}}
            }
        }


        "csv"{
                while(($Option=Read-Host "Hash csv`nPlease Enter an option, -h for the help menu`n`t") -ne "back"){
                    Switch ($Option)
                       {
                        "-h"{"
                        `a -Hash Comparison of all files user has permission to starting at C:\Users\`n`t
                        -p -Specify a path and do a hash comparison of all files within that and all accessible subdirectories`n`t`t
                        -s -Search a system for a hash value that matches the input file`n`t`t
                        -c -Compares the hash value of two files based on a requested format`n`t
                        [File Name] -Search system for the file, display the hash value in the requested format`n
                            -Supported Hash Algorithms SHA1,SHA256,SHA384,SHA512,MACTripleDES,MD5,RIPEMD160`n
                        clear -clears powershell screen`n
                        back -returns to the hash menu
                      "}
                  "clear"{clear}

	              "-a" {
                        $OutPut=Read-Host "Enter the out file path and name"
                        
                        if($Algo -eq '')
                        {
                            $All = Get-ChildItem -Path C:\Users -Recurse -File | Where-Object{'.dmp', '.vmem','.vmss','.nvram',
                            '.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Group {($_|Get-FileHash).Hash} -OutBuffer 1000 | Where Count -gt 1
                        }
                
                        elseif($Algo -ne '')
                        {
                            $All = Get-ChildItem -Path C:\Users -Recurse -File | Where-Object{'.dmp', '.vmem','.vmss','.nvram',
                            '.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Group {($_|Get-FileHash -Algorithm $Algo).Hash} -OutBuffer 1000 | Where Count -gt 1
                        }

                        foreach($FileGroup in $All)
                            {
                                "These files share hash $($FileGroup.Name)" >> $OutPut
                                $FileGroup.Group.FullName >> $OutPut
                            }
                       }
                        
                  "-p" {
                        $All=Get-ChildItem -Path (Read-Host "Please choose a path") -Recurse -File | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk' -notcontains $_.extension} | Group {($_|Get-FileHash).Hash} -OutBuffer 1000 | Where Count -gt 1
                        foreach($FileGroup in $All)
                            {
                                "These files share hash $($FileGroup.Name)" >> $OutPut
                                $FileGroup.Group.FullName >> $OutPut
                            }
                       }
                  "-s" {
                        $OutPut=Read-Host "Enter an out file path and name"
                        $File=Read-Host "Enter a file"
                        $HashedFile=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction ignore -OutBuffer 1000 | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File)*"} | Get-FileHash
                        $HashedFile
                        Measure-Command{$All=Get-ChildItem -Path C:\Users\ -Recurse -File -ErrorAction ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | Group {($_|Get-FileHash).Hash} -OutBuffer 1000| Where count -gt 1
                        foreach($Item in $all)
                            {
                            if($($HashedFile).Hash -eq $Item.Name)
                                {
                                    "These files share the same hash $($Item.Name)" >> $OutPut
                                    $Item.Group.FullName >> $OutPut
                                }
                            }           
                       }
                       }

                    "-c" {
                            $File1=Read-Host "`tEnter First file"
                            $File2=Read-Host "`tEnter Second file"
                            $Algo=Read-Host "`tEnter an algorithm to use"
                            $OutPut=Read-Host "`tEnter an out file path and name"
                            if($Algo -eq "")
                                {
                                    $HashedFile1=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File1)*"} | Get-FileHash
                                    $HashedFile2=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File2)*"} | Get-FileHash
                                    $HashedFile1 
                                    $HashedFile2
                                    compare-object $HashedFile2 $HashedFile1 -property Hash -PassThru -IncludeEqual -ExcludeDifferent:$ShowMatches.IsPresent |	Select-Object Path, Hash, algorithm,@{Name="Matched Hash";Expression={If($_.SideIndicator -eq "=="){"Matched to $($HashedFile1.Name)"}}} >> $OutPut
                                }
                            else
                                {
                                    $HashedFile1=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File1)*"} | Get-FileHash -Algorithm $Algo
                                    $HashedFile2=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($File2)*"} | Get-FileHash -Algorithm $Algo
                                    $HashedFile1
                                    $HashedFile2
                                    compare-object $HashedFile2 $HashedFile1 -property Hash -PassThru -IncludeEqual -ExcludeDifferent:$ShowMatches.IsPresent |	Select-Object Path, Hash, algorithm,@{Name="Matched Hash";Expression={If($_.SideIndicator -eq "=="){"Match"}}} >> $OutPut
                                }
                         }

                         default{$OutPut=Read-Host "Enter an out path and file"
                                    $Algo=Read-Host "`n`tAlgorithm, Sha256 is the default algorithm"
                                    if($Algo -eq ""){Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($Option)*"} | Get-FileHash >> $OutPut}
                                    else{Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($Option)*"} | Get-FileHash -Algorithm $Algo >> $OutPut}
                                }


                       }
                   }
                }

	    "" {"Nothing Entered"}

	    default{$Algo=Read-Host "`n`tAlgorithm, Sha256 is the default algorithm"
            if($Algo -eq ""){Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($Option)*"} | Get-FileHash}
            else{Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction Ignore | Where-Object{'.dmp', '.vmem','.vmss','.nvram','.vmsd','.vmx','.vmxf','.vmdk','.lnk' -notcontains $_.extension} | ? {$_.Name -like "$($Option)*"} | Get-FileHash -Algorithm $Algo}
        }
    }
}