
while(($Option=Read-Host "Hash`nPlease Enter an option, -h for the help menu`n`t") -ne "quit"){
   Switch ($Option)
   {
    "-h"{"`t1 -Hash Comparison of all files user has permission to starting at C:\Users\`n`t
    2 -Specify a path and do a hash comparison of all files within that and all accessible subdirectories`n`t`t
    3 -Search a system for a hash value that matches the input file`n`t`t
    4 -Compares the hash value of two files based on a requested format`n`t
    [File Name] -Search system for the file, display the hash value in the requested format`n
    quit -ends the program
    "}

	    1 {
             Measure-Command{$All = Get-ChildItem -Path C:\Users\ -Recurse -File | Group {($_|Get-FileHash).Hash} -OutBuffer 1000 | Where Count -gt 1
             foreach($FileGroup in $All)
             {
                Write-Host "These files share hash $($FileGroup.Name)"
                $FileGroup.Group.FullName |Write-Host
             }
           }
          } 
        2 {
             $All=Get-ChildItem -Path (Read-Host "Please Choose a Path") -Recurse -File | Group {($_|Get-FileHash).Hash} -OutBuffer 1000 | Where Count -gt 1
             foreach($FileGroup in $All)
             {
                Write-Host "These files share hash $($FileGroup.Name)"
                $FileGroup.Group.FullName |Write-Host
             }
           }

        3 {
           $File=Read-Host "Please Enter a file"
           $HashedFile=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force -OutBuffer 1000| ? {$_.Name -like "$($File)*"} | Get-FileHash
           $HashedFile
           $whichpath=read-host "Which path is correct?"
           $All=Get-ChildItem -Path C:\Users\ -Recurse -File -ErrorAction ignore | Group {($_|Get-FileHash).Hash} 
           foreach($Item in $all)
           {
             if($($HashedFile[$Whichpath-1]).Hash -eq $Item.Name)
               {
                  Write-Host "These files share the same hash $($Item.Name)"
                  $Item.Group.FullName | Write-Host
               }
           }           
                       
          }
        4 {
            $File1=Read-Host "`tEnter First file"
            $File2=Read-Host "`tEnter Second file"
            $Algo=Read-Host "`tEnter an algorithm to use"
            if($Algo -eq "")
            {
                $HashedFile1=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($File1)*"} | Get-FileHash
                $HashedFile2=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($File2)*"} | Get-FileHash
                $HashedFile1
                $HashedFile2
                compare-object $HashedFile2 $HashedFile1 -property Hash -PassThru -IncludeEqual -ExcludeDifferent:$ShowMatches.IsPresent |	Select-Object Path, Hash, algorithm,@{Name="Matched Hash";Expression={If($_.SideIndicator -eq "=="){"Match"}}}
            }
            else
            {
                $HashedFile1=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($File1)*"} | Get-FileHash -Algorithm $Algo
                $HashedFile2=Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($File2)*"} | Get-FileHash -Algorithm $Algo
                $HashedFile1
                $HashedFile2
                compare-object $HashedFile2 $HashedFile1 -property Hash -PassThru -IncludeEqual -ExcludeDifferent:$ShowMatches.IsPresent |	Select-Object Path, Hash, algorithm,@{Name="Matched Hash";Expression={If($_.SideIndicator -eq "=="){"Match"}}}
            }
        }

	    "" {"Nothing Entered"}

	    default{$Algo=Read-Host "`n`tAlgorithm, Sha256 is the default algorithm"
            if($Algo -eq ""){Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($Option)*"} | Get-FileHash}
            else{Get-ChildItem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue -Force | ? {$_.Name -like "$($Option)*"} | Get-FileHash -Algorithm $Algo}
        }
    }
}