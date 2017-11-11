$File=Read-Host "Please Enter an option`n`tget -Retrieves the hash of a file in the requested format`n`tall -Hash Comparison of all files user has permission to`n`t[FileName] -Search system for the same hash value as the input file`n"
#
Switch ($File)
{
	"compare all" {$All=Get-ChildItem -Path C:\Users\Hikiba\Desktop\ -Recurse -File -ErrorAction SilentlyContinue | Group {($_|Get-FileHash).Hash} |		Where Count -gt 1 foreach($FileGroup in $All)
		{
    			Write-Host "These files share hash $($FileGroup.Name)"
    			$FileGroup.Group.FullName |Write-Host
		}
	} 
	"" {"Nothing Entered"}
	default{Get-ChildItem -Path C:\Users\ -Filter $File -Recurse -ErrorAction Ignore -Force | Get-FileHash}
}
#
#
#
#
#
#
#if($File -eq "get"){
#	$Filename=Read-Host -prompt ""
#}
#
#else if($File -eq "all")
#{
#	$All = Get-ChildItem -Path C:\Users\ -Recurse -File -ErrorAction #Continue | Group {($_|Get-FileHash).Hash} |Where Count -gt 1
#	foreach($FileGroup in $All)
#	{
#    		Write-Host "These files share hash $($FileGroup.Name)"
#    		$FileGroup.Group.FullName |Write-Host
#	}
#}
#Else{
#	$HashedFile=Get-ChildItem -Path C:\Users\ -Filter $File -Recurse -	#	ErrorAction SilentlyContinue -Force | Get-FileHash -Algorithm MD5
#
#$i=Get-ChildItem C:\Users\Hikiba\Desktop -File -Recurse -ErrorAction 	#SilentlyContinue| Group {($_|Get-FileHash).Hash} | Where Count -gt 1
	#foreach($FileGroup in $i)
	#{
    		#Write-Host $FileGroup.name, $FileGroup.Hash
    		#$FileGroup.Group.FullName | Write-Host
	#}
#}


#	foreach($i in Get-ChildItem C:\Users\Hikiba\ -File -Recurse -		#ErrorAction SilentlyContinue | Get-FileHash -Algorithm MD5)		
#	{
#		compare-object $i $HashedFile -property Hash -PassThru -	#	IncludeEqual -ExcludeDifferent:$ShowMatches.IsPresent | 		#Select-Object Path, Hash, algorithm,@{Name="Matched 		#Hash";Expression={If($_.SideIndicator -eq "==")				#{"Match"}}}
#	}
#}