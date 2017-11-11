$ErrorActionPreference='silentlycontinue'
while(($inp=Read-Host) -ne "quit"){
	Get-ChildItem -Path C:\ -Filter *.exe -Recurse -File| Sort-Object lastwritetime -Descending | select-object FullName, LastWriteTime, 			CreationTime, Length | format-table -autosize
}