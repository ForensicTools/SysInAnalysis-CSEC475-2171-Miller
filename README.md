# SysInAnalysis-CSEC475-2171-Miller
Tested on Powershell version 5.0 Windows 10

Running powershell as an administrator is recommended, do this by searching for powershell in the search bar, right click on powershell to display a drop down menu and left click the run as administrator option. Ensure that you are able to run powershell scripts with Get-ExecutionPolicy, which should be set to unsigned or remotesigned. If this is not the case then running powershell as an administrator, use the command “Set-ExecutionPolicy RemoteSigned” without quotes.
 
Each script can be run independently or by using .\SysInAnalysis.ps1 to have access to each script.  Ensure that if SysInAnalysis.ps1 is in the same directory as the other scripts. To run open Powershell or Powershell ISE, change directory to the location of the files, this is needed to ensure that SysInAnalysis can find and run the other scripts. Then use “.\SysInAnalysis.ps1” without quotes to access all scripts, “.\information.ps1” without quotes  to run the information gathering script, “.\HashComparison.ps1” without quotes  to run a hashing script or “.\usb.ps1”  without quotes  to run a script that gathers information on usb drives inserted after the script is run.

If SysInAnalysis.ps1 is the chosen script you will be prompted to enter an option. 
 
 	-h to display the help menu, 
 
 	info to run the info script, 
 
 	hash to use the hash comparison script, 
 
 	usb to  run the usb script, 
 
	-p will display all of the processes, 
 
 	stop will prompt the user for a process ID and then will proceed to stop said process 
 
 	quit will end the script. 

Side note: selecting usb will make the powershell window disappear but the script will continue to run. To stop the script from running the user must end the process. If attempting to run this script and an error occurs informing the user that an event volumechange is already in use, use the command “Unregister-Event volumechange” without quotes.  This might occur if the script ends with a usb is still inserted and then the user attempts to reuse the script.

The information script will initially prompt the user for an option, 

            -h displays the help menu, 
	    
            -d -Displays select statements 1-18
	    
            -s -Prompts user for a number 1-22 to display specified information, -h displays help
	    
             -f -Prompts user for the name of a file, If the file exists the path is displayed
	     
             -a -Displays all Aliases
	     
             -v -Displays viewable directories/drives/Hkeys other than the C: Drive
	     
             csv -output information to csv
	     
             clear -clears the powershell screen
	     
             back -Return to last section

The Hash Comparison script prompts the user for an option.

	-h -Displays the help menu

	-a -Hash Comparison of all files user has permission to starting at C:\Users\

	-p -Specify a path and do a hash comparison of all files within that and all accessible subdirectories

	-s -Search a system from C:\Users\  for a hash value that matches the input file

	-c -Compares the hash value of two files based on a requested format

	Csv -output information into a csv file

	[File Name] -Search system from C:\Users\ for the file, display the hash value in the requested format

	clear -clears the powershell screen

	back -ends the program

Running usb.ps1 will collect information on a usb drive that has been inserted into the computer and will output the information to a csv file. The output file is log.txt and outputs to the users desktop. To change this open the script and change the first line to the output path and filename. To run this as an independent script where the powershell screen is hidden use “powershell.exe -WindowStyle Hidden -ExecutionPolicy Unrestricted .\usb.ps1” without quotes

Ending Note:
These scripts can be run either on a computer or from a usb drive for mobility. This can easily be configured to add scripts to it by changing the SysInAnalysis.ps1 and adding the name and path to the switch statement

