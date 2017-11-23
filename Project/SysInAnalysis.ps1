#Before running this Script ensure that powershell is able to run scripts. If not run powershell as administrator
#Use command "Set-ExecutionPolicy RemoteSigned" without quotes and proceed to run script.

While(($Option=Read-Host "Which file would you like to run?")-ne "quit")
{
    switch($Option)
        {
            "-h"{"`ninfo -Runs the information script used to collect data about a system`nhash -Runs the Hash Comparison script`nusb -Runs a script in the background that waits for a USB drive to be inserted and then collects information about the device`n-p -retrieves a list of processes`nstop -prompts user for a process id number and stops the process`n"}
            "info"{.\information.ps1}
            "hash"{.\HashComparison.ps1}
            "usb"{powershell.exe -WindowStyle Hidden -ExecutionPolicy Unrestricted .\usb.ps1}
            "-p"{Get-Process}
            "stop"{Stop-Process (Read-Host "Which process id needs to be stopped")}
        }
}