import os
import subprocess
import csv

def powerScript():
    #os.system('.\SysInAnalysis.ps1')
    subprocess.call(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                 ".\\SysInAnalysis.ps1 Hikiba csv"], shell=True)
powerScript()


