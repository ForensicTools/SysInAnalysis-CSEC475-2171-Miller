import os.path
import sys
import subprocess
import csv

def powerScript():
    if(len(sys.argv) > 1 and sys.argv[1]=='csv'):
        subprocess.call(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         ".\\SysInAnalysis.ps1 csv"], shell=True)
    else:
        subprocess.call(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                 ".\\SysInAnalysis.ps1"], shell=True)

def getFileNames():
    for filename in os.listdir(os.path.join(os.getcwd(), 'csvFiles')):
       csvparse(filename)

def csvparse(filename):
    size = sum(1 for _ in filename)
    with open(os.path.join(os.getcwd(),'csvFiles',filename)) as file:
        for i in range(0, size):
            line = file.readline().split(',')
            if len(line) > 1:
                print(line)
        file.close()
    return 0



def main():
    #powerScript()
    getFileNames()
main()