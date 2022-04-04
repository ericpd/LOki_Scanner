#Variables
$computername = Get-Content servers.txt
$sourcefile = "\\server01\Pranay\xxxxx.exe"
#This section will install the software 
foreach ($computer in $computername) 
{
    $destinationFolder = "\\$computer\C$\Temp"
    #It will copy $sourcefile to the $destinationfolder. If the Folder does not exist it will create it.

    if (!(Test-Path -path $destinationFolder))
    {
        New-Item $destinationFolder -Type Directory
    }
    Copy-Item -Path $sourcefile -Destination $destinationFolder
    Invoke-Command -ComputerName $computer -ScriptBlock {Start-Process 'c:\temp\xxxxx.exe --update'}
    Invoke-Command -ComputerName $computer -ScriptBlock {Start-Process 'c:\temp\xxxxxx.exe --exec -r 9080'}
}
