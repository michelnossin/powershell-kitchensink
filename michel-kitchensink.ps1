<#
Michel's powershell kitchensink v2.0
Use Windows 10 Pro/Enterprise's Powershell ISE env, or Visual Studop Code with Powershell plugin.
#>

#History
Get-History

#multie commands on one line, and special printed characters
Write-Output "one" ; Write-Output "two" ; Write-Output "`nand some newline and `ttab"

#Call paraemeter to dynamically determine command
$procesId = & ‘Get-Process’
Write-Output $procesId
$myText= "Write-Output"
& {Write-Output $myText}

#Execute another Powershell script
#. C:\someScript.ps1

#command with multiple parameters using Tick `
'one' -replace 'o', 't' `
      -replace 'n', 'w' `
      -replace 'e', 'o' 

#common operators
1 -eq 1
1 -ne 2
$true -and $true
$true -or $false
0 + 1
"tr" + "ue"
"Host is in this subexpression $($host.InstanceId)"
"IS this true ? Answer: $(1 -eq 1)"

#Drop unwanted
$null = Get-Command #assign null
[Void](Get-Command)  #cast void
Get-Command | Out-Null #pipe to Out-Null
Get-Command > $null #redirect to null

#Array and hashtsble (map)
$array = @()    # Empty array
$array = @(1, 2, 3, 4)
$array = 1, 2, 3, 4 #implicit
$array = “one”, “two”, “three”, “four”
$hashtable = @{}    # Empty hashtable
$hashtable = @{Key1 = “Value1”}
$hashtable = @{Key1 = “Value1”; Key2 = “Value2”}
$hashtable.Key1

#strings
#expanding:
“Value”
$greeting = “Hello”; “$greeting World”   # Expands variable
$one = ‘One’
@”
Must be opened on its own line.
This string will expand variables like $one.
Can contain other quotes like “ and ‘.
Must be closed on its own line with no preceding white space.
“@
#non-expanding with single quote
‘Value’
‘$greeting World’    # Does not expand variable
@’
Must be opened on its own line.
This string will not expand variables like $greeting.
Can contain other quotes like “ and ‘.
Must be closed on its own line with no preceding white space.
‘@
#quotes in string
“Double-quotes may be escaped with tick like `”.”
“Or double-quotes may be escaped with another quote ““.”
‘Single-quotes may be escaped with tick like `’.’
#‘Or single-quotes may be escaped with another quote like ‘‘.’

#common reserved keywords
$Error[0]    # The last error
$object = [PSCustomObject]@{
    Array = @(1, 2, 3, 4, 5)
    }
$object    # Shows 1, 2, 3, and 4
$formatenumerationlimit = 1
$object    # Shows 1
$host
$host.UI.RawUI.WindowTitle
‘text.out’ –match ‘out’ #true
$matches  #0   out
#output field seperator
$arr = 1, 2, 3, 4
“Joined based on OFS: $arr”
$ofs = ‘, ‘
“Joined based on OFS: $arr”
Get-Process –Id $PID
$PSVersionTable.PSVersion  #powershell version 5.1
$PWD.Path   #current dir

#commands
Get-History #, history Shows command history for the current session.
#<Text><Tab>  #Autocompletes in context. Tab can be used t(multiple times!) o complete command names,
ii #ii is an alias for the invoke-item. Opens the current directory in Explorer.
start iexplore  #start is an alias for the start-process. Opens Internet Explorer.
start iexplore -verb runas    #Runs a process as administrator.

#help
Get-Help Get-ChildItem
Get-Help | more
Get-Help default -ShowWindow
Get-Help *
Get-Help -Category All
Get-Help -Category HelpFile
Get-Help Get-Process -Detailed
Get-Help Get-Process -Full

#calculate
$x = 20
$y = $x + 40

#variable to save output
$list = Get-Service

#Verbs within command like get, Set, new
Get-Verb

#Find a command new using regex
Get-Command Get-AzureRmAD*

#Aliases
Get-Alias *ls*
Get-Alias -Definition Get-ChildItem
help ls
New-Alias grep -Value Select-String
ls | grep sprint

#Confirm, whatif , force
New-Item IMadeThisUp.txt -Force  #always do it
Remove-Item .\IMadeThisUp.txt -Confirm  #ask first
Remove-Item .\IMadeThisUp.txt -Confirm:$false  #overrule default)
$ConfirmPreference    #default powershell will determine confirm based on this preference
Remove-Item .\IMadeThisUp.txt -WhatIf  #dont do it, just say what would happen
$WhatIfPreference = $true  #means command supportoing whatif will be used if expl. defined

#providers:
Get-PSProvider #use data not easiy accessible
Get-PSDrive
Set-Location C:\
Get-ChildItem -File



#Get-ADUser -Filter { sAMAccountName -eq "SomeName" }
#Get-Service -Filter { Status -eq 'Stopped' }

#Switch arguments
Get-ChildItem -Recurse:$true  #This is a switch argument
ls -Recurse:$true | grep sprint