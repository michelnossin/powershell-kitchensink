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

#modules
New-Module -Name TestModule -ScriptBlock { 
    function Get-Number { return 1 } 
} 
Get-Number
Get-Module -ListAvailable
Import-Module -Name PSWorkflow 
Import-Module -Name C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWorkflow\PSWorkflow.psd1 
#automatic import when using command
Get-Module PSDesiredStateConfiguration  #not set
Get-DscResource
Get-Module PSDesiredStateConfiguration   #set
Get-Command -Module PSWorkflow #sfter import dhow commands works
#Remove-Module   will remove module
Find-Module Azure*
Find-Module posh-git  | Install-Module  
#Save-Module  downloads module but does not install
Get-PSSnapIn -Registered   #snap-in was used before modules were introduced


#objects
#st and non-std output , pipelines
$stdout = Get-CimInstance Win32_ComputerSystem
$stdout = Get-CimInstance Win32_ComputerSystem -Verbose  #Write-Warning , Write-Information ,Verbose are non-default output streams
Get-Process | Where-Object WorkingSet -gt 50MB  #pipe by passing an object, filtering the workingset memory property
#members , these are properties and methods
Get-Process -Id $PID | Get-Member
Get-Process -Id $PID | Get-Member -MemberType Property #notice get,or set for read and or write privs
#Access the property
$process = Get-Process -Id $PID 
$process.Name
(Get-Process -Id $PID).Name 
(Get-Process -Id $PID).StartTime.DayOfWeek  #Property of property object (datetime)
#Custom property with space in name:
$object = [PSCustomObject]@{ 'Some Name' = 'Value' } 
$object."Some Name" 
$object.'Some Name' 
$object.{Some Name}
#Access method
$date = Get-Date "01/01/2010"
$date.ToLongDateString()
#Add new memeber
$empty = New-Object Object
$empty | Add-Member -Name New -Value 'Hello world' -MemberType NoteProperty
$empty.new
#enumerate, list and filter
$drives = Get-PSDrive
$drives #list , not extra steps required
Get-Process | ForEach-Object { 
    Write-Host $_.Name -ForegroundColor Green 
}
Get-Process | Where-Object StartTime -gt (Get-Date 16:00:00)
#select certain members/properties, and sort
Get-Process | Select-Object -Property Name, Id
Get-Process | Select-Object -Property Name, *Memory
Get-Process | Select-Object -Property * -Exclude *Memory*
Get-ChildItem C:\ -Recurse | Select-Object -First 2
Get-ChildItem C:\ | Select-Object -Last 3
Get-ChildItem C:\ | Select-Object -Skip 4 -First 1
Get-ChildItem C:\ | Select-Object -ExpandProperty FullName
1, 1, 1, 3, 5, 2, 2, 4 | Select-Object -Unique
(1..3 + 1..3) | ForEach-Object { [PSCustomObject]@{ Number = $_ } }
(1..3 + 1..3) | ForEach-Object { [PSCustomObject]@{ Number = $_ } } | 
 Select-Object -Property * -Unique
 Get-Process -Id $PID | Get-Member -MemberType PropertySet
#create new
Get-Process | Select-Object -Property Name, Id, 
    @{Name='FileOwner'; Expression={ (Get-Acl $_.Path).Owner }}
#sort
5, 4, 3, 2, 1 | Sort-Object
Get-Process | Sort-Object -Property Id
Get-ChildItem C:\Windows\System32 | 
    Sort-Object LastWriteTime, Name
#custom object sort
$examResults = @(
    [PSCustomObject]@{ Exam = 'Music'; Result = 'N/A'; Mark = 0 }
    [PSCustomObject]@{ Exam = 'History'; Result = 'Fail'; Mark = 23 }
    [PSCustomObject]@{ Exam = 'Biology'; Result = 'Pass'; Mark = 78 }
    [PSCustomObject]@{ Exam = 'Physics'; Result = 'Pass'; Mark = 86 }
    [PSCustomObject]@{ Exam = 'Maths'; Result = 'Pass'; Mark = 92 }
    )
    $examResults | Sort-Object {
    switch ($_.Result) {
    'Pass' { 1 }
    'Fail' { 2 }
    'N/A' { 3 }
    }
    }
#custom sort descend
$examResults | Sort-Object { 
    switch ($_.Result) { 
        'Pass' { 1 } 
        'Fail' { 2 } 
        'N/A'  { 3 } 
    } 
}, Mark -Descending 
#Group and count
6, 7, 7, 8, 8, 8 | Group-Object
6, 7, 7, 8, 8, 8 | Group-Object -NoElement  #key is count, name is value
Get-ChildItem C:\Windows\Assembly -Filter *.dll -Recurse | 
    Group-Object Name  #Count files per filemame
Get-ChildItem C:\Windows\Assembly -Filter *.dll -Recurse |
    Group-Object Name -NoElement |
    Where-Object Count -gt 1 |
    Sort-Object Count, Name -Descending |
    Select-Object Name, Count -First 5  #Top 5
Get-ChildItem C:\Windows\Assembly -Filter *.dll -Recurse |
    Group-Object Name, Length -NoElement |
    Where-Object Count -gt 1 |
    Sort-Object Name -Descending |
    Select-Object Name, Count -First 6  #Group by name and file
'one@one.example', 'two@one.example', 'three@two.example' |
    Group-Object { ($_ -split '@')[1] }  #Group by on demand fields , the domain in this case
$hashtable = 'one', 'two', 'two' | Group-Object -AsHashtable -AsString
$hashtable['one']  #output put in hashtable, default case insensitive
1, 5, 9, 79 | Measure-Object  #stats like count, 4 in this case
1, 5, 9, 79 | Measure-Object -Average -Maximum -Minimum -Sum
Get-Process | Measure-Object WorkingSet -Average  #Property Workinset only
Get-Content C:\Windows\WindowsUpdate.log | Measure-Object -Line -Word -Character #File stats
Compare-Object -ReferenceObject 1, 2, 3, 4 -DifferenceObject 1, 2 #inequal only
Compare-Object -ReferenceObject 1, 2, 3, 4 -DifferenceObject 1, 2 -IncludeEqual
#passthru will pass the objects passing the criteriainstead of difference table
Compare-Object -ReferenceObject 1, 2, 3, 4 -DifferenceObject 1, 2 -ExcludeDifferent -IncludeEqual -PassThru
#compare files in 2 directories:
$reference = Get-ChildItem C:\Windows\System32 -File 
$difference = Get-ChildItem C:\Windows\SysWOW64 -File 
Compare-Object $reference $difference -Property Name, Length -IncludeEqual -ExcludeDifferent
#export (to csv)
Get-Process | Export-Csv processes.csv
Get-Process powershell | Select-Object Name, Id | Export-Csv .\Processes.csv
Get-Process explorer | Select-Object Name,Id | Export-Csv .\Processes.csv -Append
Get-Process | Export-Csv processes.csv -NoTypeInformation #no header
Get-Process powershell | Select-Object Name, Id | ConvertTo-Csv #just print std outpyut
#to convert array, first convert to string:
[PSCustomObject]@{
    Name = "Numbers"
    Value = 1, 2, 3, 4, 5
} | ForEach-Object {
    $_.Value = $_.Value -join ', '
    $_
} | ConvertTo-Csv -NoTypeInformation
#import tsv or csv
Import-Csv TabDelimitedFile.tsv -Delimiter `t
#Sort , prevent string sort by casting the ccolumn to int e.g.
Import-Csv .\positions.csv | Sort-Object { [Int]$_.Position }
#to get input from std input:
"powershell,404" | ConvertFrom-Csv -Header Name, Id
#to create xml file:
[PSCustomObject]@{ 
    Number  = 1 
    Decimal = 2.3 
    String  = 'Hello world' 
} | Export-Clixml .\object.xml 
$object = Import-Clixml .\object.xml
$object.Decimal.GetType()  #inspect type of column named Decimal

#Get-ADUser -Filter { sAMAccountName -eq "SomeName" }
#Get-Service -Filter { Status -eq 'Stopped' }

Get-ChildItem -Recurse:$true  #This is a switch argument
ls -Recurse:$true | grep sprint