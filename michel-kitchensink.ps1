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

#Operators
@(1, 2) + 3  #add to array
'hello'  + ' ' + 'world' 
3 + 4
@(1, 2) + @(3, 4)  #array + array
@{key1 = 1} + @{key2 = 2}   #join hashtable
'hello' * 3 
3 % 2  #modulus in this case 1
4 / 6
78 -shl 1  #Shift left each bit
#assignments
$host.UI.RawUI.WindowTitle = 'PowerShell window' 
$i = 1 
$i += 20
$hashtable = @{key1 = 1} 
$hashtable += @{key2 = 2} 
$i = 2 
$i *= 2 
$variable = 2 
$variable /= 2
$variable = 10 
$variable %= 3
#comparison
'Trees' -ceq 'trees'   #Case sensitive
'Trees' -ieq 'trees' 
1, 2, 3, 4 -ge 3    #greater then
'one', 'two', 'three' -like '*e*'  #one and three
$array = 1, 2 
if ($array -eq $null) { Write-Host 'Variable not set' }  #$nul compare
20 -ne 100 
'this' -ne 'that' 
$false -ne 'false'
'The cow jumped over the moon' -like '*moon*' 
'Hello world' -like '??llo w*' 
'' -like '*' 
'' -notlike '?*' 
1 -ge 1        # Returns true 
2 -gt 1        # Returns true 
1.4 -lt 1.9    # Returns true 
1.1 -le 1.1    # Returns true 
'bears' -gt 'Bears'    # False, they are equal to one another 
'bears' -clt 'Bears'   # True, b before B 
1, 2 -contains 2       # Returns true 
1, 2, 3 -contains 4    # Returns false 
1 -in 1, 2, 3    # Returns true 
4 -in 1, 2, 3    # Returns false 
4 -notin 5  #true

#Regular expressions
'The cow jumped over the moon' -match 'cow'  # Returns true 
'The       cow' -match 'The +cow'            # Returns true  , + means 1 or more space
'1234567689' -match '[0-4]*'   #0 or more 0 till 4
$matches  #shows what is matched 1234
'Group one, Group two' -match 'Group (.*), Group (.*)' #Capture groups
$matches #all groups
$matches[1]  #or just specific one group
$matches.1
#replace is like match but replace match
'abababab' -replace 'a', 'c'
'value1,value2,value3' -replace '(.*),(.*),(.*)', '$3,$2,$1' 
$1 = $2 = $3 = 'Oops'
Write-Host ('value1,value2,value3' -replace '(.*),(.*),(.*)', '$3,$2,$1') -ForegroundColor Green
#Using double quotes does not work
Write-Host ('value1,value2,value3' -replace '(.*),(.*),(.*)', "$3,$2,$1") -ForegroundColor Red
#Split uses regex to split array into entries
'a1b2c3d4' -split '[0-9]' 

#binary operators band bor, bnot , bxor

#logical operators
$true -and $true 
1 -lt 2 -and "string" -like 's*' 
1 -eq 1 -and 2 -eq 2 -and 3 -eq 3 
(Test-Path C:\Windows) -and (Test-Path 'C:\Program Files') 
$true -or $true 
2 -gt 1 -or "something" -ne "nothing" 
1 -eq 1 -or 2 -eq 1 
(Test-Path C:\Windows) -or (Test-Path D:\Windows)
#exclusive or, left OR right true not both:
$true -xor $false 
1 -le 2 -xor 1 -eq 2 
(Test-Path C:\Windows) -xor (Test-Path D:\Windows) 
#not
-not $false 
-not (Test-Path X:\) 
-not ($true -and $false) 
!($true -and $false) 

#type operators
#as to convert type
"1" -as [Int32] 
'String' -as [Type]
#is and isnot to test type
'string' -is [String] 
1 -is [Int32] 
[String] -is [Type] 
123 -isnot [String] 

#redirect
Get-Process -Id $pid > process.txt
Get-Content process.txt 
$i = 1 
function Test-Redirect{ 
    Write-Warning "Warning $i" 
} 
Test-Redirect 3> 'warnings.txt'   # Overwrite 
$i++ 
Test-Redirect 3>> 'warnings.txt'  # Append 
#or split streams based on error or warnings:
function Test-Redirect{ 
    'This is standard out' 
           
    Write-Error 'This is an error' 
    Write-Warning 'This is a warning' 
} 
Test-Redirect 3> 'warnings.txt' 2> 'errors.txt' 
#or all redirect
$verbosePreference = 'continue' 
function Test-Redirect{ 
    'This is standard out' 
 
    Write-Information 'This is information' 
    Write-Host 'This is information as well' 
    Write-Error 'This is an error' 
    Write-Verbose 'This is verbose' 
    Write-Warning 'This is a warning' 
} 
Test-Redirect *> 'alloutput.txt' 
#redirect to standard our
function Test-Redirect{
    'This is standard out'

    Write-Information 'This is information'
}

$stdOut = Test-Redirect 6>&1
$stdOut
#Drop unwanted
Get-Process > $null

#Other operators
$command = 'ipconfig' 
& $command 
$scriptBlock = { Write-Host 'Hello world' } 
& $scriptBlock 
#create array using , operator
$array = ,1
#format a string using -f
'1: {0}, 2: {1}, 3: {2}' -f 1, 2, 3 
'The pass mark is {0:P}' -f 0.8 
'The price is {0:C2}' -f 199 
#increment/decrement ++ and --
for ($i = 0; $i -le 15; $i++) { 
    Write-Host $i -ForegroundColor $i
 } 
#2nd example
$array = 1..5 
$i = 0 
do { 
    # $i is incremented before use, 2 will be the first printed. 
    Write-Host $array[++$i]
 } while ($i -lt $array.Count -1) 
 #join array
 "a,b,c,d" -split ',' -join "`t"



#Get-ADUser -Filter { sAMAccountName -eq "SomeName" }
#Get-Service -Filter { Status -eq 'Stopped' }

Get-ChildItem -Recurse:$true  #This is a switch argument
ls -Recurse:$true | grep sprint