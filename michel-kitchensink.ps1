<#
Michel's powershell kitchensink v2.0
Use Windows 10 Pro/Enterprise's Powershell ISE env, or Visual Studop Code with Powershell plugin.
#>

#Visual studio code keys:
#ctrl-shift-p : open command terminal
# F8 : Run current selection

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

#Variable , array hashtables
${My Variable}  = 4  #complex names
$myvar = 5
${C:\Windows\Temp\variable.txt} = "New value"  #store on FS
Get-Content C:\Windows\Temp\variable.txt
$i = $j = 0
#commands variables
Clear-Variable i
Get-Variable | Select-Object Name, Description
New-Variable -Name today -Value (Get-Date) -Option Constant
#is same as $today = Get-Date
$psProcesses = Get-Process powershell 
Remove-Variable psProcesses 
$objectCount = 23 
Set-Variable objectCount -Value 42 -Description 'The number of objects in the queue' -Option Private
#scopes
#$local:var or $gobal:var or $private:var 
Remove-Variable thisValue -ErrorAction SilentlyContinue 
# This is still "local" scope 
$private:thisValue = "Some value" 
"From global: $global:thisValue"           # Accessible 
function Test-ThisScope { 
    "Without scope: $thisValue"            # Not accessible
     "From private: $private:thisValue"     # Not accessible 
    "From global: $global:thisValue"       # Not accessible 
} 
Test-ThisScope 
#script scope , share between children but not global
# Script file: example.ps1 
[Version]$Script:Version = "0.1" 
function Get-Version { 
    Write-Host "Version: $Version" 
} 
function Set-Version { 
    param( 
        [Version]$version 
    ) 
    $Script:Version = $version 
} 
Set-Version 0.2 
Write-Host (Get-Version) 
#type and type conversion
[String](Get-Date)
[DateTime]"01/01/2016"
[Int]$thisNumber = 2
[String]$thisString = "some value"
#This type conversion add this attribute to variable
(Get-Variable thisString).Attributes 
$thisString = $null
#This attribute is now still there
#object assignment
$object1 = $object2 = [PSCustomObject]@{ 
    Name = 'First object'
 }
$object1.Name = 'New name'
Write-Host $object2.Name
#NEsted objects:
$complexObject = [PSCustomObject]@{
    OuterNumber = 1
    InnerObject = [PSCustomObject]@{
         InnerNumber = 2
    }
}
$innerObject = $complexObject.InnerObject
$innerObject.InnerNumber = 5
Write-Host $complexObject.InnerObject.InnerNumber
#arrays
$processes = Get-Process 
$myArray = @()  #empty
$myGreetings = "Hello world", "Hello sun", "Hello moon"
$myGreetings = @("Hello world", "Hello sun", "Hello moon")
$myThings = "Hello world", 2, 34.23, (Get-Date)  #different types
$myArray = New-Object Object[] 10        # 10 objects 
$byteArray = New-Object Byte[] 100       # 100 bytes 
$ipAddresses = New-Object IPAddress[] 5  # 5 IP addresses 
[String[]]      # An array of strings 
[UInt64[]]      # An array of unsigned 64-bit integers 
[Xml[]]         # An array of XML documents
[Int32[]]$myNumbers = 1, 2, $null, 3.45  #1,2,0,3
$myArray = @() 
$myArray += "New value"
$myArray = $myArray + "New value" #alternative
$firstArray = 1, 2, 3 
$secondArray = 4, 5, 6 
$mergedArray = $firstArray + $secondArray
#select from array
$myArray = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 
$myArray[0] 
$myArray[1]
$myArray[-1]   #Get last item
$myArray[-2] 
#ranges
$myArray[2..4] 
$myArray[-1..-5]
$myArray[0..2 + 6..8 + -1]  #multiple ranges
#change elements
$myArray = 1, 2, 9, 4, 5 
$myArray[2] = 3
#remove elements
$myArray = 1, 2, 3, 4, 5 
$myArray[1] = $null 
$myArray 
#count
$myArray.Count 
#loop through elements
$myArray | ForEach-Object { Write-Host $_ }
$myArray | Where-Object { $_ } | ForEach-Object { Write-Host $_ } #remove null values
#remove element
$newArray = $oldArray[0..48] + $oldArray[50..99]
#or use copy to remove
$newArray = New-Object Object[] ($oldArray.Count - 1) 
# Before the index 
[Array]::Copy($oldArray,    # Source 
              $newArray,    # Destination 
              49)           # Number of elements to copy 
# After the index 
[Array]::Copy($oldArray,    # Source 
              50,           # Copy from index of Source 
              $newArray,    # Destination 
              49,           # Copy to index of Destination 
              50)           # Number of elements to copy
#for loop to remove
$newArray = for ($i = 0; $i -lt $oldArray.Count; $i++) { 
    if ($i -ne 49) { 
        $oldArray[$i] 
    } 
}
#remove values
$oldArray = 1..100
$newArray = $oldArray | Where-Object { $_ -ne 50 } 
$index = $oldArray.IndexOf(50)
$index = $oldArray.IndexOf(50) 
if ($index -gt -1) { 
    $newArray = $oldArray[0..($index - 1)] +  
        $oldArray[($index + 1)..99] 
} 
#clear array
$newArray = 1, 2, 3, 4, 5 
$newArray.Clear()
#arrays to values
$firstName, $lastName = "First Last" -split " " 
$firstName, $lastName = "First Last".Split(" ")
$i, $j, $k = 1, 2, 3, 4, 5 #k gets 3,4,5
$i, $j, $k = 1, 2  #k is null
#multi array
$arrayOfArrays = @( 
    @(1, 2, 3), 
    @(4, 5, 6), 
    @(7, 8, 9) 
)
$arrayOfArrays[0][1]
#jagged array, different inner sizes
$arrayOfArrays = @( 
    @(1,  2), 
    @(4,  5,  6,  7,  8,  9), 
    @(10, 11, 12) 
)
#hashtables
$hashtable = @{}  #empty
$hashtable = @{Key1 = "Value1"; Key2 = "Value2"}
$hashtable.Add("Key1", "Value1")
$hashtable = @{} 
if (-not $hashtable.Contains("Key1")) { 
    $hashtable.Add("Key1", "Value1") 
} 
#or update
$hashtable = @{ Existing = "Old" } 
$hashtable["New"] = "New"            # Add this 
$hashtable["Existing"] = "Updated"   # Update this
#or update with .
$hashtable = @{ Existing = "Old" } 
$hashtable.New = "New"               # Add this 
$hashtable.Existing = "Updated"      # Update this 
#get keys and values
$hashtable.Keys
$hashtable.Values
#remove
$hashtable.Remove("Existing")
$hashtable = @{one = 1; two = 2; three = 3} 
$hashtable.Clear()
#list , dicts,queues , stacks
$list = New-Object System.Collections.Generic.List[String] 
$arrayList = New-object System.Collections.ArrayList
$list.Add("David")
$list.Insert(0, "Sarah") 
$list.Insert(2, "Jane") 
#select
$list = New-Object System.Collections.Generic.List[String] 
$list.AddRange([String[]]("Tom", "Richard", "Harry")) 
$list[1]    # Returns Richard
$index = $list.FindIndex( { $args[0] -eq 'Richard' } )
$list.IndexOf('Harry', 2)    # Start at index 2 
$list.IndexOf('Richard', 1, 2)    # Start at index 1, and 2 elements
#remove
$list = New-Object System.Collections.Generic.List[String] 
$list.AddRange([String[]]("Tom", "Richard", "Harry", "David")) 
$list.RemoveAt(1)          # By Richard by index 
$list.Remove("Richard")    # By Richard by value
$list.RemoveAll( { $args[0] -eq "David" } )
#change
$list = New-Object System.Collections.Generic.List[Int]
 $list.AddRange([Int[]](1, 2, 2, 4)) 
$list[2] = 3
#dict
$dictionary = New-Object System.Collections.Generic.Dictionary"[String,IPAddress]" 
$dictionary = New-Object "System.Collections.Generic.Dictionary[String,IPAddress]"
$dictionary.Add("Computer1", "192.168.10.222")
if (-not $dictionary.ContainsKey("Computer2")) { 
    $dictionary.Add("Computer2", "192.168.10.13") 
} 
#select
$dictionary["Computer1"]    # Key reference 
$dictionary.Computer1       # Dot-notation
$dictionary.Keys 
$dictionary.Values
foreach ($key in $dictionary.Keys) { 
    Write-Host "Key: $key    Value: $($dictionary[$key])" 
} 
#remove
$dictionary.Remove("Computer1")
#queue fifo
$queue = New-Object System.Collections.Generic.Queue[String]
$queue.ToArray()
$queue.Peek()  #next element without removing it
#add get
$queue.Enqueue("Tom") 
$queue.Enqueue("Richard") 
$queue.Enqueue("Harry") 
$queue.Dequeue()    # This returns Tom.
#stacks lilo
$stack = New-Object System.Collections.Generi
$stack.ToArray()
$stack.Peek() 
$stack.Push("Up the road") 
$stack.Push("Over the gate") 
$stack.Push("Under the bridge") 
$stack.Push("Up the road") 
$stack.Push("Over the gate") 
$stack.Pop()

#Branch and loop
$x = 1
if ($x -eq 1) { 
    $x = 2
}
else {
    $x = 3
}
#stacked
if ($x -eq 1) { 
    $x = 2
}
elseif ($x -eq 2) {
    $x = 3
}
elseif ($x -eq 3) {
    $x = 4
}
switch (1, 2) { 
    1 { Write-Host 'Equals 1'; break } 
    2 { Write-Host 'Equals 2' } 
    default { Write-Host 'No match'}
} 
#wildcard allows ? and *
switch -Wildcard ('cat') {
    'c*'  { Write-Host 'The word begins with c' } 
   '???' { Write-Host 'The word is 3 characters long' } 
   '*t'  { Write-Host 'The word ends with t' } 
} 
#regex allows regular expression comparison
switch -Regex ('cat') {
    '^c'       { Write-Host 'The word begins with c' } 
   '[a-z]{3}' { Write-Host 'The word is 3 characters long' } 
   't$'       { Write-Host 'The word ends with t' } 
} 
#Compare using Script blocks
switch (Get-Date) {
    { $_ -is [DateTime] } { Write-Host 'This is a DateTime type' } 
   { $_.Year -ge 2017 }  { Write-Host 'It is 2017 or later' } 
} 
#loop array
foreach ($process in Get-Process) { 
    Write-Host $process.Name 
}   
#For loop gives more control
$processes = Get-Process 
for ($i = 0; $i -lt $processes.Count; $i++) { 
    Write-Host $processes[$i].Name
 }
 #reverse the list
for ($i = $processes.Count - 1; $i -ge 0; $i--) { 
    Write-Host $processes[$i].Name
 } 
#execute once and continue if expression is still met
do { 
    Write-Host "Waiting for boot" 
    Start-Sleep -Seconds 5 
} until (Test-Connection 'SomeComputer' -Quiet -Count 1) 
#While will first test condition
while (-not (Test-Path $env:TEMP\test.txt -PathType Leaf)) { 
    Start-Sleep -Seconds 10 
} 
#break breaks the loop
for ($i = 0; $i -lt 20; $i += 2) {
    Write-Host $i 
   if ($i -eq 10) {
        break    # Stop this loop 
   } 
} 
#Use continue to continue the loop
for ($i = 0; $i -le 5; $i++) { 
    Write-Host $i 
    if ($i -lt 2) { 
        continue    # Continue to the next iteration 
    } 
    Write-Host "Remainder when $i is divided by 2 is $($i % 2)" 
} 



#.net , powershell is build on .net
#assemblies, classes in dll
[System.AppDomain]::CurrentDomain.GetAssemblies()
#To get info about assembly use 1 of the following
[System.Management.Automation.PowerShell].Assembly
[System.Management.Automation.PSCredential].Assembly 
[System.Management.Automation.PSObject].Assembly
#Namespaces like system.Appdomain, or Appdomain for short are to structure
[Management.Automation.PowerShell].Assembly #eg
#types = Classes
#create new
$stringBuilder = [System.Text.StringBuilder]::new()
$stringBuilder = New-Object System.Text.StringBuilder  #Alternative
#or with parameters:
New-Object System.Text.StringBuilder(10) 
[System.Text.StringBuilder]::new(10)
#lets skip the rest, but this example is nice , to show you can
#do a lot on Windows using its .net
# Load the the Windows Presentation Framework 
using assembly PresentationFramework 
# Use the System.Windows namespace 
using namespace System.Windows 
$window = New-Object Window 
$window.Height = 100 
$window.Width = 150 
# Create a System.Windows.Controls.Button object 
$button = New-Object Controls.Button 
$button.Content = 'Close' 
$button.Add_Click( { $window.Close() } ) 
$window.Content = $button 
$window.ShowDialog()


#data parsing and manipulation
#string = array
$myString = 'abcdefghijklmnopqrstuvwxyz' 
$myString[0]     # This is a (the first character in the string) 
$myString[-1]    # This is z (the last character in the string)
#Soem string methods can be executed on array
('azzz', 'bzzz', 'czzz').Trim('z') 
('a,b', 'c,d').Split(',') 
#common methods
$myString = 'abcdefghijklmnopqrstuvwxyz' 
$myString.Substring(3, 4) # Start at index 3, get 4 characters. 
$string = 'Surname,,GivenName' 
$array = $string.Split(',') 
$array.Count    # This is 3 
$array[1]       # This is empty 
$string = 'Surname,,GivenName' 
$array = $string.Split(',', [StringSplitOptions]::RemoveEmptyEntries) 
$array.Count    # This is 2
#Fill different vars from the string
$surname, $givenName = $string.Split(',', [StringSplitOptions]::RemoveEmptyEntries)
#create array of 1 char strings
[char[]]$characters = [string[]]('a', 'b', 'c') 
[char[]]$characters = 'abc'
#replace
$string = 'This is the first example' 
$string.Replace('first', 'second')
$string = 'Begin the begin.' 
$string -replace 'begin.', 'story, please.' 
$string.Replace('begin.', 'story, please.') 
#trim
$string = " 
    This string has leading and trailing white space      " 
$string.Trim()
$string = '*__This string is surrounded by clutter.--#' 
$string.Trim('*_-#')
$string = 'magnet.uk.net' 
$string.TrimEnd('.uk.net')
#insert / remove
$string = 'The letter of the alphabet is a' 
$string.Insert(4, 'first ')  # Insert this before "letter", include a trailing space
$string = 'This is is an example' 
$string.Remove(4, 3)
#indexof 
$string = 'abcdefedcba' 
$string.IndexOf('b')     # Returns 1 
$string.LastIndexOf('b') # Returns 9 
$string.IndexOf('ed')    # Returns 6
$string  = 'abcdef' 
if ($string.IndexOf('a') -gt -1) {
     'The string contains an a' 
}
#padleft, padright
('one', 'two', 'three').PadRight(10, '.')
('one', 'two', 'three').PadLeft(10, '.')
#toupper, tolower
'aBc'.ToUpper()    # Returns ABC 
'AbC'.ToLower()    # Returns abc 
#Contains , startwith , endswith
$string = 'I am the subject' 
$string.Contains('the')    # Returns $true
$string = 'abc' 
$string.StartsWith('ab') 
$string.EndsWith('bc') 
#chaining
'    ONe*?   '.Trim().TrimEnd('?*').ToLower().Replace('o', 'O') 
#convert
Get-Process -Id $pid | Select-Object Name, Id, Path | ConvertTo-Csv
'David,0123456789,28,"1 Some street, 
A Lane"' | ConvertFrom-Csv -Header Name, Phone, Age, Address | 
Format-Table -Wrap 
'Name,Age', 'David,28' | ConvertFrom-Csv 
Get-Process -Id $pid | Select-Object Name, Id, Path | Export-Csv 'somefile.csv' 
Import-Csv somefile.csv
'Michael Caine', 'Benny Hill', 'Raf Vallone' | Convert-String -Example 'First Second=FSecond' 
'Michael Caine', 'Benny Hill', 'Raf Vallone' | Convert-String -Example @{ 
    Before = 'First Second' 
    After = 'FSecond' 
} 
'"bob",tim,geoff' | ConvertFrom-String -Delimiter ',' -PropertyNames name1, name2, name3
$template = '{Task*:{ImageName:System Idle Process} {[Int]PID:0} {SessionName:Services} {Session:0} {Memory:24 K}}' 
tasklist |  
    Select-Object -Skip 3 | 
    ConvertFrom-String -TemplateContent $template | 
    Select-Object -ExpandProperty Task 
#Number manipulation
'{0:F} TB available' -f (123156235234522 / 1TB) 
22.5GB
2e2    # Returns 200 (2 * 102) 
2e-1   # Returns 0.2 (2 * 10-1) 
0x5eb4  #hex
#Math
[Math]::Round(2.123456789, 2) 
[Math]::Ceiling(2.1234)    # Returns 3 
[Math]::Floor(2.9876)      # Returns 2 
[Math]::Abs(-45748) 
[Math]::Pow(2, 8) # Returns 256 (28) 
[Math]::Sqrt(9)    # Returns 3 
[Math]::pi    # π, 3.14159265358979 
[Math]::e     # e, 2.71828182845905 
#Strings to numbers
[Int]"2"             # String to Int32 
[Decimal]"3.141"     # String to Decimal 
[UInt32]10           # Int32 to UInt32 
[SByte]-5            # Int32 to SByte 
[Convert]::ToInt32('01000111110101', 2)  # Returns 4597 from binary
[Convert]::ToInt32('FF9241', 16)  # Returns 16749121  from hex
#date time
$string = "11/10/2000"    # 11th October 2000 
[DateTime]$string         # 10th November 2000
#This might not work
function Test-DateTime { 
    param( 
        [DateTime]$Date 
    ) 
    $Date 
} 
Test-DateTime -Date "11/10/2000" 
#to fix
Test-DateTime -Date (Get-Date "11/10/2000") 
#parse date using parseexact 
$string = '20170102-2030'  # Represents 1st February 2017, 20:30 
[DateTime]::ParseExact($string, 'yyyyddMM-HHmm', (Get-Culture)) 
#change date
(Get-Date) + (New-Timespan -Hours 6) 
(Get-Date).Date
(Get-Date).AddDays(1) # One day from now 
(Get-Date).AddDays(-1) # One day before now
(Get-Date).AddTicks(1) 
(Get-Date).AddMilliseconds(1) 
(Get-Date).AddSeconds(1) 
(Get-Date).AddMinutes(1) 
(Get-Date).AddHours(1) 
(Get-Date).AddMonths(1) 
(Get-Date).AddYears(1)
#utc
(Get-Date).ToUniversalTime()
$UtcDate = New-Object DateTime ((Get-Date).Ticks, 'Utc')
#date to string
Get-Date -Format 'dd/MM/yyyy HH:mm' 
(Get-Date).ToString('dd/MM/yyyy HH:mm') 
#icw chaining
(Get-Date).ToUniversalTime().Date.AddDays(-7).ToString('dd/MM/yyyy HH:mm')
#to store use unamigious formnat like universal
(Get-Date).ToUniversalTime().ToString('u')
#compare dates
$date1 = (Get-Date).AddDays(-20) 
$date2 = (Get-Date).AddDays(1) 
$date2 -gt $date1 
(Get-Date "13/01/2017") -gt "12/01/2017"  #wrong (us UK format)
(Get-Date "13/01/2017") -gt "01/12/2017" #correct

#regular expressions
#basic
#litercal
'a' -match 'a'
#any single
'a' -match '.'
#zero or more
'abc' -match 'a*'
'abc' -match '.*'
# 1 or more
'abc' -match 'a+'
'abc' -match '.+'
#escape special meaning
'*' -match '\*'
'\' -match '\\'
'Domain\User' -replace '.+\\'  # Everything up to and including \ 
#optional
'abc' -match 'ab?c'
'ac' -match 'ab?c'  #b not required
#fixed nr chars
'abbbc' -match 'ab{3}c'
#range of nr chars
'abc' -match 'ab{1,3}c'
'abbc' -match 'ab{1,3}c'
'abbbc' -match 'ab{1,3}c'
#min nr of chars
'abbc' -match 'ab{2,}c'
'abbbbbc' -match 'ab{2,}c'
#anchors
#begin or end of string
'aba' -match '^a'  
'cbc' -match 'c$'
$env:PATH -split ';' | Where-Object { $_ -match '^C' }
#word boundary
'Band and Land' -match '\band\b'
#character class , 1 of the mentioned charaters
'get' -match 'g[aeiou]t' #true
'one-two_three,four' -split '[-_,]'
#negated class
'Ba%by8 a12315tthe1231 k#.,154eyboard' -replace '[^a-z ]'
#shorthands class : \d [0-9] \s [\t\r\n\f] \w [A-Za-z0-9_]
#ranges
'23rd place' -match '[0-9]+'   # $matches[0] is "23"
'The registry value is 0xAF9B7' -match '0x[0-9a-f]+'; $matches[0]
(ipconfig) -match 'IPv4 Address.+: *[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
#alternation (or )
'one', 'two', 'three' | Where-Object { $_ -match 'one|three' }
'one', 'one hundred', 'three', 'eighty three' |
Where-Object { $_ -match '^one|three$' }
#restricting alternation
Get-ChildItem -Recurse -File |  
    Where-Object { $_.Name -match '(pwd|pass(word|wd)?).*\.(txt|doc)$' }  
#case sensitive match
'The registry value is 0xAF9B7' -cmatch '0x[0-9a-fA-F]+'
#repeated groups
([0-9]+\.){3}[0-9]+
'v1', 'Ver 1.000.232.14', 'Version: 0.92', 'Version-7.92.1-alpha' |
    Where-Object { $_ -match '[0-9]+(\.[0-9]+)*' } | 
    ForEach-Object { $matches[0] }
#debug regex
https://www.debuggex.com/
#to show th resulting match:
"michel matches" -match "michel" ; $matches
'aaabc' -match 'a+'# Returns true, matches 'aaa' 
#quantifiers
'C:\long\path\to\some\files' -match '.*\\'; $matches[0]
#example too greedy quantifier
#should be like this
$html = '<table><tr><td>Value1</td><td>Value2</td></tr></table>'
$html -match '<td>[^>]+</td>'; $matches[0] 
#capturing values
'first second third' -match '(first) (second) (third)'; $matches
#capturing groups, and create object from result
'first second third' -match '(?<One>first) (?<Two>second) (?<Three>third)'; $matches
if ('first second third' -match '(first) (second) (third)') { 
    [PSCustomObject]@{ 
        One   = $matches[1] 
        Two   = $matches[2] 
        Three = $matches[3] 
    } 
} 
#alternative remove 0 match (whole string) first
if ('first second third' -match '(?<One>first) (?<Two>second) (?<Three>third)') {
    $matches.Remove(0)
    [PSCustomObject]$matches
}
#non capture group:
'first second third' -match '(?<One>first) (?<Two>second) (?:third)'; $matches
#examples
#mac address
$patterns = '^([0-9a-f]{2}[-:]){5}[0-9a-f]{2}$', 
            '^(([0-9a-f]{2}[-:]?){2}[-:.]){2}([0-9a-f]{2}[-:]?){2}$', 
            '^([0-9a-f]{2}[-:]){5}[0-9a-f]{2}|([0-9a-f]{4}\.){2}[0-9a-f]{4}$' 
$strings = '1a-2b-3c-4d-5f-6d', 
           '1a:2b:3c:4d:5f:6d', 
           '1c2b.3c4d.5f6d' 
foreach ($pattern in $patterns) { 
    Write-Host "Testing pattern: $pattern" -ForegroundColor Cyan 
    foreach ($string in $strings) { 
        if ($string -match $pattern) { 
            Write-Host "${string}: Matches" -ForegroundColor Green 
        } else { 
            Write-Host "${string}: Failed" -ForegroundColor Red 
        } 
    } 
}
#netstat
$regex = '^\s*(?<Protocol>\S+)\s+(?<LocalAddress>\S+)\s+(?<ForeignAddress>\S+)\s+(?<State>\S+)\s+(?<PID>\d+)$'
netstat -ano | Where-Object { $_ -match $regex } | ForEach-Object {
    $matches.Remove(0)
    [PSCustomObject]$matches
} | Select-Object Protocol, LocalAddress, ForeignAddress, State, PID |
    Format-Table


#files and folders
$PWD  #current dir
#cd alias of Set-Location
cd .. ; $PWD ; 
cd git ; $PWD
ls  #or dir or Get-Item
ls -force  #use force if hidden dirs exists
#create network drive
New-PSDrive X -PSProvider FileSystem -Root \\Server\Share 
New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
#items
#test id dir or file exists
Test-Path HKLM:\Software\Publisher
Test-Path C:\Windows -PathType Container 
Test-Path C:\Windows\System32\cmd.exe -PathType Leaf
#create dir or file
New-Item $env:Temp\newfile.txt -ItemType File 
New-Item $env:Temp\newdirectory -ItemType Directory 
New-Item HKLM:\Software\NewKey -ItemType Key
#remove
$file = [System.IO.Path]::GetTempFileName()
Set-Content -Path $file -Value 'Temporary: 10' 
Remove-Item $file
#invoke / open dir or file
Invoke-Item .   # Open the current directory in explorer 
Invoke-Item test.ps1   # Open test.ps1 in the default editor 
Invoke-Item $env:windir\system32\cmd.exe    # Open cmd 
Invoke-Item Cert:# Open the certificate store MMC for the current user
#properties
(Get-Item 'somefile.txt').IsReadOnly = $true #or chilitem
#Enumeration for file properties
[System.IO.FileAttributes]3 #readonly, hidden
[System.IO.FileAttributes]'ReadOnly, Hidden' -eq 3
#Set properties
(Get-Item 'somefile.txt').Attributes = 'ReadOnly, Hidden'
#or toggle
$file = Get-Item 'somefile.txt' 
$file.Attributes = $file.Attributes -bxor 'ReadOnly'
#or add
$file = Get-Item 'somefile.txt' 
$file.Attributes = $file.Attributes -bor 'ReadOnly'
#or use + , - as this is numeric
$file = Get-Item 'somefile.txt'
$file.Attributes = 'ReadOnly'
$file.Attributes += 'ReadOnly'
$file.Attributes
#registry
Get-ItemProperty -Path HKCU:\Environment 
Get-ItemProperty -Path HKCU:\Environment -Name Path 
Get-ItemProperty -Path HKCU:\Environment -Name Path, Temp
Set-ItemProperty -Path HKCU:\Environment -Name NewValue -Value 'New' 
Remove-ItemProperty -Path HKCU:\Environment -Name NewValue 
#permissions
#first create some crap
New-Item C:\Temp\ACL -ItemType Directory -Force
1..5 | ForEach-Object {
New-Item C:\Temp\ACL\$_ -ItemType Directory -Force
'content' | Out-File "C:\Temp\ACL\$_\$_.txt"
New-Item C:\Temp\ACL\$_\$_ -ItemType Directory -Force
'content' | Out-File "C:\Temp\ACL\$_\$_\$_.txt"
}
#read permissions
Get-Acl C:\Temp\ACL\1 | Select-Object Owner
Get-Acl C:\Temp\ACL\1 -Audit | Format-List 
$acl = Get-Acl C:\Temp\ACL\3
$acl.Access | Select-Object IdentityReference, FileSystemRights, IsInherited

#write
$acl = Get-Acl C:\Temp\ACL\1
$acl.SetOwner(
[System.Security.Principal.NTAccount]'Administrator'
)
Set-Acl C:\Temp\ACL\1 -AclObject $acl
#rule protection (no inheritance)
$acl = Get-Acl C:\Temp\ACL\2 
$acl.SetAccessRuleProtection($true, $true) 
Set-Acl C:\Temp\ACL\2 -AclObject $acl  
#reenable
$acl = Get-Acl C:\Temp\ACL\2 
$acl.SetAccessRuleProtection($false, $false) 
Set-Acl C:\Temp\ACL\2 -AclObject $acl
#remove any rules
$acl = Get-Acl C:\Temp\ACL\3     
$acl.Access | 
Where-Object { -not $_.IsInherited } | 
    ForEach-Object{ $acl.RemoveAccessRuleSpecific($_) } 
Set-Acl C:\Temp\ACL\3 -AclObject $acl
#copy lists acl
#template creation 
$acl = Get-Acl C:\Temp\ACL\4 
$acl.SetAccessRuleProtection($true, $true)
$acl.Access |
Where-Object IdentityReference -like '*\Authenticated Users' |
ForEach-Object { $acl.RemoveAccessRule($_) }
Set-Acl C:\Temp\ACL\4 –AclObject $acl
#$copy template on top of new obj
$acl = Get-Acl C:\Temp\ACL\4 
Set-Acl C:\Temp\ACL\5 -AclObject $acl 
#transactions (group of file changes)
#create
Start-Transaction 
$path = 'HKCU:\TestTransaction' 
New-Item $path -ItemType Key -UseTransaction 
Set-ItemProperty $path -Name 'Name' -Value 'Transaction' -UseTransaction 
Set-ItemProperty $path -Name 'Length' -Value 20 -UseTransaction 
#finish or undo
Undo-Transaction
Complete-Transaction
#check other transaction commands
Get-Command -ParameterName UseTransaction
#file catalog , check integrity of file
#create
New-FileCatalog -Path C:\Temp\ACL -CatalogFilePath C:\Temp\Security\example.cat
Set-Content C:\Temp\ACL\3\3.txt –Value 'New content'
#Test if some change has been done
Test-FileCatalog -Path C:\Temp\ACL -CatalogFilePath C:\Temp\Security\example.cat
#what file in acl dir was added
$result = Test-FileCatalog -Path C:\Temp\ACL -CatalogFilePath C:\Temp\Security\example.cat -Detailed
$result.PathItems.Keys | Where-Object { 
    -not $result.CatalogItems.ContainsKey($_) }
#what files were removed
$result.CatalogItems.Keys | Where-Object {  
    -not $result.PathItems.ContainsKey($_) }
#what files are modified / changed
$result.PathItems.Keys | Where-Object { 
    $result.CatalogItems[$_] -ne $result.PathItems[$_]}

#Html, xml and json
#lets skip this

#rest and soap , lets skip

#remote management skipping

#Testing , yes lets do this
#static analyse, dont execute block 
#command static test
{ Write-Host 'content' }.Ast
#Function static test
function Write-Content { Write-Host 'content' } 
(Get-Command Write-Content).ScriptBlock
#Or 
function Write-Content { Write-Host 'content' } 
(Get-Item function:\Write-Content).ScriptBlock
#proces output of test literally
{ Write-Host 'content' }.Ast. 
                         Endblock. 
                         Statements. 
                         PipelineElements. 
                         CommandElements[1]
#Or search output Ast
{ Write-Host 'content' }.Ast.FindAll( { 
    param ( $ast ) 

    $ast -is [Management.Automation.Language.CommandAst] -and  
$ast.GetCommandName() -eq 'Write-Host' 
}, 
$true 
)
#PSScriptAnalyzer (static ast evaluation)
Install-Module PSScriptAnalyzer #admin
#First create example code to test
[CmdletBinding()] 
param ( 
    [Parameter(Mandatory = $true)] 
    [String]$Password 
) 
 
$Credential = New-Object PSCredential( 
    '.\user',  
    $Password | ConvertTo-SecureString -AsPlainText -Force 
) 
$Credential.GetNetworkCredential().Password
#Now invoke test
Invoke-ScriptAnalyzer $psISE.CurrentFile.FullPath | Format-List
#Some other code to tes
function New-Message { 
    [CmdletBinding()] 
    param ( 
        $Message 
    ) 
 
    [PSCustomObject]@{ 
        Name  = 1 
        Value = $Message 
    } 
} 
#invoke test
Invoke-ScriptAnalyzer $psISE.CurrentFile.FullPath | Format-List
#Supress the error it gives by changing code
function New-Message { 
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '')] 
    [CmdletBinding()] 
    param ( 
        $Message 
    ) 
 
    [PSCustomObject]@{ 
        Name  = 1 
        Value = $Message 
    } 
} 
#unit testing , when code will execute
#eg using Test Driven development
#Pester for unit test: Debug and Refactor
Install-Module Pester -Force
#Create file: .tests.ps1
Invoke-Pester .Invoke-Pester
#what to test:
#complex condition, input complex parameters
#Exit condition errors, focus on 1 unit
#not the function it calls.
#Describe group of tests, declare it
#example code:
function Get-SquareRoot { 
    param ( 
        [Decimal]$Value 
    ) 
 
    if ($Value -lt 0) { throw 'Invalid value' } 
 
    $result = $Value 
    $previous = 0 
    while ([Math]::Abs($result - $previous) -gt 1e-300) { 
        $previous = $result 
        $result = ($result + $Value / $previous) / 2 
    } 
    return $result 
} 
Get-SquareRoot 4
#describe tests:
Describe Get-SquareRoot { 
    It 'Returns a square root of 0 for a value of 0' { 
        Get-SquareRoot 0 | Should -Be 0 
    } 

    It 'Returns simple square root values' { 
        Get-Squareroot 1 | Should -Be 1 
        Get-SquareRoot 4 | Should -Be 2 
        Get-SquareRoot 9 | Should -Be 3 
        Get-SquareRoot 16 | Should -Be 4 
    } 
} 
Describing Get-SquareRoot
#test cases, repeating tests:
$testCases = @( 
    @{ Value = 1;  ExpectedResult = 1 } 
    @{ Value = 4;  ExpectedResult = 2 } 
    @{ Value = 9;  ExpectedResult = 33 } 
    @{ Value = 16; ExpectedResult = 44 } 
) 
 
It 'Calculates the square root of <Value>to be<ExpectedResult>' -TestCases $testCases { 
    param ( 
        $Value, 
        $ExpectedResult 
    ) 
 
    Get-SquareRoot $Value | Should -Be $ExpectedResult 
} 
#Or even use independent verification
$values = 81, 9801, 60025, 3686400, 212255761, 475316482624 
$testCases = foreach ($value in $values) { 
    @{ Value = $value; ExpectedResult = [Math]::Sqrt($value) } 
} 
It 'Calculates the square root of <Value> to be <ExpectedResult>' -TestCases $testCases { 
    param ( 
        $Value, 
        $ExpectedResult 
    ) 
    Get-SquareRoot $Value | Should -Be $ExpectedResult 
} 
#Test: 
Describing Get-SquareRoot
#Assertion:
#be
0 | Should -Be 0 
$true | Should -Be $true 
@(1, 2, 3) | Should -Be @(1, 2, 3) 
#bein
'Harry' | Should -BeIn 'Tom', 'Richard', 'Harry' 
#belessthan
1 | Should -BeLessThan 20 
#belike
'Value' | Should -BeLike 'v*' 
#belikeexactly
'Value' | Should -BeLikeExactly 'V*' 
#benullorempty
@() | Should -BeNullOrEmpty 
'' | Should -BeNullOrEmpty 
#beoftype
[IPAddress]"1.2.3.4" | Should -BeOfType [IPAddress] 
#filecontentmatch sing contain
'hello world' | Out-File 'file.txt' 
'file.txt' | Should -Contain 'World' 
#filecontentmatchexacgtly
'hello world' | Out-File 'file.txt' 
'file.txt' | Should -FileContentMatchExactly 'world' 
#filecontentmatchmultiline
Set-Content file.txt -Value "1`n2`n3`n4" 
'file.txt' | Should -FileContentMatchMultiline "2`n3" 
#exists
'c:\Windows' | Should -Exist 
#match reg expression , case insensitive
'value' | Should Match '^V.+e$' 
#matchexactly , case sensitve
'value' | Should Match '^v.+e$' 
#Throw , does it throw error
function Invoke-Something { throw } 
Describe Invoke-Something { 
    It 'Throws a terminating error' { 
{ Invoke-Something } | Should Throw 
    } 
} 
#test error message
function Invoke-Something { throw 'an error' } 
Describe Invoke-Something { 
    It 'Throws a terminating error' { 
{ Invoke-Something } | Should Throw 'an error' 
    } 
}
#not , negate previous term
function Invoke-Something { return 1} 
Invoke-Something | Should -Not -Be 0 
Invoke-Something | Should -Not -BeNullOrEmpty
#Context , group tests within describe
#before and after, when to execute test code 
#eg function to test:
function Remove-StaleFile { 
    param ( 
        [Parameter(Mandatory = $true)] 
        [String]$Path, 
        [String]$Filter = '*.*', 
        [Int32]$MaximumAge = 90 
    ) 
 
    Get-ChildItem $Path -Filter $Filter | 
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-$MaximumAge) | 
        Remove-Item 
} 
#before all
BeforeAll { 
    $extensions = '.txt', '.log', '.doc' 
    $Path = 'C:\Temp\StaleFiles' 
    $null = New-Item $Path -ItemType Directory 
    Push-Location $Path 
} 
#after all
AfterAll { 
    Pop-Location 
    Remove-Item C:\Temp\StaleFiles -Recurse -Force 
} 
#before each
BeforeEach { 
    foreach ($extension in $extensions) { 
        $item = New-Item "stale$extension" -ItemType File -Force 
        $item.LastWriteTime = (Get-Date).AddDays(-92) 
} 
foreach ($extension in $extensions) { 
$item = New-Item "new$extension" -ItemType File -Force 
$item.LastWriteTime = (Get-Date).AddDays(-88) 
} 
} 
#test itself is now simpler:
It 'Removes all files older than 90 days' { 
    Remove-StaleFile $Path 
    Test-Path "stale.*" | Should -Be $false 
    Get-ChildItem "new.*" | Should -Not -BeNullOrEmpty 
} 

$testCases = $extensions | ForEach-Object { @{ Extension = $_ } } 
It 'Removes all <Extension> files older than 90 days' -TestCases $testCases { 
    param ( $Extension ) 

    Remove-StaleFile $Path -Filter "*$Extension" 
    Test-Path "stale$Extension" | Should -Be $false 
    Get-ChildItem "stale.*" | Should -Not -BeNullOrEmpty 
    Get-ChildItem "new.*" | Should -Not -BeNullOrEmpty 
} 
#testdrive , if doing filesystem tests
(Get-Item 'TestDrive:\').FullName 
#mock , override command
Mock Get-Date { 
    '01/01/2017' 
    } 
#Assert MockCalled
#eg function
function Get-OperatingSystemName{ 
    (Get-CimInstance Win32_OperatingSystem).Caption 
} 
#create test with mock:
Describe Get-OperatingSystemName { 
    Mock Get-CimInstance { 
        [PSCustomObject]@{ 
            Caption = 'OSName' 
        } 
    } 
    It 'Gets the name of the operating system' { 
        Get-OperatingSystemName | Should -Be 'OSName' 
        Assert-MockCalled Get-CimInstance 
    } 
} 
#or check how many times the test was called
Assert-MockCalled Get-CimInstance -Times 0 
Assert-MockCalled Get-CimInstance -Times 1 -Exactly
#filer parameters mock to limit scope
Describe TestPathMocking { 
    Mock Test-Path { $false } -ParameterFilter { $Path -eq 'C:\' } 
 
    It 'Uses the mock' { 
        Test-Path 'C:\' | Should -Be $false 
    } 
 
    It 'Uses the real command' { 
        Test-Path 'C:\Windows' | Should -Be $true 
    } 
} 
#mock objects
#eg object
[PSCustomObject]@{ 
    Property = "Value" 
} 
[PSCustomObject]@{} | Add-Member MethodName -MemberType ScriptMethod -Value { } 
#use this approach in Mock:
Mock New-Object { } -ParameterFilter { $TypeName -eq 'System.IO.FileStream' } 
Mock New-Object { 
    [PSCustomObject]@{} | 
        Add-Member WriteLine -MemberType ScriptMethod -Value { } -PassThru | 
        Add-Member Close -MemberType ScriptMethod -Value { } -PassThru 
} -ParameterFilter { $TypeName -eq 'System.IO.StreamWriter' } 
#mock methods
$sqlConnection = New-Object System.Data.SqlClient.SqlConnection 
$sqlConnection | Add-Member State -MemberType NoteProperty -Force -Value 'Closed' 
$sqlConnection | Add-Member Open -MemberType ScriptMethod -Force -Value { 
    $this.State = 'Open' 
} 
#Ignoring CIM objects

#ERROR HANDLING




#Get-ADUser -Filter { sAMAccountName -eq "SomeName" }
#Get-Service -Filter { Status -eq 'Stopped' }

Get-ChildItem -Recurse:$true  #This is a switch argument
ls -Recurse:$true | grep sprint