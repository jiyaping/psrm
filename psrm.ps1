# Author        : jiyaping0802@gmail.com
# Date          : 2015-7-27
# Description   : quick script to get all kinds of server infomation include memory,
#                 CPU, disk usage, import event log etc. 

# init some important global variables
$global:execute_path = split-path -parent $MyInvocation.MyCommand.Definition

function Get-JReport
{
    <#
    .SYNOPSIS
        generate report for servers
    .EXAMPLE
        Get-JReport -session $session -lastBytes 300000 -url
    #>
    param($ip, $username, $session, $destfile)

    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }
    $timestamp = (get-date -uformat "%Y%m%d%H%M%S")

    $lineWidth = 45
    $sectionSep = "-"
    $serverSep = "="
    $commentSep = "*"

    #begin 
    Write-Host ($serverSep * $lineWidth * 1.2)
    # report header 
    Write-Host ($commentSep * $lineWidth)
    Write-Host "POWERSHELL GENERATED SERVER STATUS REPORT"
    Write-Host 
    Write-Host "TIME:", $timestamp
    Write-Host "POWERED BY jiyaping"
    Write-Host ($commentSep * $lineWidth)

    Write-Host
    Write-Host

    # print cpu
    Write-Host ($sectionSep * $lineWidth)
    Write-Host "SECTION : CPU"
    Write-Host ($sectionSep * $lineWidth)
    try {
        Get-JCPU -session $session
    } catch{
        Write-Host "GET CPU INFO ERROR."
    }
    Write-Host

    # print memory
    Write-Host ($sectionSep * $lineWidth)
    Write-Host "SECTION : Memory"
    Write-Host ($sectionSep * $lineWidth)
    try {
        Get-JMemory -session $session
    } catch{
        Write-Host "GET Memory INFO ERROR."
    }
    Write-Host

    # print disk
    Write-Host ($sectionSep * $lineWidth)
    Write-Host "SECTION : Disk"
    Write-Host ($sectionSep * $lineWidth)
    try {
        Get-JDiskUsage -session $session
    } catch{
        Write-Host "GET DISK INFO ERROR."
    }
    Write-Host

    # print network 
    Write-Host ($sectionSep * $lineWidth)
    Write-Host "SECTION : NetWork(default port : 80)"
    Write-Host ($sectionSep * $lineWidth)
    try {
        Get-JNetConnectionAnalysis -session $session
    } catch{
        Write-Host "GET  INFO ERROR."
    }
    Write-Host

    # print top visit
    Write-Host ($sectionSep * $lineWidth)
    Write-Host "SECTION : Request ANALYSIS (Lastest 512*1024)"
    Write-Host ($sectionSep * $lineWidth)
    try {
        Get-JLastestVisitAnalysis -session $session -lastBytes (512*1024)
    } catch{
        Write-Host "GET VISIT INFO ERROR."
    }
    Write-Host

    # end
    Write-Host ($serverSep * $lineWidth * 1.2)
}   

function Get-JLastestVisitAnalysis
{
    <#
    .SYNOPSIS
        analysis top visited user through log file
    .DESCRIPTION
        Firstly, get content from startPostion to end in iis log file, and then, parse log file to 
        get top visited user, set path switcher on will show top visited url 
    .EXAMPLE
        Get-JLastestVisitAnalysis -session $session -lastBytes 300000 -url
    .EXAMPLE
        Get-JLastestVisitAnalysis -ip $ip -username $username -lastBytes 300000 -url
    #>

    param($ip, $username, $session, $lastBytes, [switch]$url)

    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }

    $result = @{}
    $lineNumCounter = 0
    $receiveArr = (Get-JLastestVisit -session $session -lastBytes $lastBytes | ? {
        $_ -match "^\d{4}-\d{2}-\d{2}"
    })

    # throw first line
    $startTime = $receiveArr[1].split(" ")[1]
    $endTime = $receiveArr[$receiveArr.length - 1].split(" ")[1]
    $seconds = (new-timespan -start $startTime -end $endTime).seconds

    $receiveArr | % {
        if($_ -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        {
            $clientIP = $matches[3]
            $path = $matches[2].subString($matches[2].lastIndexOf("/")).split(" ")[0]
        }

        if(-not $url)
        {
            $result[$clientIP] += 1
        }
        else
        {
            $result[$path] += 1
        }
    }

    # output summary
    New-SplitLine
    Write-Host "ALL Request:", $receiveArr.length
    Write-Host "Request Total Time:", $seconds, "sec"
    $reqPerSec = [math]::round($receiveArr.length / $seconds, 2)
    Write-Host "Request per sec:", $reqPerSec
    New-SplitLine

    $result.GetEnumerator() | % {
        $new_value = [math]::round(($_.Value/$seconds), 2)
        Write-Host $_.Name, $new_value
    }

    New-SplitLine
}

function Get-JNetConnectionAnalysis
{
    <#
    .SYNOPSIS
        Get Net Connection analysis
    .EXAMPLE
        Get-JNetConnectionAnalysis -session $session -port 80
    .EXAMPLE
        Get-JNetConnectionAnalysis -ip $ip -username $username -port 80
    #>

    param($ip, $username, $session, $port)

    if(-not $port) { $port = 80 }
    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }

    $result = @{}
    Get-JNetConnection -session $session -port $port | % {
        if($_ -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        {
            $result[$matches[3]] += 1
        }
    }

    $result.GetEnumerator() | sort-object value -descending
}

function Get-JGCPUMemory
{
    <#
    .SYNOPSIS
        Get group server CPU and memory
    .EXAMPLE
        Get-JGCPUMemory -group groupname
    #>

    param($group, [switch]$cpu, [switch]$memory)
    
    if( -not $groups[$group]) { throw "Do not config group($group) in config.ps1" }

    $groups[$group].split(",") | ? { $_.length -gt 0 } | % {
        $ip, $uname = $_, $servers[$_]["uname"]
        $session = Get-JServerConnection -ip $ip -username $uname
        
        New-SplitLine -title "$uname@$ip"
        if($cpu)
        {
            Get-JCPU -session $session
        }

        if($memory)
        {
            Get-JMemory -session $session
        }
        New-SplitLine
    }
}

function Get-JGDiskUsage
{
    <#
    .SYNOPSIS
        Get group server disk usage base on function Get-JDiskUsage
    .EXAMPLE
        Get-JGDiskUsage -group groupname
    #>

    param($group)

    if(-not $groups[$group]){ throw "Do not config group($group) in config.ps1" }

    $groups[$group].split(",") | ? { $_.length -gt 0 } | % {
        $ip, $uname = $_, $servers[$_]["uname"]
        New-SplitLine -title "$uname@$ip"
        Get-JDiskUsage -ip $ip -username $uname
        New-SplitLine
    }
}

function Get-JMemory
{
    <#
    .SYNOPSIS
        Get group server disk usage base on function Get-JDiskUsage
    .EXAMPLE
        Get-JGDiskUsage -group groupname
    #>

    param($ip, $username, $session)

    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }
    invoke-command -session $session -scriptblock {
        $result = @{}

        gwmi Win32_OperatingSystem | % {
            $result['TotalVisibleMemorySize'] = $_.TotalVisibleMemorySize
            $result['FreePhysicalMemory'] = $_.FreePhysicalMemory
        }

        $result
    }
}

function Get-JCPU
{
    <#
    .SYNOPSIS
        Get server cpu 
    .EXAMPLE
        Get-JCPU -ip $ip -username $username
    #>

    param($ip, $username, $session)

    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }
    invoke-command -session $session -scriptblock {
        (Get-counter "\Processor(_Total)\% Processor Time").Readings
    } | Fill-PerfomKeyValue
}

function Get-JLastestVisit
{
    <#
    .SYNOPSIS
        Get last remote web server visit anylsis
    .EXAMPLE
        Get-JLastestVisit -ip 192.168.1.1 -username admin -startPostion Byte
    #>

    param($ip, $username, $session, [int64]$startPosition, $lastBytes)

    if(-not $session )
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }

    try { $filepath = $servers[$session.computername]['iislog'] }
    catch { throw "this server do not set iislog path , unsupport this function." }

    invoke-command -session $session -scriptblock {
        param($filepath, $startPosition, $lastBytes)

        # using lastBytes param to cover startPosition

        # get log file name through file template
        $filepath += (ls $filepath | sort-object lastWritetime -descending)[0].Name

        try { $fullpath = Resolve-Path $filepath -ErrorAction Stop }
        catch { throw "Could not resolve path $filepath" }

        if($lastBytes)
        {
            $filesize = (get-item $fullpath).length
            $startPosition = $filesize - $lastBytes
        }
        if($startPosition -lt 0) { $startPosition = 0 }

        try{ $stream = New-Object System.IO.FileStream -ArgumentList $fullPath, 'Open' -ErrorAction Stop}
        catch { throw }

        $streamEnd = $stream.Seek(0, 'End')
        $streamStart = $stream.Seek(0, 'Begin')

        if(($streamStart -le $startPosition) -and ($startPosition -le $streamEnd))
        {
            $reader = New-Object System.IO.StreamReader -ArgumentList $stream, $true

            $reader.BaseStream.Seek(0, 'Begin') | Out-Null
            $reader.Readline() | Out-Null
            $reader.DisCardBufferedData()

            $reader.BaseStream.Seek($startPosition, 'Begin') | Out-Null
            While (-not $reader.EndOfStream)
            {
                $reader.ReadLine()
            }

            $reader.close | Out-Null
        }

        $stream.close | Out-Null

    } -argumentlist $filepath, $startPosition, $lastBytes
}

function Get-JCLR
{
    <#
    .SYNOPSIS
        Get remote server CLR infomation
    .EXAMPLE
        Get-JCLR -ip 192.168.1.1 -username admin
    #>

    param($ip, $username, $session)

    if( -not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }
}

function Get-JKeyEventLog
{
    <#
    .SYNOPSIS
        Get remote server key event infomation
    .EXAMPLE
        Get-JKeyEventLog -ip 192.168.1.1 -username admin -eventid 4378
    #>
}

function Get-JDiskUsage
{
    <#
    .SYNOPSIS
        Get remote server disk usage
    .EXAMPLE
        Get-JDiskUsage -ip 192.168.1.1 -username admin
    #>

    param($ip, $username, $session)

    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }

    invoke-command -session $session -scriptblock {
        $GByte = (1024 * 1024 * 1024)

        Get-WmiObject Win32_LogicalDisk | ? { $_.Size -gt 0 } | % {
            $total = [math]::round(( $_.Size / $GByte ), 2)
            $usage = [math]::round(( $_.FreeSpace / $GByte ), 2)

            Write-Host $_.deviceid, $total, $usage
        }
    }
}

function Get-JNetConnection
{
    <#
    .SYNOPSIS
        Get remote server all network connection with specify port
    .EXAMPLE
        Get-JNetConnection -ip 192.168.1.1 -username admin -port 80
    #>

    param($ip, $username, $session, $port)

    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }
    invoke-command -session $session -scriptblock { 
        param($port)

        if(-not $port) { $port = 80}
        netstat -ano | ? { $_ -match ":$port " }
    } -argumentlist $port
}

function Get-JPS
{
    <#
    .SYNOPSIS
        Get remote ps infomation
    .EXAMPLE
        Get-Jps -ip 192.168.1.1 -username admin
    #>

    param($ip, $username, $processname, $session)

    if(-not $session)
    {
        $session = Get-JServerConnection -ip $ip -username $username
    }
    invoke-command -session $session -scriptblock { get-process $processname}
}

function Remove-JServerConnection
{
    <#
    .SYNOPSIS
        Remove specify session files
    .EXAMPLE
        Remove-JServerConnection -ip 192.168.1.1 -username admin
    #>

    param($ip, $username)

    if( -not (Test-Path "$execute_path\credential\$ip`-$username`.txt"))
    {
        throw "credential file not found, Run New-JServerConnection first"
    }

    Remove-Item -path "$execute_path\credential\$ip`-$username`.txt"
}

function List-JServerConnection
{
    <#
    .SYNOPSIS
        List all credential session files
    .DESCRIPTION
        create a credentail file in local disk
    .EXAMPLE
        List-JServerConnection
    #>

    Get-ChildItem "$execute_path\credential" | % {
        if($_.Name -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\S*).txt")
        {
            Write-Host $matches[1], $matches[2]
        }
    }
}

function New-JServerConnection
{
    <#
    .SYNOPSIS
        Generate connecting session files
    .DESCRIPTION
        create a credentail file in local disk
    .EXAMPLE
        New-JServerConnection -ip 192.168.1.1 -username admin -password test@123
    #>

    param($ip,  $username, $password)

    if(-not (Test-Path "$execute_path\credential")) 
    {
        New-Item -Path "$execute_path\credential" -ItemType "directory"
    }

    $pwd = new-object -typename System.Security.SecureString
    $password.ToCharArray() | % {
        $pwd.AppendChar($_)
    }

    ConvertFrom-SecureString $pwd | Out-File "$execute_path\credential\$ip`-$username`.txt"

    # add the ip to trusted host
    $result = (Get-TrustedHost) | ? { $_.trim() -eq $ip}
    if($result.length -lt 0) { 
        Add-TrustedHost -value $ip 
    }
}

function Get-JServerConnection
{
    <#
    .SYNOPSIS
        Get stored session from local file
    .EXAMPLE
        Get-JServerConnection -ip 192.168.1.1 -username admin
    #>
    param($ip, $username)

    if( -not (Test-Path "$execute_path\credential\$ip`-$username`.txt"))
    {
        throw "credential file not found, Run New-JServerConnection first"
    }

    $pwd = get-content "$execute_path\credential\$ip`-$username`.txt" | convertto-securestring 
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $pwd
    $session = new-pssession -computername $ip -credential $cred

    return $session
}

function Get-TrustedHost
{
    <#
    .SYNOPSIS
        list all trusted hosts
    .EXAMPLE
        Get-TrustedHost
    #>
    (ls WSMan:\localhost\Client\TrustedHosts).Value.split(",")
}

function Add-TrustedHost
{
    <#
    .SYNOPSIS
        add a host to locat client trusted list
    .INPUTS
    .EXAMPLE
        Add-TrustedHost -value 192.168.1.1
    #>
    param($value)

    $hosts = (ls WSMan:\localhost\Client\TrustedHosts).Value  + "," + $value
    set-item WSMan:\localhost\Client\TrustedHosts -force -value $hosts
}

function New-SplitLine
{
    <#
    .SYNOPSIS
        Print a line to split multiple server
    .INPUTS
    .EXAMPLE
        New-SplitLine -length 45 -title "BEGIN"
    #>

    param($length=45, $title='', [switch]$section)

    $sep = "-"
    if($section) { $sep = "=" }

    if($title.length -gt 0){ Write-Host $title }
    Write-Host ($sep * $length)
}

function Fill-PerfomKeyValue
{
    BEGIN { $result = @{} }

    PROCESS {
        $splitedResult = $_.split(":")
        $startPos = $splitedResult[0].lastIndexOf("\")
        if($startPos -le 0){ $startPos = 0 }
        $key = $splitedResult[0].subString($startPos).trim()
        $value = $splitedResult[1].trim()

        $result[$key] = $value
    }

    END { $result }
}

function Get-Test
{
    <#
    .SYNOPSIS
    .DESCRIPTION
    .INPUTS
    .OUTPUTS
    .EXAMPLE
    .LINK
    #>
    Write-Host "ok"
}

. "$execute_path\config.ps1"