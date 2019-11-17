# To get properties of a cmdlets : Get-Service | Get-Member -Membertype property


#Initial Variables
$CurrentDate = $((Get-Date).ToString('yyyy-MM-dd-HH-mm'))
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$DestinationFolder = "$DesktopPath\Traces-$CurrentDate"

#Creating Destination Folder
New-Item -ItemType Directory -Path $DestinationFolder | Out-Null


#Creating Subfolders

    #Services
    $ServicesFolder = "$DestinationFolder\Services"
    New-Item -ItemType Directory -Path $ServicesFolder | Out-Null

    #IP Configuration
    $NetworkFolder = "$DestinationFolder\Network"
    New-Item -ItemType Directory -Path $NetworkFolder | Out-Null

    #Processes
    $ProcessesFolder = "$DestinationFolder\Processes"
    New-Item -ItemType Directory -Path $ProcessesFolder | Out-Null

    #Persistence
    $PersistenceFolder = "$DestinationFolder\Persistence"
    New-Item -ItemType Directory -Path $PersistenceFolder | Out-Null

    #System configuration
    $SystemConfigurationFolder = "$DestinationFolder\SystemConfiguration"
    New-Item -ItemType Directory -Path $SystemConfigurationFolder | Out-Null

########################################################
###                       Functions                  ###
########################################################

#File Hash
$hashtype = "MD5"
function Compute-FileHash {
Param(
    [Parameter(Mandatory = $true, Position=1)]
    [string]$FilePath,
    [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160")]
    [string]$HashType = "MD5"
)
    
    switch ( $HashType.ToUpper() )
    {
        "MD5"       { $hash = [System.Security.Cryptography.MD5]::Create() }
        "SHA1"      { $hash = [System.Security.Cryptography.SHA1]::Create() }
        "SHA256"    { $hash = [System.Security.Cryptography.SHA256]::Create() }
        "SHA384"    { $hash = [System.Security.Cryptography.SHA384]::Create() }
        "SHA512"    { $hash = [System.Security.Cryptography.SHA512]::Create() }
        "RIPEMD160" { $hash = [System.Security.Cryptography.RIPEMD160]::Create() }
        default     { "Invalid hash type selected." }
    }

    if (Test-Path $FilePath) {
        $FileName = Get-ChildItem -Force $FilePath | Select-Object -ExpandProperty Fullname
        $fileData = [System.IO.File]::ReadAllBytes($FileName)
        $HashBytes = $hash.ComputeHash($fileData)
        $PaddedHex = ""

        foreach($Byte in $HashBytes) {
            $ByteInHex = [String]::Format("{0:X}", $Byte)
            $PaddedHex += $ByteInHex.PadLeft(2,"0")
        }
        $PaddedHex
        
    } else {
        "$FilePath is invalid or locked."
        Write-Error -Message "Invalid input file or path specified. $FilePath" -Category InvalidArgument
    }
}
<#
$output = @()
foreach($item in (Get-WmiObject -Query "Select * from win32_process")) {
    if ($item.ExecutablePath) {
        $hash = Compute-FileHash -FilePath $item.ExecutablePath -HashType $hashtype
    } else {
        $hash = "N/A."
    }
    $item | Add-Member -Type NoteProperty -Name "Hash" -Value $hash
    $item.CommandLine = $item.CommandLine -Replace "`n", " " -replace '\s\s*', ' '
	$item | Add-Member -Type NoteProperty -Name "Username" -Value $username
	$item | Add-Member -Type NoteProperty -Name "SID" -Value  $SId
    $output += $item
} $output | Select-Object Hash, Path | Export-csv -Path $ProcessesFolder\ProcHashes.csv -Encoding ascii -NoTypeInformation
#>
#Process Tree
function Get-ProcessTree
{
    [CmdletBinding()]
    param([string]$ComputerName, [int]$IndentSize = 2)
    
    $indentSize   = [Math]::Max(1, [Math]::Min(12, $indentSize))
    $computerName = ($computerName, ".")[[String]::IsNullOrEmpty($computerName)]
    $processes    = Get-WmiObject Win32_Process -ComputerName $computerName
    $pids         = $processes | select -ExpandProperty ProcessId
    $parents      = $processes | select -ExpandProperty ParentProcessId -Unique
    $liveParents  = $parents | ? { $pids -contains $_ }
    $deadParents  = Compare-Object -ReferenceObject $parents -DifferenceObject $liveParents `
                  | select -ExpandProperty InputObject
    $processByParent = $processes | Group-Object -AsHashTable ParentProcessId
    
    function Write-ProcessTree($process, [int]$level = 0)
    {
        $id = $process.ProcessId
        $parentProcessId = $process.ParentProcessId
        $process = Get-Process -Id $id -ComputerName $computerName
        $indent = New-Object String(' ', ($level * $indentSize))
        $process `
        | Add-Member NoteProperty ParentId $parentProcessId -PassThru `
        | Add-Member NoteProperty Level $level -PassThru `
        | Add-Member NoteProperty IndentedName "$indent$($process.Name)" -PassThru 
        $processByParent.Item($id) `
        | ? { $_ } `
        | % { Write-ProcessTree $_ ($level + 1) }
    }

    $processes `
    | ? { $_.ProcessId -ne 0 -and ($_.ProcessId -eq $_.ParentProcessId -or $deadParents -contains $_.ParentProcessId) } `
    | % { Write-ProcessTree $_ }
}
#ARP Table
function Get-ARPTable
{
    if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
        Get-NetNeighbor
    } else {
        $IpPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        foreach ($line in (& $env:windir\system32\arp.exe -a)) {
            $line = $line.Trim()
            if ($line.Length -gt 0) {
                if ($line -match 'Interface:\s(?<Interface>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*') {
                    $Interface = $matches['Interface']
                } elseif ($line -match '(?<IpAddr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?<Mac>[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2})*\s+(?<Type>dynamic|static)') {
                    $IpAddr = $matches['IpAddr']
                    if ($matches['Mac']) {
                        $Mac = $matches['Mac']
                    } else {
                        $Mac = ""
                    }
                    $Type   = $matches['Type']
                    $o = "" | Select-Object Interface, IpAddr, Mac, Type
                    $o.Interface, $o.IpAddr, $o.Mac, $o.Type = $Interface, $IpAddr, $Mac, $Type
                    $o
                }
            }
        }
    }
}
#Network Statistics
function Get-NetworkStatistics {
    <#
    .SYNOPSIS
	    Display current TCP/IP connections for local or remote system
	
    .PARAMETER State
	    Indicates the state of a TCP connection. The possible states are as follows:
		
	    Closed       - The TCP connection is closed. 
	    Close_Wait   - The local endpoint of the TCP connection is waiting for a connection termination request from the local user. 
	    Closing      - The local endpoint of the TCP connection is waiting for an acknowledgement of the connection termination request sent previously. 
	    Delete_Tcb   - The transmission control buffer (TCB) for the TCP connection is being deleted. 
	    Established  - The TCP handshake is complete. The connection has been established and data can be sent. 
	    Fin_Wait_1   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint or for an acknowledgement of the connection termination request sent previously. 
	    Fin_Wait_2   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint. 
	    Last_Ack     - The local endpoint of the TCP connection is waiting for the final acknowledgement of the connection termination request sent previously. 
	    Listen       - The local endpoint of the TCP connection is listening for a connection request from any remote endpoint. 
	    Syn_Received - The local endpoint of the TCP connection has sent and received a connection request and is waiting for an acknowledgment. 
	    Syn_Sent     - The local endpoint of the TCP connection has sent the remote endpoint a segment header with the synchronize (SYN) control bit set and is waiting for a matching connection request. 
	    Time_Wait    - The local endpoint of the TCP connection is waiting for enough time to pass to ensure that the remote endpoint received the acknowledgement of its connection termination request. 
	    Unknown      - The TCP connection state is unknown.

    #>	
	[OutputType('System.Management.Automation.PSObject')]
	[CmdletBinding()]
	param(
		
		[Parameter(Position=0)]
		[System.String]$ProcessName='*',
		
		[Parameter(Position=1)]
		[System.String]$Address='*',		
		
		[Parameter(Position=2)]
		$Port='*',

		[Parameter(Position=3,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [System.String[]]$ComputerName=$env:COMPUTERNAME,

		[ValidateSet('*','tcp','udp')]
		[System.String]$Protocol='*',

		[ValidateSet('*','Closed','Close_Wait','Closing','Delete_Tcb','DeleteTcb','Established','Fin_Wait_1','Fin_Wait_2','Last_Ack','Listening','Syn_Received','Syn_Sent','Time_Wait','Unknown')]
		[System.String]$State='*',

        [switch]$ShowHostnames,
        
        [switch]$ShowProcessNames = $true,	

        [System.String]$TempFile = "C:\netstat.txt",

        [validateset('*','IPv4','IPv6')]
        [string]$AddressFamily = '*'
	)
    
	begin{
        #Define properties
            $properties = 'ComputerName','Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','PID'

        #store hostnames in array for quick lookup
            $dnsCache = @{}
            
	}
	
	process{

        foreach($Computer in $ComputerName) {

            #Collect processes
            if($ShowProcessNames){
                Try {
                    $processes = Get-Process -ComputerName $Computer -ErrorAction stop | select name, id
                }
                Catch {
                    Write-warning "Could not run Get-Process -computername $Computer.  Verify permissions and connectivity.  Defaulting to no ShowProcessNames"
                    $ShowProcessNames = $false
                }
            }
	    
            #Handle remote systems
                if($Computer -ne $env:COMPUTERNAME){

                    #define command
                        [string]$cmd = "cmd /c c:\windows\system32\netstat.exe -ano >> $tempFile"
            
                    #define remote file path - computername, drive, folder path
                        $remoteTempFile = "\\{0}\{1}`${2}" -f "$Computer", (split-path $tempFile -qualifier).TrimEnd(":"), (Split-Path $tempFile -noqualifier)

                    #delete previous results
                        Try{
                            $null = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c del $tempFile" -ComputerName $Computer -ErrorAction stop
                        }
                        Catch{
                            Write-Warning "Could not invoke create win32_process on $Computer to delete $tempfile"
                        }

                    #run command
                        Try{
                            $processID = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $cmd -ComputerName $Computer -ErrorAction stop).processid
                        }
                        Catch{
                            #If we didn't run netstat, break everything off
                            Throw $_
                            Break
                        }

                    #wait for process to complete
                        while (
                            #This while should return true until the process completes
                                $(
                                    try{
                                        get-process -id $processid -computername $Computer -ErrorAction Stop
                                    }
                                    catch{
                                        $FALSE
                                    }
                                )
                        ) {
                            start-sleep -seconds 2 
                        }
            
                    #gather results
                        if(test-path $remoteTempFile){
                    
                            Try {
                                $results = Get-Content $remoteTempFile | Select-String -Pattern '\s+(TCP|UDP)'
                            }
                            Catch {
                                Throw "Could not get content from $remoteTempFile for results"
                                Break
                            }

                            Remove-Item $remoteTempFile -force

                        }
                        else{
                            Throw "'$tempFile' on $Computer converted to '$remoteTempFile'.  This path is not accessible from your system."
                            Break
                        }
                }
                else{
                    #gather results on local PC
                        $results = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)'
                }

            #initialize counter for progress
                $totalCount = $results.count
                $count = 0
    
            #Loop through each line of results    
	            foreach($result in $results) {
            
    	            $item = $result.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)
    
    	            if($item[1] -notmatch '^\[::'){
                    
                        #parse the netstat line for local address and port
    	                    if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $localAddress = $la.IPAddressToString
    	                        $localPort = $item[1].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $localAddress = $item[1].split(':')[0]
    	                        $localPort = $item[1].split(':')[-1]
    	                    }
                    
                        #parse the netstat line for remote address and port
    	                    if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $remoteAddress = $ra.IPAddressToString
    	                        $remotePort = $item[2].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $remoteAddress = $item[2].split(':')[0]
    	                        $remotePort = $item[2].split(':')[-1]
    	                    }

                        #Filter IPv4/IPv6 if specified
                            if($AddressFamily -ne "*")
                            {
                                if($AddressFamily -eq 'IPv4' -and $localAddress -match ':' -and $remoteAddress -match ':|\*' )
                                {
                                    #Both are IPv6, or ipv6 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                                elseif($AddressFamily -eq 'IPv6' -and $localAddress -notmatch ':' -and ( $remoteAddress -notmatch ':' -or $remoteAddress -match '*' ) )
                                {
                                    #Both are IPv4, or ipv4 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                            }
    	    		
                        #parse the netstat line for other properties
    	    		        $procId = $item[-1]
    	    		        $proto = $item[0]
    	    		        $status = if($item[0] -eq 'tcp') {$item[3]} else {$null}	

                        #Filter the object
		    		        if($remotePort -notlike $Port -and $localPort -notlike $Port){
                                write-verbose "remote $Remoteport local $localport port $port"
                                Write-Verbose "Filtered by Port:`n$result"
                                continue
		    		        }

		    		        if($remoteAddress -notlike $Address -and $localAddress -notlike $Address){
                                Write-Verbose "Filtered by Address:`n$result"
                                continue
		    		        }
    	    			     
    	    			    if($status -notlike $State){
                                Write-Verbose "Filtered by State:`n$result"
                                continue
		    		        }

    	    			    if($proto -notlike $Protocol){
                                Write-Verbose "Filtered by Protocol:`n$result"
                                continue
		    		        }
                   
                        #Display progress bar prior to getting process name or host name
                            Write-Progress  -Activity "Resolving host and process names"`
                                -Status "Resolving process ID $procId with remote address $remoteAddress and local address $localAddress"`
                                -PercentComplete (( $count / $totalCount ) * 100)
    	    		
                        #If we are running showprocessnames, get the matching name
                            if($ShowProcessNames -or $PSBoundParameters.ContainsKey -eq 'ProcessName'){
                        
                                #handle case where process spun up in the time between running get-process and running netstat
                                if($procName = $processes | Where {$_.id -eq $procId} | select -ExpandProperty name ){ }
                                else {$procName = "Unknown"}

                            }
                            else{$procName = "NA"}

		    		        if($procName -notlike $ProcessName){
                                Write-Verbose "Filtered by ProcessName:`n$result"
                                continue
		    		        }
    	    						
                        #if the showhostnames switch is specified, try to map IP to hostname
                            if($showHostnames){
                                $tmpAddress = $null
                                try{
                                    if($remoteAddress -eq "127.0.0.1" -or $remoteAddress -eq "0.0.0.0"){
                                        $remoteAddress = $Computer
                                    }
                                    elseif($remoteAddress -match "\w"){
                                        
                                        #check with dns cache first
                                            if ($dnsCache.containskey( $remoteAddress)) {
                                                $remoteAddress = $dnsCache[$remoteAddress]
                                                write-verbose "using cached REMOTE '$remoteAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $remoteAddress
                                                    $remoteAddress = [System.Net.DNS]::GetHostByAddress("$remoteAddress").hostname
                                                    $dnsCache.add($tmpAddress, $remoteAddress)
                                                    write-verbose "using non cached REMOTE '$remoteAddress`t$tmpAddress"
                                            }
                                    }
                                }
                                catch{ }

                                try{

                                    if($localAddress -eq "127.0.0.1" -or $localAddress -eq "0.0.0.0"){
                                        $localAddress = $Computer
                                    }
                                    elseif($localAddress -match "\w"){
                                        #check with dns cache first
                                            if($dnsCache.containskey($localAddress)){
                                                $localAddress = $dnsCache[$localAddress]
                                                write-verbose "using cached LOCAL '$localAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $localAddress
                                                    $localAddress = [System.Net.DNS]::GetHostByAddress("$localAddress").hostname
                                                    $dnsCache.add($localAddress, $tmpAddress)
                                                    write-verbose "using non cached LOCAL '$localAddress'`t'$tmpAddress'"
                                            }
                                    }
                                }
                                catch{ }
                            }
    
    	    		    #Write the object	
    	    		        New-Object -TypeName PSObject -Property @{
		    		            ComputerName = $Computer
                                PID = $procId
		    		            ProcessName = $procName
		    		            Protocol = $proto
		    		            LocalAddress = $localAddress
		    		            LocalPort = $localPort
		    		            RemoteAddress =$remoteAddress
		    		            RemotePort = $remotePort
		    		            State = $status
		    	            } | Select-Object -Property $properties								

                        #Increment the progress counter
                            $count++
                    }
                }
        }
    }
}
#Running Processes Review
function Get-ProcessTre {
    [CmdletBinding()]
    param([string]$ComputerName, [int]$IndentSize = 5)
    
    $indentSize   = [Math]::Max(1, [Math]::Min(12, $indentSize))
    $computerName = ($computerName, ".")[[String]::IsNullOrEmpty($computerName)]
    $processes    = Get-WmiObject Win32_Process -ComputerName $computerName
    $pids         = $processes | select -ExpandProperty ProcessId
    $parents      = $processes | select -ExpandProperty ParentProcessId -Unique
    $liveParents  = $parents | ? { $pids -contains $_ }
    $deadParents  = Compare-Object -ReferenceObject $parents -DifferenceObject $liveParents `
                  | select -ExpandProperty InputObject
    $processByParent = $processes | Group-Object -AsHashTable ParentProcessId
    #$path = $processes | select Path
    #$hash = Compute-FileHash -FilePath $process.Path -HashType $hashtype
    #$Depth,$_.ProcessId,$_.ParentProcessId,$_.Name,$_.sessionID,$_.Handles,$_.CreationDate,$_.Path,$_.CommandLine,$_.Description
    function Write-ProcessTree($process, [int]$level = 0) {
        $id = $process.ProcessId
        $parentProcessId = $process.ParentProcessId
        if ($process.Path) {
            $ProcessHash = Compute-FileHash -FilePath $process.Path -HashType MD5
        } else {
            $ProcessHash = "N/A."
        }
        $process `
        | Add-Member NoteProperty Id $id -PassThru `
        | Add-Member NoteProperty ParentId $parentProcessId -PassThru `
        | Add-Member NoteProperty Level $level -PassThru `
        | Add-Member NoteProperty Hash $ProcessHash -PassThru
       # | Add-Member -Type NoteProperty -Name "Hash" -Value $hash
       # | Add-Member NotProperty MD5 $(Get-Hash -FilePath $path) -PassThru
        $processByParent.Item($id) `
        | ? { $_ } `
        | % { Write-ProcessTree $_ ($level + 1) }
    }

    $processes `
    | ? { $_.ProcessId -ne 0 -and ($_.ProcessId -eq $_.ParentProcessId -or $deadParents -contains $_.ParentProcessId) } `
    | % { Write-ProcessTree $_ }
}
#Prefetch List
function Get-PreftchListing{

    $pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 
    Switch -Regex ($pfconf) {
        "[1-3]" {
            $o = "" | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
            ls $env:windir\Prefetch\*.pf | % {
                $o.FullName = $_.FullName;
                $o.CreationTimeUtc = Get-Date($_.CreationTimeUtc) -format o;
                $o.LastAccesstimeUtc = Get-Date($_.LastAccessTimeUtc) -format o;
                $o.LastWriteTimeUtc = Get-Date($_.LastWriteTimeUtc) -format o;
            $o
        }
    }
    default {
        Write-Output "Prefetch not enabled on ${env:COMPUTERNAME}."
    }
}

}

#Returns Service Windows Service recovery options, which could be used as a persistence mechanism by adversaries.
Function Get-ServicesRecovery {
$data = & $env:windir\system32\sc query | ForEach-Object {
    $svc = $_
    if ($svc -match "SERVICE_NAME:\s(.*)") { 
        & $env:windir\system32\sc qfailure $($matches[1])
    }
}

$ServiceName = $RstPeriod = $RebootMsg = $CmdLine = $FailAction1 = $FailAction2 = $FailAction3 = $False
$data | ForEach-Object {
    $line = $_

    $line = $line.Trim()
    if ($line -match "^S.*\:\s(?<SvcName>[-_A-Za-z0-9]+)") {
        if ($ServiceName) {
            $o = "" | Select-Object ServiceName, RstPeriod, RebootMsg, CmdLine, FailAction1, FailAction2, FailAction3
            $o.ServiceName, $o.RstPeriod, $o.RebootMsg, $o.CmdLine, $o.FailAction1, $o.FailAction2, $o.FailAction3 = `
                (($ServiceName,$RstPeriod,$RebootMsg,$CmdLine,$FailAction1,$FailAction2,$FailAction3) -replace "False", $null)
            $o
        }
        $ServiceName = $matches['SvcName']
    } elseif ($line -match "^RESE.*\:\s(?<RstP>[0-9]+|INFINITE)") {
        $RstPeriod = $matches['RstP']
    } elseif ($line -match "^REB.*\:\s(?<RbtMsg>.*)") {
        $RebootMsg = $matches['RbtMsg']
    } elseif ($line -match "^C.*\:\s(?<Cli>.*)") {
        $CmdLine = $matches['Cli']
    } elseif ($line -match "^F.*\:\s(?<Fail1>.*)") {
        $FailAction1 = $matches['Fail1']
        $FailAction2 = $FailAction3 = $False
    } elseif ($line -match "^(?<FailNext>REST.*)") {
        if ($FailAction2) {
            $FailAction3 = $matches['FailNext']
        } else {
            $FailAction2 = $matches['FailNext']
        }
    }
}

$o = "" | Select-Object ServiceName, RstPeriod, RebootMsg, CmdLine, FailAction1, FailAction2, FailAction3
$o.ServiceName, $o.RstPeriod, $o.RebootMsg, $o.CmdLine, $o.FailAction1, $o.FailAction2, $o.FailAction3 = `
    (($ServiceName,$RstPeriod,$RebootMsg,$CmdLine,$FailAction1,$FailAction2,$FailAction3) -replace "False", $null)
$o }

#Autoruns
Function Get-AutoraunsDeep{
    function Compute-FileHash {
Param(
    [Parameter(Mandatory = $true, Position=1)]
    [string]$FilePath,
    [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160")]
    [string]$HashType = "MD5"
)
    
    switch ( $HashType.ToUpper() )
    {
        "MD5"       { $hash = [System.Security.Cryptography.MD5]::Create() }
        "SHA1"      { $hash = [System.Security.Cryptography.SHA1]::Create() }
        "SHA256"    { $hash = [System.Security.Cryptography.SHA256]::Create() }
        "SHA384"    { $hash = [System.Security.Cryptography.SHA384]::Create() }
        "SHA512"    { $hash = [System.Security.Cryptography.SHA512]::Create() }
        "RIPEMD160" { $hash = [System.Security.Cryptography.RIPEMD160]::Create() }
        default     { "Invalid hash type selected." }
    }

    if (Test-Path $FilePath) {
        $File = Get-ChildItem -Force $FilePath
        $fileData = [System.IO.File]::ReadAllBytes($File.FullName)
        $HashBytes = $hash.ComputeHash($fileData)
        $PaddedHex = ""

        foreach($Byte in $HashBytes) {
            $ByteInHex = [String]::Format("{0:X}", $Byte)
            $PaddedHex += $ByteInHex.PadLeft(2,"0")
        }
        $PaddedHex
        $File.LastWriteTimeUtc
        $File.Length
        
    } else {
        "${FilePath} is locked or could not be found."
        "${FilePath} is locked or could not be not found."
        Write-Error -Category InvalidArgument -Message ("{0} is locked or could not be found." -f $FilePath)
    }
}

function GetShannonEntropy {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [string]$FilePath
)
    $fileEntropy = 0.0
    $FrequencyTable = @{}
    $ByteArrayLength = 0
            
    if(Test-Path $FilePath) {
        $file = (ls $FilePath)
        Try {
            $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName)
        } Catch {
            Write-Error -Message ("Caught {0}." -f $_)
        }

        foreach($fileByte in $fileBytes) {
            $FrequencyTable[$fileByte]++
            $ByteArrayLength++
        }

        $byteMax = 255
        for($byte = 0; $byte -le $byteMax; $byte++) {
            $byteProb = ([double]$FrequencyTable[[byte]$byte])/$ByteArrayLength
            if ($byteProb -gt 0) {
                $fileEntropy += -$byteProb * [Math]::Log($byteProb, 2.0)
            }
        }
        $fileEntropy
        
    } else {
        "${FilePath} is locked or could not be found. Could not calculate entropy."
        Write-Error -Category InvalidArgument -Message ("{0} is locked or could not be found." -f $FilePath)
    }
}

if (Test-Path "C:\PSIR\autorunsc.exe") {
    # This regex matches all of the path types I've encountered, but there may be some it misses, if you find some, please send a sample to kansa@trustedsignal.com
    $fileRegex = New-Object System.Text.RegularExpressions.Regex "(([a-zA-Z]:|\\\\\w[ \w\.]*)(\\\w[- \w\.\\\{\}]*|\\%[ \w\.]+%+)+|%[ \w\.]+%(\\\w[ \w\.]*|\\%[ \w\.]+%+)*)"
    & C:\PSIR\autorunsc.exe /accepteula -a * -c -h -s '*' -nobanner 2> $null | ConvertFrom-Csv | ForEach-Object {
        $_ | Add-Member NoteProperty ScriptMD5 $null
        $_ | Add-Member NoteProperty ScriptModTimeUTC $null
        $_ | Add-Member NoteProperty ShannonEntropy $null
        $_ | Add-Member NoteProperty ScriptLength $null

        if ($_."Image Path") {
            $_.ShannonEntropy = GetShannonEntropy $_."Image Path"
        }

        $fileMatches = $False
        if (($_."Image Path").ToLower() -match "\.bat|\.ps1|\.vbs") {
            $fileMatches = $fileRegex.Matches($_."Image Path")
        } elseif (($_."Launch String").ToLower() -match "\.bat|\.ps1|\.vbs") {
            $fileMatches = $fileRegex.Matches($_."Launch String")
        }

        if ($fileMatches) {
            for($i = 0; $i -lt $fileMatches.count; $i++) {
                $file = $fileMatches[$i].value
                if ($file -match "\.bat|\.ps1|\.vbs") {
                    if ($file -match "%userdnsdomain%") {
                        $scriptPath = "\\" + [System.Environment]::ExpandEnvironmentVariables($file)
                    } elseif ($file -match "%") {
                        $scriptPath = [System.Environment]::ExpandEnvironmentVariables($file)
                    } else {
                        $scriptPath = $file
                    }
                }
                $scriptPath = $scriptPath.Trim()
                $_.ScriptMD5,$_.ScriptModTimeUTC,$_.ScriptLength = Compute-FileHash $scriptPath
                $scriptPath = $null
            }
        }
        $_
    }
} else {
    Write-Error "Autorunsc.exe not found in C:\PSIR\."
}
}

#Local Group Memebership
Function Get-LocalGroupMemebership {
$Groups = & net localgroup | Select-String -Pattern "^\*.+"
ForEach ($Group in $Groups) {
	if ($Group -match "\*(.+)") {
		& net localgroup $matches[1] | Select-Object -Skip 6 | Where-Object -FilterScript { $_ -and $_ -notmatch "The command completed successfully" } -ErrorAction SilentlyContinue | ForEach-Object {
			[PSCustomObject]@{
				Username = $_
				Group = $matches[1]
			}
		}
	}
}

}

#DNSCache
Function Get-DNSCache{
if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    Get-DnsClientCache | Select-Object TimeToLIve, Caption, Description, ElementName, InstanceId, Data, DataLength, Entry, Name, Section, Status, Type
} else {
	$o = "" | Select-Object TimeToLive, Data, DataLength, Entry, Name, Section, Type, RecordType
	
	# Run IPConfig.exe /DisplayDNS and set output to a variable for us to work with
	$DisplayDNS = & ipconfig.exe /displaydns | Select-Object -Skip 3 | ForEach-Object { $_.Trim() }
	
	# Parse the data from ipconfig and set to Object Properties
	$DisplayDNS | ForEach-Object {
	    switch -Regex ($_) {
	        "-----------" {
	        }
	        "Record Name[\s|\.]+:\s(?<RecordName>.*$)" {
	            $o.Name = ($matches['RecordName'])
	        } 
	        "Record Type[\s|\.]+:\s(?<RecordType>.*$)" {
	            $o.RecordType = ($matches['RecordType'])
	        }
	        "Time To Live[\s|\.]+:\s(?<TTL>.*$)" {
	            $o.TimeToLive = ($matches['TTL'])
	        }
	        "Data Length[\s|\.]+:\s(?<DataLength>.*$)" {
	            $o.DataLength = ($matches['DataLength'])
	        }
	        "Section[\s|\.]+:\s(?<Section>.*$)" {
	            $o.Section = ($matches['Section'])
	        }
	        "(?<Type>[A-Za-z()\s]+)\s.*Record[\s|\.]+:\s(?<Data>.*$)" {
	            $o.Data = ($matches['Data'])
				$o.Type = ($matches['Type'])
				$o
	        }
	        "^$" {
	            $o = "" | Select-Object TimeToLive, Data, DataLength, Entry, Name, Section, Type, RecordType
	        }
	        default {
				$o.Entry= $_
	        }
	    }
	}
}
}

########################################################
###                      Collecting                  ###
########################################################

#Get Process Review
Write-Host "[+] Collecting Processes Review Information" -ForegroundColor Green
Get-ProcessTre | select Level, Id, ParentId, Name, SessionID, Handles, CreationDate, Path, Hash, CommandLine, Description, UserName, DomainName | Export-Csv -Path $ProcessesFolder\RunningProcessReview.csv -NoTypeInformation
<#
#Get Autoruns
Write-Host "[+] Collecting Autoruns Information" -ForegroundColor Green
Get-AutoraunsDeep | Export-Csv -Path $PersistenceFolder\Autoruns.csv -Encoding ASCII -NoTypeInformation
#>
#Verify Digital Signatures of All running Processes
Write-Host "[+] Checking Digital Signatures off All Running Processes" -ForegroundColor Green
Get-Process | foreach {$DigiCert = try {Get-AuthenticodeSignature -FilePath $_.path} catch { } ; $_ | select name,ID,path,Description | Add-Member "NoteProperty" CertStatus $( If($DigiCert) {$DigiCert.Status} else {"Access Denied"} )  -PassThru | Add-Member "Noteproperty" Subject $($DigiCert.SignerCertificate.Subject) -PassThru | Add-Member "NoteProperty" ThumbPrint $($DigiCert.SignerCertificate.Thumbprint) -PassThru }  | Export-Csv -Path $ProcessesFolder\RunningProcessesSignatureCheck.csv -NoTypeInformation

<#
#Verify Digital Signature of All .EXE in C:\ Drive
Write-Host "[+] Checking Digital Signatur off All .EXE files in C:\ Drive" -ForegroundColor Green
Get-ChildItem C:\ -Include @("*.exe") -R -File -ErrorVariable Err -ErrorAction SilentlyContinue | foreach {$DigiCert = try {Get-AuthenticodeSignature -FilePath $_.FullName} catch { } ; $_ | select name,FullName | Add-Member "Noteproperty" FileDescription $_.VersionInfo.FileDescription -PassThru | Add-Member "NoteProperty" CertStatus $( If($DigiCert.Status -eq "UnknownError") {"NOT FOUND"} else {$DigiCert.Status} )  -PassThru | Add-Member "Noteproperty" Subject $($DigiCert.SignerCertificate.Subject) -PassThru | Add-Member "NoteProperty" ThumbPrint $($DigiCert.SignerCertificate.Thumbprint) -PassThru } | Export-Csv -Path $ProcessesFolder\CDriveExeSignatureCheck.csv -NoTypeInformation
$Err[0] >> $DestinationFolder\LogErrors.txt
#>

#Get all installed applications
Write-Host "[+] Collecting installed Applications" -ForegroundColor Green
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path $ProcessesFolder\ApplicationsInstalled.csv -NoTypeInformation
#Get local users accounts
Write-Host "[+] Collecting Local Users Accounts" -ForegroundColor Green
Get-WMIObject -Class Win32_UserAccount -Filter "LocalAccount='$True'" -ErrorAction SilentlyContinue | Select-Object -Property Domain, Name, FullName, Disabled, PasswordExpires, SID, Description | Export-Csv -Path $SystemConfigurationFolder\LocalUsers.csv -NoTypeInformation
#Get Local Group Memebership
Write-Host "[+] Collecting Local Group Membership" -ForegroundColor Green
Get-LocalGroupMemebership | Export-Csv -Path $SystemConfigurationFolder\LocalGroupMemebership.csv -Encoding ASCII -NoTypeInformation
#Get Prefetch Listing
Write-Host "[+] Collecting Prefetch List" -ForegroundColor Green
Get-PreftchListing | Export-Csv -Path $ProcessesFolder\PrefetchList.csv -Encoding ascii -NoTypeInformation
#Get Scheduled Tasks
Write-Host "[+] Collecting Scheduled Tasks" -ForegroundColor Green
schtasks /query /FO CSV /v | ConvertFrom-Csv | Export-Csv -Path $PersistenceFolder\ScheduledTasks.csv -Encoding ASCII -NoTypeInformation
#Get Statup Programs
Write-Host "[+] Collecting Startup Programs" -ForegroundColor Green
wmic startup get caption,command > $PersistenceFolder\StartupPrograms.txt
#Get Network Statistics
Write-Host "[+] Collecting Network Statistics" -ForegroundColor Green
Get-NetworkStatistics | Select-Object Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, ProcessName, PID | Export-Csv -Path $NetworkFolder\NetworkStatistics.csv -Encoding ascii -NoTypeInformation
#Get Smb Sessions connected to this host
Write-Host "[+] Collecting SMB Sessions connecting to this host" -ForegroundColor Green
Get-WmiObject -Class Win32_Share | select PSComputerName, Name, Description, Path, Status | Export-Csv -Path $NetworkFolder\SmbSessions.csv -NoTypeInformation
#Get ARP Table
Write-Host "[+] Collecting ARP Entries" -ForegroundColor Green
Get-ARPTable > $NetworkFolder\ARPTable.txt
#Get Process Tree
Write-Host "[+] Collecting Process Tree" -ForegroundColor Green
Get-ProcessTree -Verbose | select Id, Level, IndentedName, ParentId > $ProcessesFolder\ProcessTree.txt
#Get all running services with status and start types
Write-Host "[+] Collecting Services Information" -ForegroundColor Green
Get-Service | Sort-Object name, status -Descending | Select-Object Name, DisplayName, Status, StartType | Export-Csv -Path $ServicesFolder\Services.csv -Encoding ascii -NoTypeInformation
#Get information about Windows Service recovery options
Write-Host "[+] Collecting information about Windows Service recovery option" -ForegroundColor Green
Get-ServicesRecovery | Export-Csv -Path $ServicesFolder\ServicesRecovery.csv -Encoding ascii -NoTypeInformation
#Get Network Configuration
Write-Host "[+] Collecting Network Configuration" -ForegroundColor Green
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object DHCPEnabled, IPAddress, ServiceName, Description | Export-Csv -Path $NetworkFolder\NetConfiguration.csv -Encoding ascii -NoTypeInformation
#Get DNS Cache
Write-Host "[+] Collecting DNS Cache" -ForegroundColor Green
Get-DNSCache | Select-Object TimeToLive, Data, Entry, Name | Export-Csv -Path $NetworkFolder\DNSCache.csv -Encoding ascii -NoTypeInformation
<#
#Get Network Routes
Write-Host "[+] Collecting Network Routes" -ForegroundColor Green
Get-NetRoute | Select-Object -Property InterfaceAlias, DestinationPrefix, NextHop, RouteMetric | Export-Csv -Path $NetworkFolder\NetworkRoutes.csv -Encoding ascii -NoTypeInformation
#>
#Get task list
Write-Host "[+] Collecting Tasks list" -ForegroundColor Green
& $env:windir\system32\tasklist.exe /v /fo csv | Select-Object -Skip 1 | % {
    $o = "" | Select-Object ImageName,PID,SessionName,SessionNum,MemUsage,Status,UserName,CPUTime,WindowTitle
    $row = $_ -replace '(,)(?=(?:[^"]|"[^"]*")*$)', "`t" -replace "`""
    $o.ImageName, 
    $o.PID,
    $o.SessionName,
    $o.SessionNum,
    $o.MemUsage,
    $o.Status,
    $o.UserName,
    $o.CPUTime,
    $o.WindowTitle = ( $row -split "`t" )
    $o
} | Export-Csv -Path $ProcessesFolder\Tasklist.csv -Encoding ascii -NoTypeInformation

