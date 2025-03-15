# BluSkreener
# Author: Gibran Iqbal 
# Description: A PowerShell script that analyzes crash dumps, identifies problematic drivers,
#              and provides root cause analysis based on bugcheck codes.

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$DumpPath = "$env:SystemRoot\Minidump",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop\BSODAnalysis",
    
    [Parameter(Mandatory = $false)]
    [string]$KnowledgeBasePath = "$PSScriptRoot\BugcheckKB.json",
    
    [Parameter(Mandatory = $false)]
    [string]$DriversDBPath = "$PSScriptRoot\KnownBadDrivers.json",
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport = $true
)

# Function to find Windows Debugging Tools on the system
function Find-WindowsDebuggingTools {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    Write-Host "Searching for Windows Debugging Tools..." -ForegroundColor Cyan
    
    # Define possible paths to search
    $possiblePaths = @(
        # Windows 10/11 SDK Paths - Multiple architecture options
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\arm",
        
        # Windows 11 SDK additional paths
        "C:\Program Files\Windows Kits\11\Debuggers\x64",
        "C:\Program Files\Windows Kits\11\Debuggers\arm64",
        "C:\Program Files (x86)\Windows Kits\11\Debuggers\x86",
        
        # Legacy Windows SDK paths
        "C:\Program Files\Debugging Tools for Windows (x64)",
        "C:\Program Files (x86)\Debugging Tools for Windows (x86)"
    )
    
    # Try to find the dumpchk.exe file in any of the possible paths
    foreach ($path in $possiblePaths) {
        $dumpchkPath = Join-Path -Path $path -ChildPath "dumpchk.exe"
        if (Test-Path -Path $dumpchkPath) {
            Write-Host "Found Windows Debugging Tools (dumpchk.exe) at: $dumpchkPath" -ForegroundColor Green
            return $dumpchkPath
        }
    }
    
    # If we didn't find a fixed path, try searching in Windows directory recursively
    # Note: This could be slow but might find custom installations
    Write-Host "Searching Windows directories for dumpchk.exe..." -ForegroundColor Yellow
    $windowsSearchPaths = @(
        "${env:ProgramFiles}",
        "${env:ProgramFiles(x86)}"
    )
    
    foreach ($searchRoot in $windowsSearchPaths) {
        try {
            $results = Get-ChildItem -Path $searchRoot -Filter "dumpchk.exe" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
                     
            if ($results) {
                Write-Host "Found dumpchk.exe at: $results" -ForegroundColor Green
                return $results
            }
        }
        catch {
            Write-Warning "Error searching in $searchRoot`: $_"
        }
    }
    
    # If we still didn't find it, provide information on how to get the debugging tools
    Write-Warning "Windows Debugging Tools (dumpchk.exe) not found. To install, use one of these methods:"
    Write-Host "1. Install Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/" -ForegroundColor Yellow
    Write-Host "2. Install WinDbg Preview from Microsoft Store" -ForegroundColor Yellow
    Write-Host "3. Download standalone Debugging Tools for Windows" -ForegroundColor Yellow
    
    return $null
}

# Function to initialize the environment
function Initialize-Environment {
    [CmdletBinding()]
    param()
    
    Write-Host "Initializing environment..." -ForegroundColor Cyan
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
    }
    
    # Find the Windows Debugging Tools on the system
    $global:DumpChkPath = Find-WindowsDebuggingTools
    
    if ($null -eq $global:DumpChkPath) {
        Write-Warning "Windows Debugging Tools not found. Some functionality may be limited."
        $global:DebuggerAvailable = $false
    }
    else {
        $global:DebuggerAvailable = $true
        Write-Host "DumpChk found at: $global:DumpChkPath" -ForegroundColor Green
    }
    
    # Initialize or load bugcheck knowledge base
    if (-not (Test-Path -Path $KnowledgeBasePath)) {
        Write-Host "Bugcheck knowledge base not found. Creating sample knowledge base..." -ForegroundColor Yellow
        Initialize-BugcheckKnowledgeBase
    }
    else {
        Write-Host "Loading existing bugcheck knowledge base..." -ForegroundColor Green
        $global:BugcheckKB = Get-Content -Path $KnowledgeBasePath -Raw | ConvertFrom-Json
    }
    
    # Initialize or load drivers database
    if (-not (Test-Path -Path $DriversDBPath)) {
        Write-Host "Known bad drivers database not found. Creating sample database..." -ForegroundColor Yellow
        Initialize-DriversDatabase
    }
    else {
        Write-Host "Loading existing drivers database..." -ForegroundColor Green
        $global:DriversDB = Get-Content -Path $DriversDBPath -Raw | ConvertFrom-Json
    }
}

# Function to create a sample bugcheck knowledge base
function Initialize-BugcheckKnowledgeBase {
    [CmdletBinding()]
    param()
    
    $bugcheckData = @{
        "0x0000001E" = @{
            "Name"            = "KMODE_EXCEPTION_NOT_HANDLED"
            "Description"     = "A kernel-mode program generated an exception which the error handler did not catch."
            "CommonCauses"    = @(
                "Faulty device driver"
                "System service"
                "NTFS corruption"
                "Faulty hardware (especially memory-related)"
            )
            "Recommendations" = @(
                "Check for recent driver updates or rollbacks"
                "Run hardware diagnostics, especially memory test"
                "Check system file integrity with SFC /scannow"
                "Run chkdsk to verify disk integrity"
            )
        }
        "0x0000007E" = @{
            "Name"            = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"
            "Description"     = "A system thread generated an exception that the error handler did not catch."
            "CommonCauses"    = @(
                "Faulty device driver"
                "Defective hardware (RAM, motherboard, etc.)"
                "Overclocking"
                "System file corruption"
            )
            "Recommendations" = @(
                "Update drivers, especially graphics, storage, and network drivers"
                "Reset overclocking to factory settings if applicable"
                "Check for hardware issues with diagnostic tools"
                "Restore system to earlier restore point"
            )
        }
        "0x00000050" = @{
            "Name"            = "PAGE_FAULT_IN_NONPAGED_AREA"
            "Description"     = "Memory corruption in the nonpaged area of memory, often indicating hardware issues."
            "CommonCauses"    = @(
                "Faulty RAM modules"
                "Incompatible device drivers"
                "System service that has corrupted the memory"
                "Improperly seated hardware"
            )
            "Recommendations" = @(
                "Run a memory diagnostic like Windows Memory Diagnostic or Memtest86+"
                "Update BIOS and device drivers"
                "Check for proper seating of hardware components"
                "Disable any recently installed third-party services"
            )
        }
        "0x00000116" = @{
            "Name"            = "VIDEO_TDR_FAILURE"
            "Description"     = "The display driver failed to respond in a timely fashion. Usually occurs when the GPU hangs."
            "CommonCauses"    = @(
                "Graphics driver crash"
                "GPU overheating"
                "Unstable GPU overclock"
                "Failing GPU hardware"
            )
            "Recommendations" = @(
                "Update graphics drivers to the latest version"
                "Check GPU temperature under load"
                "Disable GPU overclocking"
                "Test with a different graphics card if possible"
            )
        }
        "0x0000009C" = @{
            "Name"            = "MACHINE_CHECK_EXCEPTION"
            "Description"     = "Hardware reported a fatal error to the CPU, usually indicating CPU, memory or power issues."
            "CommonCauses"    = @(
                "Processor error (CPU failure)"
                "Memory error (bad RAM)"
                "Motherboard or power supply issues"
                "Overclocking"
            )
            "Recommendations" = @(
                "Check system temperatures and cooling"
                "Reset BIOS settings to default or disable overclocking"
                "Run memory diagnostics"
                "Update BIOS to latest version"
            )
        }
    }
    
    # Write the knowledge base to a JSON file
    $bugcheckData | ConvertTo-Json -Depth 4 | Out-File -FilePath $KnowledgeBasePath -Encoding utf8
    $global:BugcheckKB = $bugcheckData
    Write-Host "Created sample bugcheck knowledge base at: $KnowledgeBasePath" -ForegroundColor Green
}

# Function to create a sample drivers database
function Initialize-DriversDatabase {
    [CmdletBinding()]
    param()
    
    $driverData = @{
        "nvlddmkm.sys" = @{
            "VendorName"  = "NVIDIA Corporation"
            "DriverType"  = "Display Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange"     = @("456.71", "460.89")
                    "IssueDescription" = "May cause SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7E) when entering sleep mode"
                    "Resolution"       = "Update to version 461.09 or later"
                    "AffectedOS"       = @("Windows 10", "Windows 11")
                },
                @{
                    "VersionRange"     = @("471.11", "471.41")
                    "IssueDescription" = "Can trigger VIDEO_TDR_FAILURE (0x116) with certain applications"
                    "Resolution"       = "Update to version 472.12 or later"
                    "AffectedOS"       = @("Windows 11")
                }
            )
        }
        "iastor.sys"   = @{
            "VendorName"  = "Intel Corporation"
            "DriverType"  = "Storage Controller Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange"     = @("11.2.0.1006", "11.2.0.1032")
                    "IssueDescription" = "Can cause KERNEL_DATA_INPAGE_ERROR (0x7A) when using NVMe storage"
                    "Resolution"       = "Update to Intel Rapid Storage Technology version 11.2.0.1033 or later"
                    "AffectedOS"       = @("Windows 10", "Windows 11")
                }
            )
        }
        "rtkvhd64.sys" = @{
            "VendorName"  = "Realtek Semiconductor Corp."
            "DriverType"  = "Audio Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange"     = @("6.0.9107.1", "6.0.9107.5")
                    "IssueDescription" = "May cause DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1) on wake from sleep"
                    "Resolution"       = "Update to version 6.0.9107.6 or later"
                    "AffectedOS"       = @("Windows 11")
                }
            )
        }
        "atikmpag.sys" = @{
            "VendorName"  = "AMD Inc."
            "DriverType"  = "Display Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange"     = @("27.20.21001.14001", "27.20.21003.8013")
                    "IssueDescription" = "Can trigger VIDEO_TDR_FAILURE (0x116) with power state transitions"
                    "Resolution"       = "Update to Adrenalin version 21.3.1 or later"
                    "AffectedOS"       = @("Windows 10", "Windows 11")
                }
            )
        }
        "asmtxhci.sys" = @{
            "VendorName"  = "ASMedia Technology Inc."
            "DriverType"  = "USB Controller Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange"     = @("1.16.51.1", "1.16.55.1")
                    "IssueDescription" = "Can cause SYSTEM_SERVICE_EXCEPTION (0x3B) when transferring large files"
                    "Resolution"       = "Update to version 1.16.56.1 or later or use Microsoft inbox driver"
                    "AffectedOS"       = @("Windows 10", "Windows 11")
                }
            )
        }
    }
    
    # Write the drivers database to a JSON file
    $driverData | ConvertTo-Json -Depth 4 | Out-File -FilePath $DriversDBPath -Encoding utf8
    $global:DriversDB = $driverData
    Write-Host "Created sample known bad drivers database at: $DriversDBPath" -ForegroundColor Green
}

# Function to find the most recent crash dump
function Get-LatestCrashDump {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$DumpDirectory = $DumpPath
    )
    
    if (-not (Test-Path -Path $DumpDirectory)) {
        Write-Warning "Crash dump directory not found: $DumpDirectory"
        return $null
    }
    
    $latestDump = Get-ChildItem -Path $DumpDirectory -Filter "*.dmp" | 
    Sort-Object -Property LastWriteTime -Descending | 
    Select-Object -First 1
    
    if ($null -eq $latestDump) {
        Write-Warning "No crash dump files found in: $DumpDirectory"
        return $null
    }
    
    Write-Host "Found latest crash dump: $($latestDump.FullName) (Created: $($latestDump.LastWriteTime))" -ForegroundColor Green
    return $latestDump.FullName
}

# Function to extract metadata from a crash dump file
function Get-CrashDumpMetadata {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DumpFile
    )
    
    Write-Host "Extracting metadata from crash dump: $DumpFile" -ForegroundColor Cyan
    
    # Initialize with default values to avoid nulls
    $metadata = @{
        "DumpFile"       = $DumpFile
        "FileName"       = (Split-Path -Path $DumpFile -Leaf)
        "CreationTime"   = (Get-Item -Path $DumpFile).LastWriteTime
        "FileSize"       = (Get-Item -Path $DumpFile).Length
        "BugcheckCode"   = "Unknown"
        "BugcheckName"   = "Unknown"
        "CrashedDrivers" = @()
    }
    
    # Try to extract minimal information from the dump file name for fallback
    if ($metadata.FileName -match "(\d{8}-\d+)") {
        $metadata["CrashTime"] = $Matches[1]
    }
    
    if (-not $global:DebuggerAvailable) {
        Write-Warning "DumpChk not available. Limited metadata extraction only."
        return $metadata
    }
    
    try {
        # Run dumpchk with verbose option to get maximum information
        Write-Host "Running DumpChk to analyze crash dump..." -ForegroundColor Cyan
        $dumpchkOutput = & $global:DumpChkPath -v $DumpFile
        
        if ($null -eq $dumpchkOutput -or $dumpchkOutput.Count -eq 0) {
            Write-Warning "DumpChk returned no output. Using limited metadata."
            return $metadata
        }
        
        # Extract bugcheck information
        $bugcheckCode = "Unknown"
        $bugcheckName = "Unknown"
        $crashedDrivers = @()
        
        # Convert to a single string for regex error checking
        $outputText = $dumpchkOutput -join "`n"
        
        # Check for common error patterns in dumpchk output
        if ($outputText -match "could not|cannot|error|invalid|corrupt|failed") {
            Write-Warning "DumpChk reported potential issues with the dump file: $($Matches[0])"
        }
        
        foreach ($line in $dumpchkOutput) {
            # Extract bugcheck code
            if ($line -match "BUGCHECK_CODE\s*:\s*([0-9a-fA-F]+)") {
                $bugcheckCode = "0x" + $Matches[1]
                Write-Host "Found bugcheck code: $bugcheckCode" -ForegroundColor Green
            }
            # Extract any potential module names
            elseif ($line -match "MODULE_NAME:\s+(\w+)") {
                $moduleName = $Matches[1]
                if ($moduleName.EndsWith(".sys", [StringComparison]::OrdinalIgnoreCase)) {
                    $crashedDrivers += $moduleName
                    Write-Host "Found module: $moduleName" -ForegroundColor Green
                }
            }
            # Try to find image names (drivers) that might be implicated
            elseif ($line -match "IMAGE_NAME:\s+(\w+\.sys)") {
                $imageName = $Matches[1]
                $crashedDrivers += $imageName
                Write-Host "Found image: $imageName" -ForegroundColor Green
            }
            # Look for any failure bucket ID related to specific modules
            elseif ($line -match "FAILURE_BUCKET_ID:.*?(\w+\.sys)") {
                $bucketDriver = $Matches[1]
                $crashedDrivers += $bucketDriver
                Write-Host "Found in failure bucket: $bucketDriver" -ForegroundColor Green
            }
            # Look for process names that might be system drivers
            elseif ($line -match "PROCESS_NAME:\s+(\w+\.sys)") {
                $processName = $Matches[1]
                $crashedDrivers += $processName
                Write-Host "Found process: $processName" -ForegroundColor Green
            }
            # Extract bugcheck parameters that might help identify the issue
            elseif ($line -match "BUGCHECK_P1:\s+([0-9a-fA-F]+)") {
                $metadata["BugcheckParam1"] = "0x" + $Matches[1]
            }
            elseif ($line -match "BUGCHECK_P2:\s+([0-9a-fA-F]+)") {
                $metadata["BugcheckParam2"] = "0x" + $Matches[1]
            }
            elseif ($line -match "BUGCHECK_P3:\s+([0-9a-fA-F]+)") {
                $metadata["BugcheckParam3"] = "0x" + $Matches[1]
            }
            elseif ($line -match "BUGCHECK_P4:\s+([0-9a-fA-F]+)") {
                $metadata["BugcheckParam4"] = "0x" + $Matches[1]
            }
            # Try to extract the timestamp if available
            elseif ($line -match "Debug session time: (.*?)$") {
                $metadata["DebugSessionTime"] = $Matches[1]
            }
        }
        
        # Remove duplicates from crashed drivers list and filter out empty values
        $crashedDrivers = $crashedDrivers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        
        # Update metadata with extracted information
        $metadata["BugcheckCode"] = $bugcheckCode
        $metadata["BugcheckName"] = $bugcheckName
        $metadata["CrashedDrivers"] = $crashedDrivers
        
        # If we couldn't extract the bugcheck name from dumpchk, 
        # we'll try to get it from our knowledge base
        if ($bugcheckCode -ne "Unknown") {
            # Format the bugcheck code consistently to match our knowledge base
            $lookupCode = $bugcheckCode
            if ($bugcheckCode -match "0x([0-9A-Fa-f]+)") {
                $lookupCode = "0x" + $Matches[1]
            }
            
            if ($global:BugcheckKB.PSObject.Properties.Name -contains $lookupCode) {
                $metadata["BugcheckName"] = $global:BugcheckKB.$lookupCode.Name
                Write-Host "Found bugcheck name from knowledge base: $($metadata.BugcheckName)" -ForegroundColor Green
            }
        }
        
        Write-Host "Extracted metadata: Bugcheck $($metadata.BugcheckCode) ($($metadata.BugcheckName)), Found $($crashedDrivers.Count) potential problem drivers" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Error analyzing crash dump with DumpChk: $_"
        # We'll still return the basic metadata
    }
    
    return $metadata
}

# Function to analyze drivers against known bad database
function Find-ProblemDrivers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$CrashMetadata
    )
    
    Write-Host "Analyzing drivers against known issues database..." -ForegroundColor Cyan
    
    # Initialize return array
    $driverResults = @()
    
    try {
        # Get all currently loaded drivers
        Write-Host "Scanning system for currently loaded drivers..." -ForegroundColor Cyan
        $loadedDrivers = Get-WmiObject -Class Win32_SystemDriver -ErrorAction Stop | 
        Where-Object { $_.State -eq "Running" } | 
        Select-Object Name, DisplayName, PathName, Description
        
        if ($null -eq $loadedDrivers) {
            Write-Warning "No loaded drivers were found. This is unusual and may indicate a problem with WMI."
            $loadedDrivers = @()
        }
        
        # First, check the crashed drivers identified in the dump
        # DumpChk might have identified fewer drivers, but we work with what we have
        if ($null -ne $CrashMetadata.CrashedDrivers -and $CrashMetadata.CrashedDrivers.Count -gt 0) {
            foreach ($driver in $CrashMetadata.CrashedDrivers) {
                if ([string]::IsNullOrEmpty($driver)) {
                    continue
                }
                
                Write-Host "Analyzing identified problematic driver: $driver" -ForegroundColor Yellow
                
                # Check if the driver exists in our known bad database
                if ($global:DriversDB.PSObject.Properties.Name -contains $driver) {
                    $knownIssues = $global:DriversDB.$driver
                    
                    # Get the current driver version (if still installed)
                    $driverInfo = $loadedDrivers | Where-Object { $_.Name -eq ($driver -replace '\.sys$', '') -or $_.PathName -like "*\$driver" }
                    $driverVersion = "Unknown"
                    
                    if ($null -ne $driverInfo) {
                        # Try to get driver version from file
                        if ($driverInfo.PathName -and (Test-Path $driverInfo.PathName)) {
                            $driverVersion = (Get-Item $driverInfo.PathName).VersionInfo.FileVersion
                        }
                    }
                    
                    $result = @{
                        "DriverName"     = $driver
                        "VendorName"     = $knownIssues.VendorName
                        "DriverType"     = $knownIssues.DriverType
                        "CurrentVersion" = $driverVersion
                        "IsInstalled"    = ($null -ne $driverInfo)
                        "KnownIssues"    = @()
                    }
                    
                    # Check each known issue for version match
                    if ($null -ne $knownIssues.KnownIssues -and $knownIssues.KnownIssues.Count -gt 0) {
                        foreach ($issue in $knownIssues.KnownIssues) {
                            try {
                                $minVersion = [version]($issue.VersionRange[0])
                                $maxVersion = [version]($issue.VersionRange[1])
                                
                                try {
                                    $currentVer = [version]$driverVersion
                                    $isAffected = ($currentVer -ge $minVersion -and $currentVer -le $maxVersion)
                                    
                                    # Check if the OS is in the affected list
                                    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                                    $osVersion = if ($osInfo) { $osInfo.Caption } else { "Unknown" }
                                    $isOSAffected = $issue.AffectedOS -contains $osVersion -or $issue.AffectedOS -contains "Windows 11"
                                    
                                    $matchResult = @{
                                        "IssueDescription"       = $issue.IssueDescription
                                        "VersionRange"           = $issue.VersionRange -join " to "
                                        "CurrentVersionAffected" = $isAffected
                                        "OSAffected"             = $isOSAffected
                                        "Resolution"             = $issue.Resolution
                                    }
                                    
                                    $result.KnownIssues += $matchResult
                                } 
                                catch {
                                    # Version parsing failed
                                    Write-Warning "Failed to parse driver version: $_"
                                    $result.KnownIssues += @{
                                        "IssueDescription"       = $issue.IssueDescription
                                        "VersionRange"           = $issue.VersionRange -join " to "
                                        "CurrentVersionAffected" = "Unknown (version comparison failed)"
                                        "Resolution"             = $issue.Resolution
                                    }
                                }
                            }
                            catch {
                                Write-Warning "Error processing known issue for driver $driver`: $_"
                            }
                        }
                    }
                    
                    $driverResults += $result
                } 
                else {
                    # Driver not in known bad database
                    $driverInfo = $loadedDrivers | Where-Object { $_.Name -eq ($driver -replace '\.sys$', '') -or $_.PathName -like "*\$driver" }
                    
                    $result = @{
                        "DriverName"     = $driver
                        "VendorName"     = "Unknown"
                        "DriverType"     = "Unknown"
                        "CurrentVersion" = "Unknown"
                        "IsInstalled"    = ($null -ne $driverInfo)
                        "KnownIssues"    = @()
                    }
                    
                    if ($null -ne $driverInfo) {
                        $result.VendorName = if ($driverInfo.Description) { $driverInfo.Description } else { "Unknown" }
                        
                        # Try to get driver version from file
                        if ($driverInfo.PathName -and (Test-Path $driverInfo.PathName)) {
                            $result.CurrentVersion = (Get-Item $driverInfo.PathName).VersionInfo.FileVersion
                        }
                    }
                    
                    $driverResults += $result
                }
            }
        }
        else {
            Write-Warning "No crashed drivers were identified in the dump. This could be due to limitations of dumpchk.exe."
        }
        
        # As dumpchk may not identify all problematic drivers, do a more thorough scan
        # Get all loaded modules that might be related to the bugcheck code
        # We scan all loaded drivers against the known bad database
        Write-Host "Scanning all loaded drivers for potential issues..." -ForegroundColor Cyan
        
        if ($null -ne $loadedDrivers -and $loadedDrivers.Count -gt 0) {
            foreach ($driver in $loadedDrivers) {
                if ($null -eq $driver.PathName -or [string]::IsNullOrEmpty($driver.PathName)) {
                    continue
                }
                
                $driverFileName = Split-Path -Path $driver.PathName -Leaf
                
                # Skip if driver filename is empty
                if ([string]::IsNullOrEmpty($driverFileName)) {
                    continue
                }
                
                # Skip if this driver was already identified in crash dump
                if ($null -ne $CrashMetadata.CrashedDrivers -and $CrashMetadata.CrashedDrivers -contains $driverFileName) {
                    continue
                }
                
                # Check if the driver exists in our known bad database
                if ($global:DriversDB.PSObject.Properties.Name -contains $driverFileName) {
                    Write-Host "Found potentially problematic loaded driver: $driverFileName" -ForegroundColor Yellow
                    
                    $knownIssues = $global:DriversDB.$driverFileName
                    $driverVersion = "Unknown"
                    
                    # Try to get driver version from file
                    if (Test-Path $driver.PathName) {
                        $driverVersion = (Get-Item $driver.PathName).VersionInfo.FileVersion
                    }
                    
                    $result = @{
                        "DriverName"        = $driverFileName
                        "VendorName"        = $knownIssues.VendorName
                        "DriverType"        = $knownIssues.DriverType
                        "CurrentVersion"    = $driverVersion
                        "IsInstalled"       = $true
                        "IdentifiedInCrash" = $false
                        "KnownIssues"       = @()
                    }
                    
                    # Check each known issue for version match
                    if ($null -ne $knownIssues.KnownIssues -and $knownIssues.KnownIssues.Count -gt 0) {
                        foreach ($issue in $knownIssues.KnownIssues) {
                            try {
                                $minVersion = [version]($issue.VersionRange[0])
                                $maxVersion = [version]($issue.VersionRange[1])
                                
                                try {
                                    $currentVer = [version]$driverVersion
                                    $isAffected = ($currentVer -ge $minVersion -and $currentVer -le $maxVersion)
                                    
                                    # Check if the OS is in the affected list
                                    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                                    $osVersion = if ($osInfo) { $osInfo.Caption } else { "Unknown" }
                                    $isOSAffected = $issue.AffectedOS -contains $osVersion -or $issue.AffectedOS -contains "Windows 11"
                                    
                                    $matchResult = @{
                                        "IssueDescription"       = $issue.IssueDescription
                                        "VersionRange"           = $issue.VersionRange -join " to "
                                        "CurrentVersionAffected" = $isAffected
                                        "OSAffected"             = $isOSAffected
                                        "Resolution"             = $issue.Resolution
                                    }
                                    
                                    $result.KnownIssues += $matchResult
                                } 
                                catch {
                                    # Version parsing failed
                                    Write-Warning "Failed to parse driver version: $_"
                                    $result.KnownIssues += @{
                                        "IssueDescription"       = $issue.IssueDescription
                                        "VersionRange"           = $issue.VersionRange -join " to "
                                        "CurrentVersionAffected" = "Unknown (version comparison failed)"
                                        "Resolution"             = $issue.Resolution
                                    }
                                }
                            }
                            catch {
                                Write-Warning "Error processing known issue for driver $driverFileName`: $_"
                            }
                        }
                    }
                    
                    $driverResults += $result
                }
            }
        }
        
        # For bugcheck codes related to specific driver types, add additional warnings
        # This is especially useful with dumpchk which may not identify all problematic drivers
        if ($CrashMetadata.BugcheckCode -ne "Unknown") {
            # For VIDEO_TDR_FAILURE, add warnings for graphics drivers
            if ($CrashMetadata.BugcheckCode -eq "0x00000116" -or $CrashMetadata.BugcheckName -eq "VIDEO_TDR_FAILURE") {
                Write-Host "Bugcheck indicates graphics driver issue, checking all graphics drivers..." -ForegroundColor Yellow
                
                # Check for common graphics drivers that might not have been identified
                $graphicsDrivers = $loadedDrivers | Where-Object { 
                    $_.PathName -like "*nvlddmkm.sys" -or 
                    $_.PathName -like "*atikmpag.sys" -or 
                    $_.PathName -like "*igdkmd64.sys" -or
                    $_.PathName -like "*amdkmdag.sys"
                }
                
                if ($null -ne $graphicsDrivers) {
                    foreach ($gfxDriver in $graphicsDrivers) {
                        if ($null -eq $gfxDriver.PathName -or [string]::IsNullOrEmpty($gfxDriver.PathName)) {
                            continue
                        }
                        
                        $driverFileName = Split-Path -Path $gfxDriver.PathName -Leaf
                        
                        # Skip if already analyzed
                        if ([string]::IsNullOrEmpty($driverFileName) -or ($driverResults | Where-Object { $_.DriverName -eq $driverFileName }).Count -gt 0) {
                            continue
                        }
                        
                        $driverVersion = "Unknown"
                        if (Test-Path $gfxDriver.PathName) {
                            $driverVersion = (Get-Item $gfxDriver.PathName).VersionInfo.FileVersion
                        }
                        
                        $result = @{
                            "DriverName"        = $driverFileName
                            "VendorName"        = if ($gfxDriver.Description) { $gfxDriver.Description } else { "Unknown Graphics Driver" }
                            "DriverType"        = "Graphics Driver"
                            "CurrentVersion"    = $driverVersion
                            "IsInstalled"       = $true
                            "IdentifiedInCrash" = $false
                            "RelatedToBugcheck" = $true
                            "KnownIssues"       = @(
                                @{
                                    "IssueDescription"       = "Possible cause of VIDEO_TDR_FAILURE bugcheck"
                                    "VersionRange"           = "All Versions"
                                    "CurrentVersionAffected" = "Unknown"
                                    "OSAffected"             = $true
                                    "Resolution"             = "Update to the latest graphics driver version from manufacturer website"
                                }
                            )
                        }
                        
                        $driverResults += $result
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Error in Find-ProblemDrivers: $_"
        # Still return an empty array rather than null
    }
    
    if ($driverResults.Count -eq 0) {
        Write-Warning "No problematic drivers were identified. Analysis may be limited."
    }
    else {
        Write-Host "Identified $($driverResults.Count) potential problem drivers." -ForegroundColor Green
    }
    
    return $driverResults
}

# Function to get bugcheck information from the knowledge base
function Get-BugcheckAnalysis {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$CrashMetadata
    )
    
    Write-Host "Analyzing bugcheck code against knowledge base..." -ForegroundColor Cyan
    
    $bugcheckCode = $CrashMetadata.BugcheckCode
    
    # When using dumpchk, we might get a different format bugcheck code
    # Make sure we have the 0x format for consistency
    if ($bugcheckCode -ne "Unknown" -and -not $bugcheckCode.StartsWith("0x")) {
        $bugcheckCode = "0x" + $bugcheckCode
    }
    
    # Extract just the digits if the code starts with 0x
    $lookupCode = $bugcheckCode
    if ($bugcheckCode -match "0x([0-9A-Fa-f]+)") {
        $lookupCode = "0x" + $Matches[1]
    }
    
    if ($global:BugcheckKB.PSObject.Properties.Name -contains $lookupCode) {
        $bugcheckInfo = $global:BugcheckKB.$lookupCode
        
        $analysis = @{
            "BugcheckCode"    = $bugcheckCode
            "BugcheckName"    = $bugcheckInfo.Name
            "Description"     = $bugcheckInfo.Description
            "CommonCauses"    = $bugcheckInfo.CommonCauses
            "Recommendations" = $bugcheckInfo.Recommendations
        }
    } 
    else {
        Write-Warning "Bugcheck code $bugcheckCode not found in knowledge base."
        
        # Try to get name from the metadata if available
        $bugcheckName = $CrashMetadata.BugcheckName
        if ($bugcheckName -eq "Unknown" -and $bugcheckCode -ne "Unknown") {
            # Try looking up common bugcheck codes online or from a local resource
            $commonBugchecks = @{
                "0x0000001E" = "KMODE_EXCEPTION_NOT_HANDLED"
                "0x0000007E" = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"
                "0x00000050" = "PAGE_FAULT_IN_NONPAGED_AREA"
                "0x00000116" = "VIDEO_TDR_FAILURE"
                "0x0000009C" = "MACHINE_CHECK_EXCEPTION"
                "0x0000000A" = "IRQL_NOT_LESS_OR_EQUAL"
                "0x000000D1" = "DRIVER_IRQL_NOT_LESS_OR_EQUAL"
                "0x000000C5" = "DRIVER_CORRUPTED_EXPOOL"
                "0x0000007A" = "KERNEL_DATA_INPAGE_ERROR"
                "0x000000F4" = "CRITICAL_OBJECT_TERMINATION"
            }
            
            if ($commonBugchecks.ContainsKey($lookupCode)) {
                $bugcheckName = $commonBugchecks[$lookupCode]
            }
        }
        
        $analysis = @{
            "BugcheckCode"    = $bugcheckCode
            "BugcheckName"    = $bugcheckName
            "Description"     = "No detailed information available in knowledge base."
            "CommonCauses"    = @("Unknown - not in knowledge base")
            "Recommendations" = @(
                "Search for the bugcheck code online"
                "Check Windows Event Logs for related errors"
                "Run system file integrity check (SFC /scannow)"
                "Check for Windows updates"
            )
        }
        
        # Add specific recommendations based on bugcheck code patterns
        if ($bugcheckCode -ne "Unknown") {
            switch -Regex ($bugcheckCode) {
                "0x0000001E|0x0000007E" {
                    $analysis.CommonCauses += "Likely a driver issue"
                    $analysis.Recommendations += "Update all device drivers, especially recently installed ones"
                }
                "0x00000050|0x0000000A|0x000000D1" {
                    $analysis.CommonCauses += "Possible memory or driver issue"
                    $analysis.Recommendations += "Run Windows Memory Diagnostic"
                }
                "0x00000116" {
                    $analysis.CommonCauses += "Graphics driver issue"
                    $analysis.Recommendations += "Update graphics drivers from manufacturer website"
                    $analysis.Recommendations += "Check for overheating GPU"
                }
                "0x0000009C" {
                    $analysis.CommonCauses += "Hardware issue, possibly CPU or memory"
                    $analysis.Recommendations += "Check system temperatures"
                    $analysis.Recommendations += "Run hardware diagnostics"
                }
            }
        }
    }
    
    return $analysis
}

# Function to create detailed HTML report
function New-AnalysisReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$CrashMetadata,
        
        [Parameter(Mandatory = $true)]
        [array]$DriverAnalysis,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$BugcheckAnalysis,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputFile = (Join-Path -Path $OutputPath -ChildPath "BSOD_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').html")
    )
    
    Write-Host "Generating analysis report..." -ForegroundColor Cyan
    
    try {
        # Ensure output directory exists
        $outputFolder = Split-Path -Path $OutputFile -Parent
        if (-not (Test-Path -Path $outputFolder)) {
            New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
            Write-Host "Created output directory: $outputFolder" -ForegroundColor Green
        }
        
        # Ensure driver analysis is an array
        if ($null -eq $DriverAnalysis) {
            $DriverAnalysis = @()
            Write-Warning "Driver analysis was null, using empty array instead."
        }
        
        # Get system information with error handling
        try {
            $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $systemManufacturer = $systemInfo.Manufacturer
            $systemModel = $systemInfo.Model
        }
        catch {
            Write-Warning "Failed to get system information: $_"
            $systemManufacturer = "Unknown"
            $systemModel = "Unknown"
        }
        
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $osCaption = $osInfo.Caption
            $osVersion = $osInfo.Version
        }
        catch {
            Write-Warning "Failed to get OS information: $_"
            $osCaption = "Unknown Windows Version"
            $osVersion = "Unknown"
        }
        
        $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Create HTML content with CSS styling
        $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BSOD Analysis Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #0066cc;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .summary {
            background-color: #e6f2ff;
            border-left: 5px solid #0066cc;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #0066cc;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .critical {
            background-color: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .notice {
            background-color: #d1ecf1;
            color: #0c5460;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Windows BSOD Root Cause Analysis Report</h1>
        <p>Generated on: $reportDate</p>
"@

        # Add notice if using dumpchk instead of windbg
        $htmlReport += @"
        <div class="notice">
            <p><strong>Note:</strong> This analysis was performed using dumpchk.exe which provides more limited information than WinDbg. 
            Some details may not be available and driver identification may be less precise.</p>
        </div>
"@

        $htmlReport += @"
        <div class="section summary">
            <h2>Analysis Summary</h2>
            <table>
                <tr>
                    <th>Attribute</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Crash Dump File</td>
                    <td>$($CrashMetadata.FileName)</td>
                </tr>
                <tr>
                    <td>Crash Time</td>
                    <td>$($CrashMetadata.CreationTime)</td>
                </tr>
                <tr>
                    <td>Bugcheck Code</td>
                    <td>$($BugcheckAnalysis.BugcheckCode) ($($BugcheckAnalysis.BugcheckName))</td>
                </tr>
                <tr>
                    <td>Primary Cause</td>
                    <td>$($BugcheckAnalysis.Description)</td>
                </tr>
                <tr>
                    <td>System</td>
                    <td>$systemManufacturer $systemModel</td>
                </tr>
                <tr>
                    <td>Operating System</td>
                    <td>$osCaption (Version $osVersion)</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Bugcheck Analysis</h2>
            <h3>$($BugcheckAnalysis.BugcheckCode) - $($BugcheckAnalysis.BugcheckName)</h3>
            <p>$($BugcheckAnalysis.Description)</p>
            
            <h4>Common Causes</h4>
            <ul>
"@

        # Add common causes with null check
        if ($null -ne $BugcheckAnalysis.CommonCauses -and $BugcheckAnalysis.CommonCauses.Count -gt 0) {
            foreach ($cause in $BugcheckAnalysis.CommonCauses) {
                $htmlReport += @"
                <li>$cause</li>
"@
            }
        }
        else {
            $htmlReport += @"
                <li>Unknown - no common causes available</li>
"@
        }

        $htmlReport += @"
            </ul>
            
            <h4>Recommendations</h4>
            <ul>
"@

        # Add recommendations with null check
        if ($null -ne $BugcheckAnalysis.Recommendations -and $BugcheckAnalysis.Recommendations.Count -gt 0) {
            foreach ($recommendation in $BugcheckAnalysis.Recommendations) {
                $htmlReport += @"
                <li>$recommendation</li>
"@
            }
        }
        else {
            $htmlReport += @"
                <li>Research the bugcheck code online for specific recommendations</li>
"@
        }

        $htmlReport += @"
            </ul>
        </div>
        
        <div class="section">
            <h2>Driver Analysis</h2>
"@

        # Check if we found any critical drivers
        $criticalDriversFound = $false
        if ($DriverAnalysis.Count -gt 0) {
            foreach ($driver in $DriverAnalysis) {
                $hasCriticalIssue = $false
                if ($null -ne $driver.KnownIssues) {
                    foreach ($issue in $driver.KnownIssues) {
                        if ($issue.CurrentVersionAffected -eq $true -and $issue.OSAffected -eq $true) {
                            $hasCriticalIssue = $true
                            $criticalDriversFound = $true
                            break
                        }
                    }
                }
                
                $statusClass = if ($hasCriticalIssue) { "critical" } else { "" }
                $identifiedInCrash = if ($null -ne $CrashMetadata.CrashedDrivers -and $CrashMetadata.CrashedDrivers -contains $driver.DriverName) { "Yes (identified in crash dump)" } else { "No" }
                
                $htmlReport += @"
            <div class="section $statusClass">
                <h3>Driver: $($driver.DriverName)</h3>
                <table>
                    <tr>
                        <th>Attribute</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Vendor</td>
                        <td>$($driver.VendorName)</td>
                    </tr>
                    <tr>
                        <td>Driver Type</td>
                        <td>$($driver.DriverType)</td>
                    </tr>
                    <tr>
                        <td>Current Version</td>
                        <td>$($driver.CurrentVersion)</td>
                    </tr>
                    <tr>
                        <td>Currently Installed</td>
                        <td>$($driver.IsInstalled)</td>
                    </tr>
                    <tr>
                        <td>Identified In Crash</td>
                        <td>$identifiedInCrash</td>
                    </tr>
"@

                # Add "Related To Bugcheck" row if that property exists
                if ($driver.PSObject.Properties.Name -contains "RelatedToBugcheck") {
                    $htmlReport += @"
                    <tr>
                        <td>Related To Bugcheck</td>
                        <td>$($driver.RelatedToBugcheck)</td>
                    </tr>
"@
                }

                $htmlReport += @"
                </table>
"@

                if ($null -ne $driver.KnownIssues -and $driver.KnownIssues.Count -gt 0) {
                    $htmlReport += @"
                <h4>Known Issues</h4>
                <table>
                    <tr>
                        <th>Issue Description</th>
                        <th>Affected Versions</th>
                        <th>Current Version Affected</th>
                        <th>Resolution</th>
                    </tr>
"@
                    
                    foreach ($issue in $driver.KnownIssues) {
                        $issueClass = if ($issue.CurrentVersionAffected -eq $true -and $issue.OSAffected -eq $true) { "critical" } elseif ($issue.CurrentVersionAffected -eq $true) { "warning" } else { "" }
                        
                        $htmlReport += @"
                    <tr class="$issueClass">
                        <td>$($issue.IssueDescription)</td>
                        <td>$($issue.VersionRange)</td>
                        <td>$($issue.CurrentVersionAffected)</td>
                        <td>$($issue.Resolution)</td>
                    </tr>
"@
                    }
                    
                    $htmlReport += @"
                </table>
"@
                }
                else {
                    $htmlReport += @"
                <p>No known issues found for this driver in the database.</p>
"@
                }
                
                $htmlReport += @"
            </div>
"@
            }
        }
        else {
            $htmlReport += @"
            <div class="warning">
                <p>No drivers were analyzed. This could be due to limitations in analyzing this dump file with dumpchk.exe.</p>
            </div>
"@
        }

        if (-not $criticalDriversFound -and $DriverAnalysis.Count -gt 0) {
            $htmlReport += @"
            <div class="success">
                <p>No critical driver issues were found that match the specific BSOD pattern. Consider checking the recommendations for the bugcheck code.</p>
            </div>
"@
        }

        $htmlReport += @"
        </div>
        
        <div class="section">
            <h2>System Event Log Analysis</h2>
"@

        # Get relevant system events around the crash time with error handling
        try {
            $crashTime = $CrashMetadata.CreationTime
            $eventTimeStart = $crashTime.AddMinutes(-30)
            $eventTimeEnd = $crashTime.AddMinutes(5)

            $relevantEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Level     = 1, 2, 3  # Error, Warning, Information
                StartTime = $eventTimeStart
                EndTime   = $eventTimeEnd
            } -MaxEvents 50 -ErrorAction SilentlyContinue | 
            Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName

            if ($null -ne $relevantEvents -and $relevantEvents.Count -gt 0) {
                $htmlReport += @"
            <p>Found $(($relevantEvents | Measure-Object).Count) relevant events in the System Event Log around the time of the crash.</p>
            <table>
                <tr>
                    <th>Time</th>
                    <th>EventID</th>
                    <th>Level</th>
                    <th>Provider</th>
                    <th>Message</th>
                </tr>
"@
                
                foreach ($event in $relevantEvents) {
                    $levelClass = switch ($event.LevelDisplayName) {
                        "Error" { "critical" }
                        "Warning" { "warning" }
                        default { "" }
                    }
                    
                    # Truncate very long messages and ensure message is not null
                    $message = if ($null -ne $event.Message) { $event.Message } else { "No message" }
                    if ($message.Length -gt 200) {
                        $message = $message.Substring(0, 200) + "..."
                    }
                    
                    $htmlReport += @"
                <tr class="$levelClass">
                    <td>$($event.TimeCreated)</td>
                    <td>$($event.Id)</td>
                    <td>$($event.LevelDisplayName)</td>
                    <td>$($event.ProviderName)</td>
                    <td>$([System.Web.HttpUtility]::HtmlEncode($message))</td>
                </tr>
"@
                }
                
                $htmlReport += @"
            </table>
"@
            }
            else {
                $htmlReport += @"
            <p>No relevant System Event Log entries found around the time of the crash.</p>
"@
            }
        }
        catch {
            $htmlReport += @"
            <div class="warning">
                <p>Failed to retrieve System Event Log entries: $_</p>
            </div>
"@
        }

        $htmlReport += @"
        </div>
        
        <div class="section">
            <h2>Next Steps and Recommendations</h2>
            <ol>
"@

        # Add dynamic recommendations based on analysis findings
        if ($criticalDriversFound) {
            $htmlReport += @"
                <li class="critical">Update the following drivers identified with known issues:
                    <ul>
"@
            
            foreach ($driver in $DriverAnalysis) {
                $hasCriticalIssue = $false
                $resolutions = @()
                
                if ($null -ne $driver.KnownIssues) {
                    foreach ($issue in $driver.KnownIssues) {
                        if ($issue.CurrentVersionAffected -eq $true -and $issue.OSAffected -eq $true) {
                            $hasCriticalIssue = $true
                            $resolutions += $issue.Resolution
                        }
                    }
                }
                
                if ($hasCriticalIssue) {
                    $resolutionsText = ($resolutions | Select-Object -Unique) -join " or "
                    $htmlReport += @"
                        <li>$($driver.DriverName) ($($driver.VendorName)) - $resolutionsText</li>
"@
                }
            }
            
            $htmlReport += @"
                    </ul>
                </li>
"@
        }

        # Add standard recommendations based on the bugcheck code
        $htmlReport += @"
                <li>Follow the specific recommendations for bugcheck $($BugcheckAnalysis.BugcheckCode):</li>
                <ul>
"@

        if ($null -ne $BugcheckAnalysis.Recommendations -and $BugcheckAnalysis.Recommendations.Count -gt 0) {
            foreach ($recommendation in $BugcheckAnalysis.Recommendations) {
                $htmlReport += @"
                    <li>$recommendation</li>
"@
            }
        }
        else {
            $htmlReport += @"
                    <li>Research this bugcheck code online for specific guidance</li>
"@
        }

        $htmlReport += @"
                </ul>
                <li>Run a full system hardware diagnostic to check for memory and disk issues.</li>
                <li>Check system temperatures to ensure proper cooling.</li>
                <li>Run System File Checker: <code>sfc /scannow</code></li>
                <li>Check for Windows updates: <code>Start > Settings > Windows Update</code></li>
                <li>If problems persist, consider creating a complete memory dump for more detailed analysis.</li>
            </ol>
        </div>
    </div>
</body>
</html>
"@

        # Write the HTML report to a file
        $htmlReport | Out-File -FilePath $OutputFile -Encoding utf8 -Force
        Write-Host "Analysis report generated: $OutputFile" -ForegroundColor Green
        
        return $OutputFile
    }
    catch {
        Write-Error "Error generating HTML report: $_"
        
        # Create a minimal HTML report as fallback
        try {
            $fallbackFile = Join-Path -Path $OutputPath -ChildPath "BSOD_Analysis_Basic_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            @"
<!DOCTYPE html>
<html>
<head><title>BSOD Analysis - Error</title></head>
<body>
    <h1>Error Generating Full Report</h1>
    <p>An error occurred while generating the full HTML report: $([System.Web.HttpUtility]::HtmlEncode($_))</p>
    <h2>Basic Information</h2>
    <p>Bugcheck Code: $($BugcheckAnalysis.BugcheckCode)</p>
    <p>Bugcheck Name: $($BugcheckAnalysis.BugcheckName)</p>
    <p>Generated: $(Get-Date)</p>
</body>
</html>
"@ | Out-File -FilePath $fallbackFile -Encoding utf8 -Force
            
            Write-Warning "Created basic HTML report instead: $fallbackFile"
            return $fallbackFile
        }
        catch {
            Write-Error "Failed to create even basic HTML report: $_"
            return $null
        }
    }
}

# Function to extract data for a PowerShell or JSON report
function Get-AnalysisData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$CrashMetadata,
        
        [Parameter(Mandatory = $true)]
        [array]$DriverAnalysis,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$BugcheckAnalysis
    )
    
    try {
        # Get system information
        $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        
        # Initialize with default values
        $systemInfoData = @{
            "Manufacturer" = "Unknown"
            "Model"        = "Unknown"
            "OSName"       = "Unknown"
            "OSVersion"    = "Unknown"
            "OSBuild"      = "Unknown"
        }
        
        # Update with actual values if available
        if ($null -ne $systemInfo) {
            $systemInfoData["Manufacturer"] = $systemInfo.Manufacturer
            $systemInfoData["Model"] = $systemInfo.Model
        }
        
        if ($null -ne $osInfo) {
            $systemInfoData["OSName"] = $osInfo.Caption
            $systemInfoData["OSVersion"] = $osInfo.Version
            $systemInfoData["OSBuild"] = $osInfo.BuildNumber
        }
        
        # Ensure driver analysis is an array, not null
        if ($null -eq $DriverAnalysis) {
            $DriverAnalysis = @()
        }
        
        # Create a structured data object
        $analysisData = @{
            "GeneratedOn"      = Get-Date
            "SystemInfo"       = $systemInfoData
            "CrashInfo"        = @{
                "DumpFile"     = $CrashMetadata.FileName
                "CrashTime"    = $CrashMetadata.CreationTime
                "BugcheckCode" = $BugcheckAnalysis.BugcheckCode
                "BugcheckName" = $BugcheckAnalysis.BugcheckName
                "Description"  = $BugcheckAnalysis.Description
            }
            "BugcheckAnalysis" = $BugcheckAnalysis
            "DriverAnalysis"   = $DriverAnalysis
        }
        
        # Include bugcheck parameters if they exist
        if ($CrashMetadata.ContainsKey("BugcheckParam1")) {
            $analysisData.CrashInfo["BugcheckParam1"] = $CrashMetadata.BugcheckParam1
        }
        if ($CrashMetadata.ContainsKey("BugcheckParam2")) {
            $analysisData.CrashInfo["BugcheckParam2"] = $CrashMetadata.BugcheckParam2
        }
        if ($CrashMetadata.ContainsKey("BugcheckParam3")) {
            $analysisData.CrashInfo["BugcheckParam3"] = $CrashMetadata.BugcheckParam3
        }
        if ($CrashMetadata.ContainsKey("BugcheckParam4")) {
            $analysisData.CrashInfo["BugcheckParam4"] = $CrashMetadata.BugcheckParam4
        }
        
        Write-Host "Generated analysis data successfully." -ForegroundColor Green
        return $analysisData
    }
    catch {
        Write-Error "Error in Get-AnalysisData: $_"
        # Return a minimal structure to avoid null returns
        return @{
            "GeneratedOn"    = Get-Date
            "Error"          = "Failed to generate complete analysis: $_"
            "CrashInfo"      = @{
                "DumpFile"     = if ($CrashMetadata -and $CrashMetadata.FileName) { $CrashMetadata.FileName } else { "Unknown" }
                "BugcheckCode" = if ($BugcheckAnalysis -and $BugcheckAnalysis.BugcheckCode) { $BugcheckAnalysis.BugcheckCode } else { "Unknown" }
            }
            "DriverAnalysis" = if ($null -ne $DriverAnalysis) { $DriverAnalysis } else { @() }
        }
    }
}

# Function to export data to JSON for programmatic use
function Export-AnalysisToJSON {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$AnalysisData,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputFile = (Join-Path -Path $OutputPath -ChildPath "BSOD_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json")
    )
    
    try {
        # Ensure the output folder exists
        $outputFolder = Split-Path -Path $OutputFile -Parent
        if (-not (Test-Path -Path $outputFolder)) {
            New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
            Write-Host "Created output directory: $outputFolder" -ForegroundColor Green
        }
        
        # If AnalysisData is null or empty, create a minimal structure
        if ($null -eq $AnalysisData -or $AnalysisData.Count -eq 0) {
            Write-Warning "Analysis data is empty or null. Creating minimal JSON structure."
            $AnalysisData = @{
                "GeneratedOn"    = Get-Date
                "Error"          = "No analysis data was available"
                "CrashInfo"      = @{
                    "BugcheckCode" = "Unknown"
                    "BugcheckName" = "Unknown"
                }
                "DriverAnalysis" = @()
            }
        }
        
        # Convert to JSON with error handling for maximum depth
        try {
            $jsonContent = $AnalysisData | ConvertTo-Json -Depth 10 -ErrorAction Stop
        }
        catch {
            Write-Warning "Error converting to JSON with depth 10: $_"
            Write-Host "Trying with reduced depth..." -ForegroundColor Yellow
            # Try with reduced depth
            $jsonContent = $AnalysisData | ConvertTo-Json -Depth 5 -ErrorAction Stop
        }
        
        # Write the JSON to a file
        $jsonContent | Out-File -FilePath $OutputFile -Encoding utf8 -Force
        Write-Host "Analysis data exported to JSON: $OutputFile" -ForegroundColor Green
        
        return $OutputFile
    }
    catch {
        Write-Error "Error in Export-AnalysisToJSON: $_"
        
        # Try to write a basic JSON file as fallback
        try {
            $fallbackFile = Join-Path -Path $OutputPath -ChildPath "BSOD_Analysis_Fallback_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            @{ "Error" = "Failed to export full analysis: $_"; "GeneratedOn" = (Get-Date).ToString() } | 
            ConvertTo-Json | 
            Out-File -FilePath $fallbackFile -Encoding utf8 -Force
            
            Write-Warning "Created fallback JSON file: $fallbackFile"
            return $fallbackFile
        }
        catch {
            Write-Error "Failed to create even fallback JSON file: $_"
            return $null
        }
    }
}

# Main function to run the analysis
function Start-BSODAnalysis {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TargetDumpFile,
        
        [Parameter(Mandatory = $false)]
        [switch]$PromptForDebuggerInstall = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$GenerateReport = $true
    )
    
    Write-Host "==== Windows BSOD Root Cause Triage Tool ====" -ForegroundColor Cyan
    Write-Host "Starting analysis at $(Get-Date)" -ForegroundColor Cyan
    
    # Initialize variables with defaults to avoid null reference issues
    $crashMetadata = $null
    $bugcheckAnalysis = $null
    $driverAnalysis = @()
    $analysisData = $null
    
    # Initialize environment and databases
    Initialize-Environment
    
    # Get the crash dump to analyze
    if ([string]::IsNullOrEmpty($TargetDumpFile)) {
        $dumpFile = Get-LatestCrashDump
        if ($null -eq $dumpFile) {
            Write-Error "No crash dump files found to analyze. Exiting."
            return
        }
    }
    else {
        if (-not (Test-Path -Path $TargetDumpFile)) {
            Write-Error "Specified dump file not found: $TargetDumpFile"
            return
        }
        $dumpFile = $TargetDumpFile
    }
    
    # Validate the dump file using dumpchk first
    $dumpFileValid = $true
    if ($global:DebuggerAvailable) {
        Write-Host "Validating crash dump file integrity..." -ForegroundColor Cyan
        $validationOutput = & $global:DumpChkPath $dumpFile
    
        if ($validationOutput -join " " -match "DebugClient cannot open DumpFile|invalid file format|corrupt") {
            Write-Warning "The dump file appears to be corrupt or invalid. Analysis may be incomplete or inaccurate."
            $dumpFileValid = $false
            # We'll still try to proceed with limited analysis
        }
        else {
            Write-Host "Dump file validation successful." -ForegroundColor Green
        }
    }
    
    # Extract metadata from the crash dump
    try {
        $crashMetadata = Get-CrashDumpMetadata -DumpFile $dumpFile
        if ($null -eq $crashMetadata) {
            Write-Error "Failed to extract metadata from crash dump."
            return
        }
    }
    catch {
        Write-Error "Error extracting crash dump metadata: $_"
        # Create minimal metadata to avoid null reference exceptions
        $crashMetadata = @{
            "DumpFile"       = $dumpFile
            "FileName"       = (Split-Path -Path $dumpFile -Leaf)
            "CreationTime"   = (Get-Item -Path $dumpFile).LastWriteTime
            "FileSize"       = (Get-Item -Path $dumpFile).Length
            "BugcheckCode"   = "Unknown (extraction error)"
            "BugcheckName"   = "Unknown (extraction error)"
            "CrashedDrivers" = @()
        }
    }
    
    # Analyze bugcheck code
    try {
        $bugcheckAnalysis = Get-BugcheckAnalysis -CrashMetadata $crashMetadata
        if ($null -eq $bugcheckAnalysis) {
            Write-Warning "Failed to analyze bugcheck code. Using default analysis."
            $bugcheckAnalysis = @{
                "BugcheckCode"    = $crashMetadata.BugcheckCode
                "BugcheckName"    = $crashMetadata.BugcheckName
                "Description"     = "Analysis failed - no details available."
                "CommonCauses"    = @("Unknown - analysis failed")
                "Recommendations" = @("Search for the bugcheck code online", "Run system diagnostics")
            }
        }
    }
    catch {
        Write-Error "Error analyzing bugcheck code: $_"
        $bugcheckAnalysis = @{
            "BugcheckCode"    = $crashMetadata.BugcheckCode
            "BugcheckName"    = $crashMetadata.BugcheckName
            "Description"     = "Analysis failed - no details available."
            "CommonCauses"    = @("Unknown - analysis failed")
            "Recommendations" = @("Search for the bugcheck code online", "Run system diagnostics")
        }
    }
    
    # Find and analyze problematic drivers
    try {
        $driverAnalysis = Find-ProblemDrivers -CrashMetadata $crashMetadata
        if ($null -eq $driverAnalysis) {
            Write-Warning "Driver analysis returned no results. Using empty driver list."
            $driverAnalysis = @()
        }
    }
    catch {
        Write-Error "Error analyzing driver information: $_"
        $driverAnalysis = @()
    }
    
    # Generate the complete analysis data
    try {
        $analysisData = Get-AnalysisData -CrashMetadata $crashMetadata -DriverAnalysis $driverAnalysis -BugcheckAnalysis $bugcheckAnalysis
    }
    catch {
        Write-Error "Error generating analysis data: $_"
        # Create minimal analysis data
        $analysisData = @{
            "GeneratedOn"    = Get-Date
            "CrashInfo"      = @{
                "DumpFile"     = $crashMetadata.FileName
                "CrashTime"    = $crashMetadata.CreationTime
                "BugcheckCode" = $bugcheckAnalysis.BugcheckCode
                "BugcheckName" = $bugcheckAnalysis.BugcheckName
            }
            "DriverAnalysis" = $driverAnalysis
        }
    }
    
    # Export the data to JSON for programmatic use
    try {
        $jsonFile = Export-AnalysisToJSON -AnalysisData $analysisData
    }
    catch {
        Write-Error "Error exporting analysis to JSON: $_"
    }
    
    # Generate an HTML report if requested
    if ($GenerateReport) {
        try {
            $reportFile = New-AnalysisReport -CrashMetadata $crashMetadata -DriverAnalysis $driverAnalysis -BugcheckAnalysis $bugcheckAnalysis
    
            # Try to open the report in the default browser
            try {
                Start-Process $reportFile
            }
            catch {
                Write-Warning "Could not open the HTML report automatically. Please open manually: $reportFile"
            }
        }
        catch {
            Write-Error "Error generating HTML report: $_"
        }
    }
    
    Write-Host "==== Analysis Complete ====" -ForegroundColor Cyan
    Write-Host "Results saved to: $OutputPath" -ForegroundColor Green
    
    return $analysisData
}

# Run the analysis when the script is executed
Start-BSODAnalysis
