# Windows BSOD Root Cause Triage Tool
# Author: Principal Systems Development Engineer
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
    
    # Check if the Debugging Tools for Windows are installed
    $winDbgPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots" -Name "KitsRoot10" -ErrorAction SilentlyContinue
    
    if ($null -eq $winDbgPath) {
        Write-Warning "Windows Debugging Tools not found. Some functionality may be limited."
        $global:DebuggerAvailable = $false
    } else {
        $debuggerPath = Join-Path -Path $winDbgPath.KitsRoot10 -ChildPath "Debuggers\x64\kd.exe"
        if (Test-Path $debuggerPath) {
            $global:DebuggerPath = $debuggerPath
            $global:DebuggerAvailable = $true
            Write-Host "Windows Debugger found at: $debuggerPath" -ForegroundColor Green
        } else {
            Write-Warning "Windows Debugger (kd.exe) not found at expected location. Some functionality may be limited."
            $global:DebuggerAvailable = $false
        }
    }
    
    # Initialize or load bugcheck knowledge base
    if (-not (Test-Path -Path $KnowledgeBasePath)) {
        Write-Host "Bugcheck knowledge base not found. Creating sample knowledge base..." -ForegroundColor Yellow
        Initialize-BugcheckKnowledgeBase
    } else {
        Write-Host "Loading existing bugcheck knowledge base..." -ForegroundColor Green
        $global:BugcheckKB = Get-Content -Path $KnowledgeBasePath -Raw | ConvertFrom-Json
    }
    
    # Initialize or load drivers database
    if (-not (Test-Path -Path $DriversDBPath)) {
        Write-Host "Known bad drivers database not found. Creating sample database..." -ForegroundColor Yellow
        Initialize-DriversDatabase
    } else {
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
            "Name" = "KMODE_EXCEPTION_NOT_HANDLED"
            "Description" = "A kernel-mode program generated an exception which the error handler did not catch."
            "CommonCauses" = @(
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
            "Name" = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"
            "Description" = "A system thread generated an exception that the error handler did not catch."
            "CommonCauses" = @(
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
            "Name" = "PAGE_FAULT_IN_NONPAGED_AREA"
            "Description" = "Memory corruption in the nonpaged area of memory, often indicating hardware issues."
            "CommonCauses" = @(
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
            "Name" = "VIDEO_TDR_FAILURE"
            "Description" = "The display driver failed to respond in a timely fashion. Usually occurs when the GPU hangs."
            "CommonCauses" = @(
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
            "Name" = "MACHINE_CHECK_EXCEPTION"
            "Description" = "Hardware reported a fatal error to the CPU, usually indicating CPU, memory or power issues."
            "CommonCauses" = @(
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
            "VendorName" = "NVIDIA Corporation"
            "DriverType" = "Display Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange" = @("456.71", "460.89")
                    "IssueDescription" = "May cause SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7E) when entering sleep mode"
                    "Resolution" = "Update to version 461.09 or later"
                    "AffectedOS" = @("Windows 10", "Windows 11")
                },
                @{
                    "VersionRange" = @("471.11", "471.41")
                    "IssueDescription" = "Can trigger VIDEO_TDR_FAILURE (0x116) with certain applications"
                    "Resolution" = "Update to version 472.12 or later"
                    "AffectedOS" = @("Windows 11")
                }
            )
        }
        "iastor.sys" = @{
            "VendorName" = "Intel Corporation"
            "DriverType" = "Storage Controller Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange" = @("11.2.0.1006", "11.2.0.1032")
                    "IssueDescription" = "Can cause KERNEL_DATA_INPAGE_ERROR (0x7A) when using NVMe storage"
                    "Resolution" = "Update to Intel Rapid Storage Technology version 11.2.0.1033 or later"
                    "AffectedOS" = @("Windows 10", "Windows 11")
                }
            )
        }
        "rtkvhd64.sys" = @{
            "VendorName" = "Realtek Semiconductor Corp."
            "DriverType" = "Audio Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange" = @("6.0.9107.1", "6.0.9107.5")
                    "IssueDescription" = "May cause DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1) on wake from sleep"
                    "Resolution" = "Update to version 6.0.9107.6 or later"
                    "AffectedOS" = @("Windows 11")
                }
            )
        }
        "atikmpag.sys" = @{
            "VendorName" = "AMD Inc."
            "DriverType" = "Display Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange" = @("27.20.21001.14001", "27.20.21003.8013")
                    "IssueDescription" = "Can trigger VIDEO_TDR_FAILURE (0x116) with power state transitions"
                    "Resolution" = "Update to Adrenalin version 21.3.1 or later"
                    "AffectedOS" = @("Windows 10", "Windows 11")
                }
            )
        }
        "asmtxhci.sys" = @{
            "VendorName" = "ASMedia Technology Inc."
            "DriverType" = "USB Controller Driver"
            "KnownIssues" = @(
                @{
                    "VersionRange" = @("1.16.51.1", "1.16.55.1")
                    "IssueDescription" = "Can cause SYSTEM_SERVICE_EXCEPTION (0x3B) when transferring large files"
                    "Resolution" = "Update to version 1.16.56.1 or later or use Microsoft inbox driver"
                    "AffectedOS" = @("Windows 10", "Windows 11")
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
    
    if (-not $global:DebuggerAvailable) {
        Write-Warning "Windows Debugger not available. Limited metadata extraction only."
        
        $metadata = @{
            "DumpFile" = $DumpFile
            "FileName" = (Split-Path -Path $DumpFile -Leaf)
            "CreationTime" = (Get-Item -Path $DumpFile).LastWriteTime
            "FileSize" = (Get-Item -Path $DumpFile).Length
            "BugcheckCode" = "Unknown (debugger not available)"
            "BugcheckName" = "Unknown (debugger not available)"
            "CrashedDrivers" = @()
        }
        
        # Try to extract minimal information from the dump file name
        if ($metadata.FileName -match "(\d{8}-\d+)") {
            $metadata["CrashTime"] = $Matches[1]
        }
        
        return $metadata
    }
    
    # Create a temporary file for debugger commands
    $debugCmdsFile = [System.IO.Path]::GetTempFileName()
    $analyzeCmds = @(
        ".symfix"
        ".reload"
        "!analyze -v"
        "lm t n"
        "!for_each_module .echo @#ModuleName @#Base @#End @#ImageSize @#LoadedImageName @#ImageName"
        "q"
    )
    
    $analyzeCmds | Out-File -FilePath $debugCmdsFile -Encoding ascii
    
    # Run the debugger commands
    $debugOutput = & $global:DebuggerPath -z $DumpFile -c "`"$$<$debugCmdsFile`""
    Remove-Item -Path $debugCmdsFile -Force
    
    # Extract bugcheck information
    $bugcheckCode = "Unknown"
    $bugcheckName = "Unknown"
    $crashedDrivers = @()
    
    foreach ($line in $debugOutput) {
        # Extract bugcheck code and name
        if ($line -match "BUGCHECK_CODE:\s+([0-9a-fA-F]+)") {
            $bugcheckCode = "0x" + $Matches[1]
        }
        elseif ($line -match "BUGCHECK_STR:\s+(.+)") {
            $bugcheckName = $Matches[1].Trim()
        }
        
        # Look for probable causes
        if ($line -match "Probably caused by\s*:\s*(.+)") {
            $probableCause = $Matches[1].Trim()
            
            # Extract driver names (typical format is "driver_name.sys")
            if ($probableCause -match "(\w+\.sys)") {
                $crashedDrivers += $Matches[1]
            }
        }
        
        # Alternate method to find faulty drivers - look for modules flagged in analyze output
        if ($line -match "IMAGE_NAME:\s+(\w+\.sys)") {
            $driverName = $Matches[1]
            
            # Check next few lines for fault indications
            $nextIndex = $debugOutput.IndexOf($line) + 1
            $checkLines = 10  # Check next 10 lines
            
            for ($i = $nextIndex; $i -lt ($nextIndex + $checkLines) -and $i -lt $debugOutput.Count; $i++) {
                if ($debugOutput[$i] -match "FAULTING_MODULE") {
                    $crashedDrivers += $driverName
                    break
                }
            }
        }
    }
    
    # Remove duplicates from crashed drivers list
    $crashedDrivers = $crashedDrivers | Select-Object -Unique
    
    $metadata = @{
        "DumpFile" = $DumpFile
        "FileName" = (Split-Path -Path $DumpFile -Leaf)
        "CreationTime" = (Get-Item -Path $DumpFile).LastWriteTime
        "FileSize" = (Get-Item -Path $DumpFile).Length
        "BugcheckCode" = $bugcheckCode
        "BugcheckName" = $bugcheckName
        "CrashedDrivers" = $crashedDrivers
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
    
    # Get all currently loaded drivers
    Write-Host "Scanning system for currently loaded drivers..." -ForegroundColor Cyan
    $loadedDrivers = Get-WmiObject -Class Win32_SystemDriver | 
                    Where-Object { $_.State -eq "Running" } | 
                    Select-Object Name, DisplayName, PathName, Description
    
    $driverResults = @()
    
    # First, check the crashed drivers identified in the dump
    foreach ($driver in $CrashMetadata.CrashedDrivers) {
        Write-Host "Analyzing identified problematic driver: $driver" -ForegroundColor Yellow
        
        # Check if the driver exists in our known bad database
        if ($global:DriversDB.PSObject.Properties.Name -contains $driver) {
            $knownIssues = $global:DriversDB.$driver
            
            # Get the current driver version (if still installed)
            $driverInfo = $loadedDrivers | Where-Object { $_.Name -eq ($driver -replace '\.sys$', '') -or $_.PathName -like "*\$driver" }
            $driverVersion = "Unknown"
            
            if ($null -ne $driverInfo) {
                # Try to get driver version from file
                if (Test-Path $driverInfo.PathName) {
                    $driverVersion = (Get-Item $driverInfo.PathName).VersionInfo.FileVersion
                }
            }
            
            $result = @{
                "DriverName" = $driver
                "VendorName" = $knownIssues.VendorName
                "DriverType" = $knownIssues.DriverType
                "CurrentVersion" = $driverVersion
                "IsInstalled" = ($null -ne $driverInfo)
                "KnownIssues" = @()
            }
            
            # Check each known issue for version match
            foreach ($issue in $knownIssues.KnownIssues) {
                $minVersion = [version]($issue.VersionRange[0])
                $maxVersion = [version]($issue.VersionRange[1])
                
                try {
                    $currentVer = [version]$driverVersion
                    $isAffected = ($currentVer -ge $minVersion -and $currentVer -le $maxVersion)
                    
                    # Check if the OS is in the affected list
                    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
                    $osVersion = $osInfo.Caption
                    $isOSAffected = $issue.AffectedOS -contains $osVersion -or $issue.AffectedOS -contains "Windows 11"
                    
                    $matchResult = @{
                        "IssueDescription" = $issue.IssueDescription
                        "VersionRange" = $issue.VersionRange -join " to "
                        "CurrentVersionAffected" = $isAffected
                        "OSAffected" = $isOSAffected
                        "Resolution" = $issue.Resolution
                    }
                    
                    $result.KnownIssues += $matchResult
                } 
                catch {
                    # Version parsing failed
                    $result.KnownIssues += @{
                        "IssueDescription" = $issue.IssueDescription
                        "VersionRange" = $issue.VersionRange -join " to "
                        "CurrentVersionAffected" = "Unknown (version comparison failed)"
                        "Resolution" = $issue.Resolution
                    }
                }
            }
            
            $driverResults += $result
        } 
        else {
            # Driver not in known bad database
            $driverInfo = $loadedDrivers | Where-Object { $_.Name -eq ($driver -replace '\.sys$', '') -or $_.PathName -like "*\$driver" }
            
            $result = @{
                "DriverName" = $driver
                "VendorName" = "Unknown"
                "DriverType" = "Unknown"
                "CurrentVersion" = "Unknown"
                "IsInstalled" = ($null -ne $driverInfo)
                "KnownIssues" = @()
            }
            
            if ($null -ne $driverInfo) {
                $result.VendorName = if ($driverInfo.Description) { $driverInfo.Description } else { "Unknown" }
                
                # Try to get driver version from file
                if (Test-Path $driverInfo.PathName) {
                    $result.CurrentVersion = (Get-Item $driverInfo.PathName).VersionInfo.FileVersion
                }
            }
            
            $driverResults += $result
        }
    }
    
    # Also scan all loaded drivers against the known bad database
    Write-Host "Scanning all loaded drivers for potential issues..." -ForegroundColor Cyan
    
    foreach ($driver in $loadedDrivers) {
        $driverFileName = Split-Path -Path $driver.PathName -Leaf
        
        # Skip if this driver was already identified in crash dump
        if ($CrashMetadata.CrashedDrivers -contains $driverFileName) {
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
                "DriverName" = $driverFileName
                "VendorName" = $knownIssues.VendorName
                "DriverType" = $knownIssues.DriverType
                "CurrentVersion" = $driverVersion
                "IsInstalled" = $true
                "IdentifiedInCrash" = $false
                "KnownIssues" = @()
            }
            
            # Check each known issue for version match
            foreach ($issue in $knownIssues.KnownIssues) {
                $minVersion = [version]($issue.VersionRange[0])
                $maxVersion = [version]($issue.VersionRange[1])
                
                try {
                    $currentVer = [version]$driverVersion
                    $isAffected = ($currentVer -ge $minVersion -and $currentVer -le $maxVersion)
                    
                    # Check if the OS is in the affected list
                    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
                    $osVersion = $osInfo.Caption
                    $isOSAffected = $issue.AffectedOS -contains $osVersion -or $issue.AffectedOS -contains "Windows 11"
                    
                    $matchResult = @{
                        "IssueDescription" = $issue.IssueDescription
                        "VersionRange" = $issue.VersionRange -join " to "
                        "CurrentVersionAffected" = $isAffected
                        "OSAffected" = $isOSAffected
                        "Resolution" = $issue.Resolution
                    }
                    
                    $result.KnownIssues += $matchResult
                } 
                catch {
                    # Version parsing failed
                    $result.KnownIssues += @{
                        "IssueDescription" = $issue.IssueDescription
                        "VersionRange" = $issue.VersionRange -join " to "
                        "CurrentVersionAffected" = "Unknown (version comparison failed)"
                        "Resolution" = $issue.Resolution
                    }
                }
            }
            
            $driverResults += $result
        }
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
    
    if ($global:BugcheckKB.PSObject.Properties.Name -contains $bugcheckCode) {
        $bugcheckInfo = $global:BugcheckKB.$bugcheckCode
        
        $analysis = @{
            "BugcheckCode" = $bugcheckCode
            "BugcheckName" = $bugcheckInfo.Name
            "Description" = $bugcheckInfo.Description
            "CommonCauses" = $bugcheckInfo.CommonCauses
            "Recommendations" = $bugcheckInfo.Recommendations
        }
    } 
    else {
        Write-Warning "Bugcheck code $bugcheckCode not found in knowledge base."
        
        $analysis = @{
            "BugcheckCode" = $bugcheckCode
            "BugcheckName" = $CrashMetadata.BugcheckName
            "Description" = "No detailed information available in knowledge base."
            "CommonCauses" = @("Unknown - not in knowledge base")
            "Recommendations" = @(
                "Search for the bugcheck code online"
                "Check Windows Event Logs for related errors"
                "Run system file integrity check (SFC /scannow)"
                "Check for Windows updates"
            )
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
    
    # Get system information
    $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Create HTML content
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
    </style>
</head>
<body>
    <div class="container">
        <h1>Windows BSOD Root Cause Analysis Report</h1>
        <p>Generated on: $reportDate</p>
        
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
                    <td>$($systemInfo.Manufacturer) $($systemInfo.Model)</td>
                </tr>
                <tr>
                    <td>Operating System</td>
                    <td>$($osInfo.Caption) (Version $($osInfo.Version))</td>
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

foreach ($cause in $BugcheckAnalysis.CommonCauses) {
    $htmlReport += @"
                <li>$cause</li>
"@
}

$htmlReport += @"
            </ul>
            
            <h4>Recommendations</h4>
            <ul>
"@

foreach ($recommendation in $BugcheckAnalysis.Recommendations) {
    $htmlReport += @"
                <li>$recommendation</li>
"@
}

$htmlReport += @"
            </ul>
        </div>
        
        <div class="section">
            <h2>Driver Analysis</h2>
"@

$criticalDriversFound = $false
foreach ($driver in $DriverAnalysis) {
    $hasCriticalIssue = $false
    foreach ($issue in $driver.KnownIssues) {
        if ($issue.CurrentVersionAffected -eq $true -and $issue.OSAffected -eq $true) {
            $hasCriticalIssue = $true
            $criticalDriversFound = $true
            break
        }
    }
    
    $statusClass = if ($hasCriticalIssue) { "critical" } else { "" }
    $identifiedInCrash = if ($CrashMetadata.CrashedDrivers -contains $driver.DriverName) { "Yes (identified in crash dump)" } else { "No" }
    
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
                </table>
"@

    if ($driver.KnownIssues.Count -gt 0) {
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

if (-not $criticalDriversFound) {
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

# Get relevant system events around the crash time
$crashTime = $CrashMetadata.CreationTime
$eventTimeStart = $crashTime.AddMinutes(-30)
$eventTimeEnd = $crashTime.AddMinutes(5)

$relevantEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Level = 1,2,3  # Error, Warning, Information
    StartTime = $eventTimeStart
    EndTime = $eventTimeEnd
} -MaxEvents 50 -ErrorAction SilentlyContinue | 
Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName

if ($relevantEvents -and $relevantEvents.Count -gt 0) {
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
        
        # Truncate very long messages
        $message = $event.Message
        if ($message.Length -gt 200) {
            $message = $message.Substring(0, 200) + "..."
        }
        
        $htmlReport += @"
                <tr class="$levelClass">
                    <td>$($event.TimeCreated)</td>
                    <td>$($event.Id)</td>
                    <td>$($event.LevelDisplayName)</td>
                    <td>$($event.ProviderName)</td>
                    <td>$message</td>
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
        
        foreach ($issue in $driver.KnownIssues) {
            if ($issue.CurrentVersionAffected -eq $true -and $issue.OSAffected -eq $true) {
                $hasCriticalIssue = $true
                $resolutions += $issue.Resolution
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

foreach ($recommendation in $BugcheckAnalysis.Recommendations) {
    $htmlReport += @"
                    <li>$recommendation</li>
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
    
    # Get system information
    $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    
    # Create a structured data object
    $analysisData = @{
        "GeneratedOn" = Get-Date
        "SystemInfo" = @{
            "Manufacturer" = $systemInfo.Manufacturer
            "Model" = $systemInfo.Model
            "OSName" = $osInfo.Caption
            "OSVersion" = $osInfo.Version
            "OSBuild" = $osInfo.BuildNumber
        }
        "CrashInfo" = @{
            "DumpFile" = $CrashMetadata.FileName
            "CrashTime" = $CrashMetadata.CreationTime
            "BugcheckCode" = $BugcheckAnalysis.BugcheckCode
            "BugcheckName" = $BugcheckAnalysis.BugcheckName
            "Description" = $BugcheckAnalysis.Description
        }
        "BugcheckAnalysis" = $BugcheckAnalysis
        "DriverAnalysis" = $DriverAnalysis
    }
    
    return $analysisData
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
    
    $AnalysisData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding utf8 -Force
    Write-Host "Analysis data exported to JSON: $OutputFile" -ForegroundColor Green
    
    return $OutputFile
}

# Main function to run the analysis
function Start-BSODAnalysis {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TargetDumpFile
    )
    
    Write-Host "==== Windows BSOD Root Cause Triage Tool ====" -ForegroundColor Cyan
    Write-Host "Starting analysis at $(Get-Date)" -ForegroundColor Cyan
    
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
    
    # Extract metadata from the crash dump
    $crashMetadata = Get-CrashDumpMetadata -DumpFile $dumpFile
    
    # Analyze bugcheck code
    $bugcheckAnalysis = Get-BugcheckAnalysis -CrashMetadata $crashMetadata
    
    # Find and analyze problematic drivers
    $driverAnalysis = Find-ProblemDrivers -CrashMetadata $crashMetadata
    
    # Generate the complete analysis data
    $analysisData = Get-AnalysisData -CrashMetadata $crashMetadata -DriverAnalysis $driverAnalysis -BugcheckAnalysis $bugcheckAnalysis
    
    # Export the data to JSON for programmatic use
    $jsonFile = Export-AnalysisToJSON -AnalysisData $analysisData
    
    # Generate an HTML report if requested
    if ($GenerateReport) {
        $reportFile = New-AnalysisReport -CrashMetadata $crashMetadata -DriverAnalysis $driverAnalysis -BugcheckAnalysis $bugcheckAnalysis
        
        # Try to open the report in the default browser
        try {
            Start-Process $reportFile
        }
        catch {
            Write-Warning "Could not open the HTML report automatically. Please open manually: $reportFile"
        }
    }
    
    Write-Host "==== Analysis Complete ====" -ForegroundColor Cyan
    Write-Host "Results saved to: $OutputPath" -ForegroundColor Green
    
    return $analysisData
}

# Run the analysis when the script is executed
Start-BSODAnalysis
