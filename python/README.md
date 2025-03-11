
# BluSkreener

```bash
 ____  _       ____  _                                  
| __ )| |_   _/ ___|| | ___ __ ___  ___ _ __   ___ _ __ 
|  _ \| | | | \___ \| |/ / '__/ _ \/ _ \ '_ \ / _ \ '__|
| |_) | | |_| |___) |   <| | |  __/  __/ | | |  __/ |   
|____/|_|\__,_|____/|_|\_\_|  \___|\___|_| |_|\___|_|   
```

---

# Windows BSOD Root Cause Triage Tool - dotPy

## Usage Guide

## Overview

The Python implementation of the Windows BSOD Root Cause Triage Tool provides a sophisticated yet accessible approach to diagnosing and resolving Windows 11 system crashes. This powerful utility employs multiple analytical layers to transform cryptic crash data into actionable insights, empowering both technical professionals and knowledgeable users to identify and remediate the underlying causes of system instability.

The tool orchestrates several key analytical components to create a comprehensive diagnostic framework:

1. **Crash Dump Analysis Engine**: Meticulously extracts critical metadata from Windows memory dumps, decoding the information that Windows captures at the moment of system failure.

2. **Driver Verification System**: Systematically cross-references all system drivers against an extensive database of known problematic versions, identifying those with documented stability issues.

3. **Bugcheck Interpretation Framework**: Translates cryptic bugcheck codes into human-readable explanations, common causes, and evidence-based remediation strategies.

4. **System Event Correlation Matrix**: Examines system event logs temporally surrounding the crash to establish contextual patterns and potential trigger events.

5. **Multi-format Reporting System**: Generates both visually intuitive HTML reports for human analysis and structured JSON data for programmatic consumption or integration with enterprise monitoring systems.

## Prerequisites

Before deploying the Python-based BSOD analysis tool, ensure your environment meets the following requirements:

- **Windows 11 operating system** – While the tool may work on Windows 10, it's specifically optimized for Windows 11 architecture and diagnostic patterns
- **Python 3.7 or higher** – The implementation leverages modern Python features for robust error handling and processing
- **Administrator privileges** – Required to access system logs, driver information, and crash dump files
- **Windows Debugging Tools** (recommended but not required) – Provides enhanced crash dump analysis capabilities when installed

Additionally, the following Python packages are automatically utilized by the tool:

- Standard library components (`os`, `sys`, `json`, `datetime`, etc.)
- `subprocess` for interfacing with PowerShell commands
- `winreg` for accessing the Windows registry

## Installation

1. **Obtain the required files**:
   - `bsod_analyzer.py` – The main Python script
   - `BugcheckKB.json` – Database of bugcheck code interpretations
   - `KnownBadDrivers.json` – Repository of problematic driver information

2. **Place all files in a common directory** of your choosing.

3. **Verify Python installation**:

   ```bash
   python --version
   ```

   Ensure the version is 3.7 or higher.

4. **Optional: Install Windows Debugging Tools**:
   - These are included in the Windows SDK, available from Microsoft's developer website
   - The tool will automatically detect and utilize them if available
   - While optional, these tools significantly enhance the depth and accuracy of crash dump analysis

## Basic Usage

### Analyzing the Most Recent Crash

To examine the most recent BSOD event that occurred on your system:

1. Open Command Prompt or PowerShell with administrator privileges
2. Navigate to the directory containing the Python script
3. Execute the basic analysis command:

```bash
python bsod_analyzer.py
```

The tool will automatically:

- Locate the most recent crash dump in the default Windows location (`%SystemRoot%\Minidump`)
- Extract and interpret the bugcheck information
- Analyze all loaded drivers against the known issues database
- Collect relevant system events surrounding the crash time
- Generate both HTML and JSON reports
- Attempt to open the HTML report in your default browser

### Analyzing a Specific Crash Dump

To analyze a particular crash dump file rather than the most recent one:

```bash
python bsod_analyzer.py --dump C:\Path\To\Your\Crash.dmp
```

This is particularly useful when:

- Investigating multiple historical crashes
- Analyzing dumps transferred from another system
- Comparing different crash scenarios to identify patterns

### Customizing Output Location

By default, analysis reports are saved to your Desktop in a folder named "BSODAnalysis". To specify a different location:

```bash
python bsod_analyzer.py --output D:\Diagnostics\CrashReports
```

This is useful for:

- Keeping reports organized in a centralized location
- Storing analysis results on high-capacity drives
- Generating reports directly on shared network locations for team access

## Advanced Parameters

The Python implementation supports several advanced command-line parameters:

```bash
python bsod_analyzer.py --help
```

Key parameters include:

- `--dump` or `-d`: Path to a specific crash dump file to analyze
- `--output` or `-o`: Directory where analysis reports should be saved
- `--kb` or `-k`: Path to a custom bugcheck knowledge base file
- `--drivers` or `-r`: Path to a custom known bad drivers database
- `--verbose` or `-v`: Enable detailed logging for troubleshooting

For integration into automated scripts or enterprise environments, you can combine parameters:

```bash
python bsod_analyzer.py --dump C:\Dumps\recent.dmp --output D:\Reports --verbose
```

## Understanding the Analysis Report

The HTML report generated by the tool provides a comprehensive view of the crash analysis, organized into logical sections:

### Analysis Summary

The report begins with a high-level overview of the crash event, including:

- Crash dump file name and timestamp
- Bugcheck code and symbolic name
- Primary cause description
- System manufacturer and model information
- Operating system version details

This summary section serves as a quick reference to understand the nature of the crash at a glance.

### Bugcheck Analysis

This section provides in-depth information about the specific bugcheck code that triggered the BSOD:

- Detailed description of what the bugcheck code represents
- Common causes that typically trigger this particular bugcheck
- Recommended troubleshooting steps specific to this error condition

The bugcheck analysis helps narrow the focus to the most likely categories of issues based on Microsoft's documented error patterns.

### Driver Analysis

Perhaps the most valuable section, the driver analysis provides a detailed examination of:

- Drivers explicitly implicated in the crash
- Other loaded drivers that match known problematic versions
- For each identified driver:
  - Vendor information and driver type
  - Current installed version
  - Known issues associated with this version
  - Whether the current version falls within problematic version ranges
  - Specific resolution steps recommended by the vendor

Drivers with critical issues are visually highlighted to draw attention to the most likely culprits.

### System Event Log Analysis

This section examines Windows Event Log entries temporally surrounding the crash:

- Events are shown in chronological order with timestamps
- Includes event IDs, severity levels, and source providers
- Full event messages provide context for system state changes
- Visual highlighting calls attention to errors and warnings

The event log analysis often reveals triggering events or cascading failures that led to the crash.

### Next Steps and Recommendations

The final section provides a prioritized action plan:

- Driver updates specifically targeting identified problematic drivers
- General recommendations based on the bugcheck type
- System maintenance tasks to improve overall stability
- Diagnostic steps to identify hardware issues
- Resources for further troubleshooting if needed

This structured approach transforms complex diagnostic data into a clear roadmap for resolving the issue.

## Knowledge Base Maintenance

One of the most powerful aspects of the Python implementation is its ability to evolve through knowledge base updates.

### Bugcheck Knowledge Base

The `BugcheckKB.json` file contains interpretive information about Windows bugcheck codes. Each entry includes:

- The symbolic name of the bugcheck (e.g., "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED")
- A plain-language description of what the bugcheck represents
- Common causes associated with this type of crash
- Recommended troubleshooting steps

You can extend this database by adding new entries as you encounter them, following the established JSON schema:

```json
"0xYOURCODE": {
    "Name": "SYMBOLIC_NAME",
    "Description": "Description of what this bugcheck means",
    "CommonCauses": [
        "First common cause",
        "Second common cause"
    ],
    "Recommendations": [
        "First recommendation",
        "Second recommendation"
    ]
}
```

### Known Bad Drivers Database

The `KnownBadDrivers.json` file maintains a registry of driver versions with documented stability issues. Each entry contains:

- Driver filename as the key (e.g., "nvlddmkm.sys")
- Vendor and driver type information
- An array of known issues, each specifying:
  - Affected version range (minimum and maximum versions)
  - Description of the issue
  - Recommended resolution steps
  - Affected operating systems

As vendors release information about problematic driver versions, you can add them to the database:

```json
"driver_name.sys": {
    "VendorName": "Vendor Corporation",
    "DriverType": "Category of Driver",
    "KnownIssues": [
        {
            "VersionRange": ["10.0.1234.56", "10.0.1234.89"],
            "IssueDescription": "Description of the issue",
            "Resolution": "Update to version X or later",
            "AffectedOS": ["Windows 10", "Windows 11"]
        }
    ]
}
```

Regular updates to these knowledge bases significantly enhance the tool's diagnostic capabilities over time.

## Example Scenarios

### Scenario 1: Recurring Graphics Driver Crashes

A system experiences frequent BSODs while running graphically intensive applications.

1. Run the analyzer:

   ```bash
   python bsod_analyzer.py
   ```

2. The HTML report identifies:

   - Bugcheck code 0x116 (VIDEO_TDR_FAILURE)
   - NVIDIA display driver (nvlddmkm.sys) implicated in the crash
   - Current driver version falls within a known problematic range
   - Recommendation to update to the specific version that resolves the issue

3. The user updates the graphics driver to the recommended version, resolving the instability.

### Scenario 2: Memory-Related System Instability

A system crashes intermittently with different bugcheck codes.

1. Analyze multiple crash dumps:

   ```bash
   python bsod_analyzer.py --dump C:\Windows\Minidump\minidump-20230615-01.dmp
   python bsod_analyzer.py --dump C:\Windows\Minidump\minidump-20230618-02.dmp
   ```

2. Comparing the reports reveals:

   - Different bugcheck codes (0x50, 0x1A) but all memory-related
   - No consistent driver implicated across crashes
   - Event logs showing memory correction events prior to crashes
   - Recommendations consistently pointing to memory diagnostics

3. The user runs memory diagnostics and discovers faulty RAM, which when replaced resolves the crashes.

### Scenario 3: Corporate Deployment for IT Support

An IT department deploys the tool across multiple systems.

1. Create a network share for reports:

   ```bash
   python bsod_analyzer.py --output \\server\share\crashreports\%computername%
   ```

2. Add to automated incident response:

   - Script detects a new crash dump
   - Runs the analyzer with custom knowledge base
   - Uploads the JSON results to a central monitoring system
   - Automatically creates support tickets with analysis results
   - Suggests resolutions based on historical success patterns

## Troubleshooting the Analyzer

If you encounter issues with the tool itself:

- **No Windows Debugger Found**: While the tool will function with limited capabilities, consider installing the Windows SDK for enhanced analysis.

- **JSON Parsing Errors**: If you've manually modified the knowledge base files, ensure they maintain valid JSON syntax.

- **PowerShell Execution Failures**: The tool uses PowerShell commands to gather system information. Ensure PowerShell is available and execution policy allows these operations.

- **Permission Issues**: Run the tool with administrator privileges to ensure it can access all required system information.

- **Python Version Compatibility**: If you encounter syntax errors, verify you're using Python 3.7 or higher.

- **Report Generation Failures**: Ensure the output directory is writable by checking permissions.

## Integration with Other Systems

The JSON output generated by the analyzer facilitates integration with other diagnostic and management systems:

```python
# Example of programmatically working with analysis results
import json
import subprocess

# Run the analyzer and capture the path to the JSON output
result = subprocess.run(
    ["python", "bsod_analyzer.py", "--output", "./reports"],
    capture_output=True, text=True
)

# Extract the JSON file path from the output
for line in result.stdout.splitlines():
    if "Analysis data exported to JSON:" in line:
        json_path = line.split(":")[-1].strip()
        break

# Load and process the analysis data
with open(json_path, 'r') as f:
    analysis = json.load(f)

# Extract key information
bugcheck_code = analysis["CrashInfo"]["BugcheckCode"]
critical_drivers = [d for d in analysis["DriverAnalysis"] 
                    if any(i["CurrentVersionAffected"] and i["OSAffected"] 
                           for i in d.get("KnownIssues", []))]

# Take automated actions based on analysis results
if critical_drivers:
    print(f"Critical driver issues found: {len(critical_drivers)}")
    # Trigger automated remediation workflows
```

This programmatic access enables:

- Integration with ticketing systems
- Automated remediation workflows
- Historical crash pattern analysis
- Custom notification systems
- Centralized fleet health monitoring

## Conclusion

The Python implementation of the Windows BSOD Root Cause Triage Tool transforms the typically obscure and frustrating experience of troubleshooting system crashes into a methodical, evidence-based process. By combining crash dump analysis, driver verification, bugcheck interpretation, and event correlation, the tool provides a comprehensive diagnostic framework that significantly reduces mean time to resolution for system stability issues.

Whether you're an IT professional managing a fleet of systems, a power user troubleshooting your own computer, or a software developer diagnosing compatibility issues, this tool provides the insights needed to move from cryptic blue screens to targeted solutions efficiently and effectively.
