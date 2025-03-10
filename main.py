#!/usr/bin/env python3
# Windows BSOD Root Cause Triage Tool - Python Implementation
# Author: Principal Systems Development Engineer
# Description: Python implementation for analyzing crash dumps and identifying
#              problematic drivers based on a knowledge base of known issues.

import os
import sys
import json
import datetime
import subprocess
import re
import platform
from pathlib import Path
import argparse
import logging
import tempfile
import shutil
import winreg

class BSODAnalyzer:
    """Main class for analyzing Windows BSOD crash dumps."""
    
    def __init__(self, dump_path=None, output_path=None, kb_path=None, drivers_db_path=None):
        """Initialize the BSOD analyzer with paths and configuration."""
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("BSODAnalyzer")
        
        # Set default paths if not specified
        system_root = os.environ.get('SystemRoot', 'C:\\Windows')
        user_profile = os.environ.get('USERPROFILE', 'C:\\Users\\Default')
        
        self.dump_path = dump_path or os.path.join(system_root, 'Minidump')
        self.output_path = output_path or os.path.join(user_profile, 'Desktop', 'BSODAnalysis')
        
        # Get script directory for database files
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.kb_path = kb_path or os.path.join(script_dir, 'BugcheckKB.json')
        self.drivers_db_path = drivers_db_path or os.path.join(script_dir, 'KnownBadDrivers.json')
        
        # Initialize debugger info
        self.debugger_available = False
        self.debugger_path = None
        
        # Load knowledge bases
        self.bugcheck_kb = {}
        self.drivers_db = {}
        
        # Results storage
        self.crash_metadata = {}
        self.driver_analysis = []
        self.bugcheck_analysis = {}
        
        # Ensure we're running on Windows 11
        if not self._check_windows_11():
            self.logger.warning("This tool is optimized for Windows 11. Some features may not work correctly on your system.")
    
    def _check_windows_11(self):
        """Check if the system is running Windows 11."""
        try:
            win_ver = platform.win32_ver()
            # Windows 11 has version numbers 10.0.22xxx
            if win_ver[0] == "10" and int(win_ver[1].split(".")[2]) >= 22000:
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error checking Windows version: {e}")
            return False
    
    def initialize_environment(self):
        """Set up the environment for analysis."""
        self.logger.info("Initializing environment...")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_path, exist_ok=True)
        self.logger.info(f"Output directory: {self.output_path}")
        
        # Check for Windows Debugging Tools
        self._find_debugger()
        
        # Load or initialize knowledge bases
        self._load_bugcheck_kb()
        self._load_drivers_db()
        
        self.logger.info("Environment initialized successfully")
    
    def _find_debugger(self):
        """Locate the Windows Debugger (kd.exe or windbg.exe)."""
        try:
            # Try to get Windows Kits path from registry
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               "SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots") as key:
                kits_root = winreg.QueryValueEx(key, "KitsRoot10")[0]
                
                # Check for x64 debugger
                debugger_path = os.path.join(kits_root, "Debuggers", "x64", "kd.exe")
                if os.path.exists(debugger_path):
                    self.debugger_path = debugger_path
                    self.debugger_available = True
                    self.logger.info(f"Windows Debugger found at: {debugger_path}")
                    return
            
            self.logger.warning("Windows Debugger not found. Some functionality will be limited.")
            self.debugger_available = False
        except Exception as e:
            self.logger.warning(f"Error finding Windows Debugger: {e}")
            self.debugger_available = False
    
    def _load_bugcheck_kb(self):
        """Load the bugcheck knowledge base from JSON file."""
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, 'r', encoding='utf-8') as f:
                    self.bugcheck_kb = json.load(f)
                self.logger.info(f"Loaded bugcheck knowledge base from {self.kb_path}")
            except Exception as e:
                self.logger.error(f"Error loading bugcheck knowledge base: {e}")
                self._initialize_bugcheck_kb()
        else:
            self.logger.warning(f"Bugcheck knowledge base not found at {self.kb_path}")
            self._initialize_bugcheck_kb()
    
    def _initialize_bugcheck_kb(self):
        """Create a default bugcheck knowledge base if one doesn't exist."""
        self.logger.info("Creating default bugcheck knowledge base...")
        
        # Sample bugcheck data - abbreviated version
        self.bugcheck_kb = {
            "0x0000001E": {
                "Name": "KMODE_EXCEPTION_NOT_HANDLED",
                "Description": "A kernel-mode program generated an exception which the error handler did not catch.",
                "CommonCauses": [
                    "Faulty device driver",
                    "System service",
                    "NTFS corruption",
                    "Faulty hardware (especially memory-related)"
                ],
                "Recommendations": [
                    "Check for recent driver updates or rollbacks",
                    "Run hardware diagnostics, especially memory test",
                    "Check system file integrity with SFC /scannow",
                    "Run chkdsk to verify disk integrity"
                ]
            },
            "0x0000007E": {
                "Name": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
                "Description": "A system thread generated an exception that the error handler did not catch.",
                "CommonCauses": [
                    "Faulty device driver",
                    "Defective hardware (RAM, motherboard, etc.)",
                    "Overclocking",
                    "System file corruption"
                ],
                "Recommendations": [
                    "Update drivers, especially graphics, storage, and network drivers",
                    "Reset overclocking to factory settings if applicable",
                    "Check for hardware issues with diagnostic tools",
                    "Restore system to earlier restore point"
                ]
            },
            # Additional entries would be included in the actual implementation
        }
        
        # Save to file
        try:
            with open(self.kb_path, 'w', encoding='utf-8') as f:
                json.dump(self.bugcheck_kb, f, indent=4)
            self.logger.info(f"Created default bugcheck knowledge base at {self.kb_path}")
        except Exception as e:
            self.logger.error(f"Error creating bugcheck knowledge base: {e}")
    
    def _load_drivers_db(self):
        """Load the known bad drivers database from JSON file."""
        if os.path.exists(self.drivers_db_path):
            try:
                with open(self.drivers_db_path, 'r', encoding='utf-8') as f:
                    self.drivers_db = json.load(f)
                self.logger.info(f"Loaded known bad drivers database from {self.drivers_db_path}")
            except Exception as e:
                self.logger.error(f"Error loading drivers database: {e}")
                self._initialize_drivers_db()
        else:
            self.logger.warning(f"Drivers database not found at {self.drivers_db_path}")
            self._initialize_drivers_db()
    
    def _initialize_drivers_db(self):
        """Create a default known bad drivers database if one doesn't exist."""
        self.logger.info("Creating default known bad drivers database...")
        
        # Sample driver data - abbreviated version
        self.drivers_db = {
            "nvlddmkm.sys": {
                "VendorName": "NVIDIA Corporation",
                "DriverType": "Display Driver",
                "KnownIssues": [
                    {
                        "VersionRange": ["456.71", "460.89"],
                        "IssueDescription": "May cause SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7E) when entering sleep mode",
                        "Resolution": "Update to version 461.09 or later",
                        "AffectedOS": ["Windows 10", "Windows 11"]
                    }
                ]
            },
            "iastor.sys": {
                "VendorName": "Intel Corporation",
                "DriverType": "Storage Controller Driver",
                "KnownIssues": [
                    {
                        "VersionRange": ["11.2.0.1006", "11.2.0.1032"],
                        "IssueDescription": "Can cause KERNEL_DATA_INPAGE_ERROR (0x7A) when using NVMe storage",
                        "Resolution": "Update to Intel Rapid Storage Technology version 11.2.0.1033 or later",
                        "AffectedOS": ["Windows 10", "Windows 11"]
                    }
                ]
            },
            # Additional entries would be included in the actual implementation
        }
        
        # Save to file
        try:
            with open(self.drivers_db_path, 'w', encoding='utf-8') as f:
                json.dump(self.drivers_db, f, indent=4)
            self.logger.info(f"Created default drivers database at {self.drivers_db_path}")
        except Exception as e:
            self.logger.error(f"Error creating drivers database: {e}")
    
    def get_latest_crash_dump(self):
        """Find the most recent crash dump file."""
        try:
            if not os.path.exists(self.dump_path):
                self.logger.warning(f"Crash dump directory not found: {self.dump_path}")
                return None
            
            dump_files = [os.path.join(self.dump_path, f) for f in os.listdir(self.dump_path) 
                          if f.endswith('.dmp')]
            
            if not dump_files:
                self.logger.warning(f"No crash dump files found in {self.dump_path}")
                return None
            
            # Get the most recent file
            latest_dump = max(dump_files, key=os.path.getmtime)
            self.logger.info(f"Found latest crash dump: {latest_dump}")
            return latest_dump
        
        except Exception as e:
            self.logger.error(f"Error finding latest crash dump: {e}")
            return None
    
    def extract_dump_metadata(self, dump_file):
        """Extract metadata from a crash dump file."""
        self.logger.info(f"Extracting metadata from crash dump: {dump_file}")
        
        if not os.path.exists(dump_file):
            self.logger.error(f"Dump file not found: {dump_file}")
            return None
        
        metadata = {
            "DumpFile": dump_file,
            "FileName": os.path.basename(dump_file),
            "CreationTime": datetime.datetime.fromtimestamp(os.path.getmtime(dump_file)),
            "FileSize": os.path.getsize(dump_file),
            "BugcheckCode": "Unknown",
            "BugcheckName": "Unknown",
            "CrashedDrivers": []
        }
        
        if not self.debugger_available:
            self.logger.warning("Windows Debugger not available. Limited metadata extraction only.")
            # Try to extract information from filename pattern (e.g., MEMORY.DMP or minidump-YYYYMMDD-NN.dmp)
            return metadata
        
        # Create a temporary file with debugger commands
        temp_cmd_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        try:
            with open(temp_cmd_file.name, 'w') as f:
                f.write(".symfix\n")
                f.write(".reload\n")
                f.write("!analyze -v\n")
                f.write("lm t n\n")
                f.write("!for_each_module .echo @#ModuleName @#Base @#End @#ImageSize @#LoadedImageName @#ImageName\n")
                f.write("q\n")
            
            # Run the debugger commands
            cmd = [self.debugger_path, "-z", dump_file, "-c", f"$$<{temp_cmd_file.name}"]
            self.logger.debug(f"Running debugger command: {' '.join(cmd)}")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                      text=True, universal_newlines=True)
            debug_output, _ = process.communicate()
            
            # Parse the output for relevant information
            for line in debug_output.splitlines():
                # Extract bugcheck code
                if "BUGCHECK_CODE:" in line:
                    match = re.search(r"BUGCHECK_CODE:\s+([0-9a-fA-F]+)", line)
                    if match:
                        metadata["BugcheckCode"] = "0x" + match.group(1)
                
                # Extract bugcheck name
                elif "BUGCHECK_STR:" in line:
                    match = re.search(r"BUGCHECK_STR:\s+(.+)", line)
                    if match:
                        metadata["BugcheckName"] = match.group(1).strip()
                
                # Look for probable causes
                elif "Probably caused by" in line:
                    match = re.search(r"Probably caused by\s*:\s*(.+)", line)
                    if match:
                        probable_cause = match.group(1).strip()
                        
                        # Extract driver names (typical format is "driver_name.sys")
                        driver_match = re.search(r"(\w+\.sys)", probable_cause)
                        if driver_match:
                            metadata["CrashedDrivers"].append(driver_match.group(1))
                
                # Extract driver names from alternate patterns
                elif "IMAGE_NAME:" in line:
                    match = re.search(r"IMAGE_NAME:\s+(\w+\.sys)", line)
                    if match:
                        # Only add if not already in the list
                        driver_name = match.group(1)
                        if driver_name not in metadata["CrashedDrivers"]:
                            metadata["CrashedDrivers"].append(driver_name)
            
            self.logger.info(f"Extracted metadata: Bugcheck {metadata['BugcheckCode']} ({metadata['BugcheckName']})")
            if metadata["CrashedDrivers"]:
                self.logger.info(f"Identified crashed drivers: {', '.join(metadata['CrashedDrivers'])}")
            
            return metadata
        
        except Exception as e:
            self.logger.error(f"Error extracting dump metadata: {e}")
            return metadata
        
        finally:
            # Cleanup temp file
            if os.path.exists(temp_cmd_file.name):
                os.unlink(temp_cmd_file.name)
    
    def analyze_bugcheck(self, crash_metadata):
        """Get information about the bugcheck code from the knowledge base."""
        self.logger.info("Analyzing bugcheck code against knowledge base...")
        
        bugcheck_code = crash_metadata.get("BugcheckCode", "Unknown")
        
        if bugcheck_code in self.bugcheck_kb:
            bugcheck_info = self.bugcheck_kb[bugcheck_code]
            
            analysis = {
                "BugcheckCode": bugcheck_code,
                "BugcheckName": bugcheck_info["Name"],
                "Description": bugcheck_info["Description"],
                "CommonCauses": bugcheck_info["CommonCauses"],
                "Recommendations": bugcheck_info["Recommendations"]
            }
        else:
            self.logger.warning(f"Bugcheck code {bugcheck_code} not found in knowledge base.")
            
            analysis = {
                "BugcheckCode": bugcheck_code,
                "BugcheckName": crash_metadata.get("BugcheckName", "Unknown"),
                "Description": "No detailed information available in knowledge base.",
                "CommonCauses": ["Unknown - not in knowledge base"],
                "Recommendations": [
                    "Search for the bugcheck code online",
                    "Check Windows Event Logs for related errors",
                    "Run system file integrity check (SFC /scannow)",
                    "Check for Windows updates"
                ]
            }
        
        self.logger.info(f"Bugcheck analysis completed for code {bugcheck_code}")
        return analysis
    
    def analyze_drivers(self, crash_metadata):
        """Analyze drivers against the known issues database."""
        self.logger.info("Analyzing drivers against known issues database...")
        
        # Get list of loaded drivers
        drivers_list = self._get_loaded_drivers()
        
        driver_results = []
        
        # First check the crashed drivers identified in the dump
        for driver_name in crash_metadata.get("CrashedDrivers", []):
            self.logger.info(f"Analyzing identified problematic driver: {driver_name}")
            
            # Check if in our known bad database
            if driver_name in self.drivers_db:
                known_issues = self.drivers_db[driver_name]
                
                # Find the driver in our loaded drivers list
                driver_info = next((d for d in drivers_list if d["Name"] == driver_name or 
                                   d["FileName"] == driver_name), None)
                
                driver_version = "Unknown"
                if driver_info and driver_info.get("Version"):
                    driver_version = driver_info["Version"]
                
                result = {
                    "DriverName": driver_name,
                    "VendorName": known_issues["VendorName"],
                    "DriverType": known_issues["DriverType"],
                    "CurrentVersion": driver_version,
                    "IsInstalled": driver_info is not None,
                    "KnownIssues": []
                }
                
                # Check each known issue for version match
                for issue in known_issues.get("KnownIssues", []):
                    min_version = issue["VersionRange"][0]
                    max_version = issue["VersionRange"][1]
                    
                    # Check if current version is in the affected range
                    version_affected = False
                    if driver_version != "Unknown":
                        try:
                            # Simple version comparison
                            version_affected = self._is_version_in_range(driver_version, min_version, max_version)
                        except ValueError:
                            version_affected = "Unknown (version comparison failed)"
                    
                    # Check if OS is affected
                    os_affected = "Windows 11" in issue.get("AffectedOS", [])
                    
                    match_result = {
                        "IssueDescription": issue["IssueDescription"],
                        "VersionRange": f"{min_version} to {max_version}",
                        "CurrentVersionAffected": version_affected,
                        "OSAffected": os_affected,
                        "Resolution": issue["Resolution"]
                    }
                    
                    result["KnownIssues"].append(match_result)
                
                driver_results.append(result)
            else:
                # Driver not in known bad database
                driver_info = next((d for d in drivers_list if d["Name"] == driver_name or 
                                  d["FileName"] == driver_name), None)
                
                result = {
                    "DriverName": driver_name,
                    "VendorName": "Unknown",
                    "DriverType": "Unknown",
                    "CurrentVersion": "Unknown",
                    "IsInstalled": driver_info is not None,
                    "KnownIssues": []
                }
                
                if driver_info:
                    if driver_info.get("Company"):
                        result["VendorName"] = driver_info["Company"]
                    if driver_info.get("Version"):
                        result["CurrentVersion"] = driver_info["Version"]
                
                driver_results.append(result)
        
        # Also scan all loaded drivers against the known bad database
        self.logger.info("Scanning all loaded drivers for potential issues...")
        
        for driver in drivers_list:
            driver_filename = driver.get("FileName", "")
            
            # Skip if already analyzed above
            if driver_filename in crash_metadata.get("CrashedDrivers", []):
                continue
            
            # Check if in our known bad database
            if driver_filename in self.drivers_db:
                self.logger.info(f"Found potentially problematic loaded driver: {driver_filename}")
                
                known_issues = self.drivers_db[driver_filename]
                driver_version = driver.get("Version", "Unknown")
                
                result = {
                    "DriverName": driver_filename,
                    "VendorName": known_issues["VendorName"],
                    "DriverType": known_issues["DriverType"],
                    "CurrentVersion": driver_version,
                    "IsInstalled": True,
                    "IdentifiedInCrash": False,
                    "KnownIssues": []
                }
                
                # Check each known issue for version match
                for issue in known_issues.get("KnownIssues", []):
                    min_version = issue["VersionRange"][0]
                    max_version = issue["VersionRange"][1]
                    
                    # Check if current version is in the affected range
                    version_affected = False
                    if driver_version != "Unknown":
                        try:
                            version_affected = self._is_version_in_range(driver_version, min_version, max_version)
                        except ValueError:
                            version_affected = "Unknown (version comparison failed)"
                    
                    # Check if OS is affected
                    os_affected = "Windows 11" in issue.get("AffectedOS", [])
                    
                    match_result = {
                        "IssueDescription": issue["IssueDescription"],
                        "VersionRange": f"{min_version} to {max_version}",
                        "CurrentVersionAffected": version_affected,
                        "OSAffected": os_affected,
                        "Resolution": issue["Resolution"]
                    }
                    
                    result["KnownIssues"].append(match_result)
                
                driver_results.append(result)
        
        self.logger.info(f"Driver analysis completed. Found {len(driver_results)} potential issues.")
        return driver_results
    
    def _get_loaded_drivers(self):
        """Get a list of currently loaded drivers."""
        self.logger.info("Retrieving currently loaded drivers...")
        
        drivers = []
        try:
            # Use PowerShell to get driver information
            ps_cmd = "Get-WmiObject -Class Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | " + \
                     "Select-Object Name, DisplayName, PathName, Description, State | ConvertTo-Json -Depth 1"
            
            process = subprocess.Popen(["powershell", "-Command", ps_cmd], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, universal_newlines=True)
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Error retrieving drivers: {stderr}")
                return drivers
            
            # Parse the JSON output
            drivers_info = json.loads(stdout)
            
            # Ensure we have a list (PowerShell may return a single object if only one driver)
            if not isinstance(drivers_info, list):
                drivers_info = [drivers_info]
            
            # Process each driver
            for driver in drivers_info:
                # Extract the filename from the path
                path = driver.get("PathName", "")
                filename = os.path.basename(path) if path else ""
                
                # Get driver version from file
                version = "Unknown"
                if path and os.path.exists(path):
                    try:
                        # Use PowerShell to get file version
                        ver_cmd = f"(Get-Item -Path '{path}').VersionInfo.FileVersion"
                        ver_process = subprocess.Popen(["powershell", "-Command", ver_cmd],
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                    text=True, universal_newlines=True)
                        ver_stdout, _ = ver_process.communicate()
                        if ver_process.returncode == 0:
                            version = ver_stdout.strip()
                    except Exception as e:
                        self.logger.debug(f"Error getting version for {path}: {e}")
                
                # Add to our list
                drivers.append({
                    "Name": driver.get("Name", ""),
                    "DisplayName": driver.get("DisplayName", ""),
                    "PathName": path,
                    "FileName": filename,
                    "Description": driver.get("Description", ""),
                    "Company": "",  # Will be filled in later if available
                    "Version": version
                })
            
            self.logger.info(f"Retrieved {len(drivers)} loaded drivers")
            return drivers
            
        except Exception as e:
            self.logger.error(f"Error retrieving drivers: {e}")
            return drivers
    
    def _is_version_in_range(self, current, min_ver, max_ver):
        """Check if a version is within a specified range."""
        # Convert version strings to comparable objects
        try:
            current_parts = [int(x) for x in current.split('.')]
            min_parts = [int(x) for x in min_ver.split('.')]
            max_parts = [int(x) for x in max_ver.split('.')]
            
            # Pad with zeros to ensure equal length
            max_length = max(len(current_parts), len(min_parts), len(max_parts))
            current_parts = current_parts + [0] * (max_length - len(current_parts))
            min_parts = min_parts + [0] * (max_length - len(min_parts))
            max_parts = max_parts + [0] * (max_length - len(max_parts))
            
            # Compare component by component
            is_greater_than_min = False
            is_less_than_max = False
            
            for i in range(max_length):
                if current_parts[i] > min_parts[i]:
                    is_greater_than_min = True
                    break
                elif current_parts[i] < min_parts[i]:
                    return False
            
            for i in range(max_length):
                if current_parts[i] < max_parts[i]:
                    is_less_than_max = True
                    break
                elif current_parts[i] > max_parts[i]:
                    return False
            
            return is_greater_than_min and is_less_than_max
        except Exception as e:
            self.logger.warning(f"Version comparison error: {e}")
            raise ValueError(f"Invalid version format: {e}")
    
    def get_event_log_data(self, crash_time, minutes_before=30, minutes_after=5):
        """Get relevant system events around the crash time."""
        self.logger.info(f"Retrieving system events around crash time: {crash_time}")
        
        try:
            # Calculate time range
            start_time = crash_time - datetime.timedelta(minutes=minutes_before)
            end_time = crash_time + datetime.timedelta(minutes=minutes_after)
            
            # Format times for PowerShell
            start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # PowerShell command to get events
            ps_cmd = f"""
            $startTime = [datetime]'{start_str}'
            $endTime = [datetime]'{end_str}'
            Get-WinEvent -FilterHashtable @{{
                LogName = 'System'
                Level = 1,2,3  # Error, Warning, Information
                StartTime = $startTime
                EndTime = $endTime
            }} -MaxEvents 50 -ErrorAction SilentlyContinue | 
            Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName |
            ConvertTo-Json -Depth 1
            """
            
            process = subprocess.Popen(["powershell", "-Command", ps_cmd],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, universal_newlines=True)
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0 or "No events were found that match the specified criteria" in stderr:
                self.logger.warning(f"No relevant events found: {stderr}")
                return []
            
            # Parse the JSON output
            events = json.loads(stdout)
            
            # Ensure we have a list
            if not isinstance(events, list):
                events = [events]
            
            # Process events
            processed_events = []
            for event in events:
                # Convert time string to datetime
                time_str = event.get("TimeCreated", "")
                if time_str:
                    try:
                        time_obj = datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                    except ValueError:
                        time_obj = datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
                else:
                    time_obj = None
                
                processed_events.append({
                    "TimeCreated": time_obj,
                    "Id": event.get("Id", 0),
                    "Level": event.get("LevelDisplayName", ""),
                    "Provider": event.get("ProviderName", ""),
                    "Message": event.get("Message", "")[:200] + "..." if len(event.get("Message", "")) > 200 else event.get("Message", "")
                })
            
            self.logger.info(f"Retrieved {len(processed_events)} system events")
            return processed_events
        
        except Exception as e:
            self.logger.error(f"Error retrieving system events: {e}")
            return []
    
    def generate_html_report(self, crash_metadata, driver_analysis, bugcheck_analysis, event_data):
        """Generate an HTML report with the analysis results."""
        self.logger.info("Generating HTML analysis report...")
        
        # Create a unique filename for the report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_path, f"BSOD_Analysis_{timestamp}.html")
        
        # Get system information
        system_info = self._get_system_info()
        
        # Determine if any critical driver issues were found
        critical_drivers = []
        for driver in driver_analysis:
            for issue in driver.get("KnownIssues", []):
                if issue.get("CurrentVersionAffected") is True and issue.get("OSAffected") is True:
                    critical_drivers.append(driver)
                    break
        
        # Generate the HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BSOD Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #0066cc;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .section {{
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            background-color: #f9f9f9;
        }}
        .summary {{
            background-color: #e6f2ff;
            border-left: 5px solid #0066cc;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #0066cc;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .warning {{
            background-color: #fff3cd;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
        .critical {{
            background-color: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
        .success {{
            background-color: #d4edda;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Windows BSOD Root Cause Analysis Report</h1>
        <p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="section summary">
            <h2>Analysis Summary</h2>
            <table>
                <tr>
                    <th>Attribute</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Crash Dump File</td>
                    <td>{crash_metadata.get("FileName", "Unknown")}</td>
                </tr>
                <tr>
                    <td>Crash Time</td>
                    <td>{crash_metadata.get("CreationTime", "Unknown")}</td>
                </tr>
                <tr>
                    <td>Bugcheck Code</td>
                    <td>{bugcheck_analysis.get("BugcheckCode", "Unknown")} ({bugcheck_analysis.get("BugcheckName", "Unknown")})</td>
                </tr>
                <tr>
                    <td>Primary Cause</td>
                    <td>{bugcheck_analysis.get("Description", "Unknown")}</td>
                </tr>
                <tr>
                    <td>System</td>
                    <td>{system_info.get("Manufacturer", "Unknown")} {system_info.get("Model", "Unknown")}</td>
                </tr>
                <tr>
                    <td>Operating System</td>
                    <td>{system_info.get("OSName", "Unknown")} (Version {system_info.get("OSVersion", "Unknown")})</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Bugcheck Analysis</h2>
            <h3>{bugcheck_analysis.get("BugcheckCode", "Unknown")} - {bugcheck_analysis.get("BugcheckName", "Unknown")}</h3>
            <p>{bugcheck_analysis.get("Description", "No description available.")}</p>
            
            <h4>Common Causes</h4>
            <ul>
        """
        
        # Add common causes
        for cause in bugcheck_analysis.get("CommonCauses", []):
            html_content += f"<li>{cause}</li>\n"
        
        html_content += """
            </ul>
            
            <h4>Recommendations</h4>
            <ul>
        """
        
        # Add recommendations
        for recommendation in bugcheck_analysis.get("Recommendations", []):
            html_content += f"<li>{recommendation}</li>\n"
        
        html_content += """
            </ul>
        </div>
        
        <div class="section">
            <h2>Driver Analysis</h2>
        """
        
        # Add driver analysis sections
        for driver in driver_analysis:
            # Determine if this driver has critical issues
            has_critical_issue = driver in critical_drivers
            status_class = "critical" if has_critical_issue else ""
            
            identified_in_crash = "Yes (identified in crash dump)" if driver.get("DriverName") in crash_metadata.get("CrashedDrivers", []) else "No"
            
            html_content += f"""
            <div class="section {status_class}">
                <h3>Driver: {driver.get("DriverName", "Unknown")}</h3>
                <table>
                    <tr>
                        <th>Attribute</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Vendor</td>
                        <td>{driver.get("VendorName", "Unknown")}</td>
                    </tr>
                    <tr>
                        <td>Driver Type</td>
                        <td>{driver.get("DriverType", "Unknown")}</td>
                    </tr>
                    <tr>
                        <td>Current Version</td>
                        <td>{driver.get("CurrentVersion", "Unknown")}</td>
                    </tr>
                    <tr>
                        <td>Currently Installed</td>
                        <td>{driver.get("IsInstalled", False)}</td>
                    </tr>
                    <tr>
                        <td>Identified In Crash</td>
                        <td>{identified_in_crash}</td>
                    </tr>
                </table>
            """
            
            # Add known issues if present
            if driver.get("KnownIssues", []):
                html_content += """
                <h4>Known Issues</h4>
                <table>
                    <tr>
                        <th>Issue Description</th>
                        <th>Affected Versions</th>
                        <th>Current Version Affected</th>
                        <th>Resolution</th>
                    </tr>
                """
                
                for issue in driver.get("KnownIssues", []):
                    issue_class = ""
                    if issue.get("CurrentVersionAffected") is True and issue.get("OSAffected") is True:
                        issue_class = "critical"
                    elif issue.get("CurrentVersionAffected") is True:
                        issue_class = "warning"
                    
                    html_content += f"""
                    <tr class="{issue_class}">
                        <td>{issue.get("IssueDescription", "Unknown")}</td>
                        <td>{issue.get("VersionRange", "Unknown")}</td>
                        <td>{issue.get("CurrentVersionAffected", "Unknown")}</td>
                        <td>{issue.get("Resolution", "Unknown")}</td>
                    </tr>
                    """
                
                html_content += """
                </table>
                """
            else:
                html_content += """
                <p>No known issues found for this driver in the database.</p>
                """
            
            html_content += """
            </div>
            """
        
        # Add message if no critical drivers found
        if not critical_drivers:
            html_content += """
            <div class="success">
                <p>No critical driver issues were found that match the specific BSOD pattern. Consider checking the recommendations for the bugcheck code.</p>
            </div>
            """
        
        html_content += """
        </div>
        
        <div class="section">
            <h2>System Event Log Analysis</h2>
        """
        
        # Add event log data
        if event_data:
            html_content += f"""
            <p>Found {len(event_data)} relevant events in the System Event Log around the time of the crash.</p>
            <table>
                <tr>
                    <th>Time</th>
                    <th>EventID</th>
                    <th>Level</th>
                    <th>Provider</th>
                    <th>Message</th>
                </tr>
            """
            
            for event in event_data:
                level_class = ""
                if event.get("Level") == "Error":
                    level_class = "critical"
                elif event.get("Level") == "Warning":
                    level_class = "warning"
                
                event_time = event.get("TimeCreated", "")
                if isinstance(event_time, datetime.datetime):
                    event_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
                
                html_content += f"""
                <tr class="{level_class}">
                    <td>{event_time}</td>
                    <td>{event.get("Id", "")}</td>
                    <td>{event.get("Level", "")}</td>
                    <td>{event.get("Provider", "")}</td>
                    <td>{event.get("Message", "")}</td>
                </tr>
                """
            
            html_content += """
            </table>
            """
        else:
            html_content += """
            <p>No relevant System Event Log entries found around the time of the crash.</p>
            """
        
        html_content += """
        </div>
        
        <div class="section">
            <h2>Next Steps and Recommendations</h2>
            <ol>
        """
        
        # Add recommendations based on findings
        if critical_drivers:
            html_content += """
                <li class="critical">Update the following drivers identified with known issues:
                    <ul>
            """
            
            for driver in critical_drivers:
                resolutions = []
                for issue in driver.get("KnownIssues", []):
                    if issue.get("CurrentVersionAffected") is True and issue.get("OSAffected") is True:
                        resolutions.append(issue.get("Resolution", ""))
                
                # Remove duplicates and join
                unique_resolutions = list(set(resolutions))
                resolutions_text = " or ".join(unique_resolutions)
                
                html_content += f"""
                        <li>{driver.get("DriverName", "")} ({driver.get("VendorName", "")}) - {resolutions_text}</li>
                """
            
            html_content += """
                    </ul>
                </li>
            """
        
        html_content += f"""
                <li>Follow the specific recommendations for bugcheck {bugcheck_analysis.get("BugcheckCode", "Unknown")}:</li>
                <ul>
        """
        
        for recommendation in bugcheck_analysis.get("Recommendations", []):
            html_content += f"<li>{recommendation}</li>\n"
        
        html_content += """
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
        """
        
        # Write the report to file
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            self.logger.info(f"HTML report generated: {report_file}")
            return report_file
        except Exception as e:
            self.logger.error(f"Error writing HTML report: {e}")
            return None
    
    def _get_system_info(self):
        """Get basic system information."""
        info = {
            "Manufacturer": "Unknown",
            "Model": "Unknown",
            "OSName": "Unknown",
            "OSVersion": "Unknown",
            "OSBuild": "Unknown"
        }
        
        try:
            # Get computer system info
            ps_cmd = "Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model | ConvertTo-Json"
            process = subprocess.Popen(["powershell", "-Command", ps_cmd],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, universal_newlines=True)
            stdout, _ = process.communicate()
            
            if process.returncode == 0:
                sys_info = json.loads(stdout)
                info["Manufacturer"] = sys_info.get("Manufacturer", "Unknown")
                info["Model"] = sys_info.get("Model", "Unknown")
            
            # Get OS info
            ps_cmd = "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json"
            process = subprocess.Popen(["powershell", "-Command", ps_cmd],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, universal_newlines=True)
            stdout, _ = process.communicate()
            
            if process.returncode == 0:
                os_info = json.loads(stdout)
                info["OSName"] = os_info.get("Caption", "Unknown")
                info["OSVersion"] = os_info.get("Version", "Unknown")
                info["OSBuild"] = os_info.get("BuildNumber", "Unknown")
                
            return info
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return info
    
    def export_to_json(self, data, filename=None):
        """Export analysis data to JSON for programmatic use."""
        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_path, f"BSOD_Analysis_{timestamp}.json")
        
        try:
            # Convert datetime objects to strings for JSON serialization
            def json_serial(obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                raise TypeError(f"Type {type(obj)} not serializable")
            
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, default=json_serial, indent=4)
            
            self.logger.info(f"Analysis data exported to JSON: {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}")
            return None
    
    def analyze(self, target_dump_file=None):
        """Run the complete analysis process."""
        self.logger.info("==== Windows BSOD Root Cause Triage Tool ====")
        self.logger.info(f"Starting analysis at {datetime.datetime.now()}")
        
        # Initialize environment
        self.initialize_environment()
        
        # Get the crash dump to analyze
        if not target_dump_file:
            dump_file = self.get_latest_crash_dump()
            if not dump_file:
                self.logger.error("No crash dump files found to analyze. Exiting.")
                return None
        else:
            if not os.path.exists(target_dump_file):
                self.logger.error(f"Specified dump file not found: {target_dump_file}")
                return None
            dump_file = target_dump_file
        
        # Extract metadata from crash dump
        self.crash_metadata = self.extract_dump_metadata(dump_file)
        
        # Analyze bugcheck code
        self.bugcheck_analysis = self.analyze_bugcheck(self.crash_metadata)
        
        # Analyze drivers
        self.driver_analysis = self.analyze_drivers(self.crash_metadata)
        
        # Get event log data
        event_data = self.get_event_log_data(self.crash_metadata.get("CreationTime", datetime.datetime.now()))
        
        # Create complete analysis data
        analysis_data = {
            "GeneratedOn": datetime.datetime.now(),
            "SystemInfo": self._get_system_info(),
            "CrashInfo": {
                "DumpFile": self.crash_metadata.get("FileName", ""),
                "CrashTime": self.crash_metadata.get("CreationTime", ""),
                "BugcheckCode": self.bugcheck_analysis.get("BugcheckCode", ""),
                "BugcheckName": self.bugcheck_analysis.get("BugcheckName", ""),
                "Description": self.bugcheck_analysis.get("Description", "")
            },
            "BugcheckAnalysis": self.bugcheck_analysis,
            "DriverAnalysis": self.driver_analysis,
            "EventData": event_data
        }
        
        # Export data to JSON
        json_file = self.export_to_json(analysis_data)
        
        # Generate HTML report
        html_file = self.generate_html_report(self.crash_metadata, self.driver_analysis, 
                                             self.bugcheck_analysis, event_data)
        
        # Try to open the report
        if html_file and os.path.exists(html_file):
            try:
                os.startfile(html_file)
            except AttributeError:
                # os.startfile is Windows-specific
                self.logger.warning(f"Could not automatically open the report. Please open manually: {html_file}")
        
        self.logger.info("==== Analysis Complete ====")
        self.logger.info(f"Results saved to: {self.output_path}")
        
        return analysis_data


def main():
    """Main function to parse arguments and run the analyzer."""
    parser = argparse.ArgumentParser(description="Windows BSOD Root Cause Triage Tool")
    parser.add_argument("--dump", "-d", help="Path to specific crash dump file to analyze")
    parser.add_argument("--output", "-o", help="Directory to store analysis results")
    parser.add_argument("--kb", "-k", help="Path to bugcheck knowledge base JSON file")
    parser.add_argument("--drivers", "-r", help="Path to known bad drivers database JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set up logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize analyzer
    analyzer = BSODAnalyzer(
        dump_path=None if not args.dump else os.path.dirname(args.dump),
        output_path=args.output,
        kb_path=args.kb,
        drivers_db_path=args.drivers
    )
    
    # Run analysis
    analyzer.analyze(args.dump)


if __name__ == "__main__":
    # Check for administrator privileges
    if os.name == 'nt':
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
        if not is_admin:
            print("WARNING: This script works best with administrator privileges.")
            print("Some functionality may be limited.")
            print("Please restart as administrator for full functionality.\n")
    
    main()
