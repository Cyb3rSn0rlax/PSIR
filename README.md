# PSIR
PowerShell Incident Response

## Description:
PSIR is a PowerShell script that can be used to collect artifacts from a Windows Machine. PSIR is made so it can be used with PowerShell version 2. 

PSIR can be used to:
* Collect Processes Review Information
* Collect Autoruns Information
* Collect & Verify Digital Signatures of All running Processes
* Collect & Verify Digital Signature of All .EXE in C:\ Drive
* Collect All installed applications
* Collect local users accounts
* Collect Local Group Memebership
* Get Prefetch Listing
* Get Scheduled Tasks
* Get Statup Programs
* Get Network Statistics
* Get Smb Sessions connected to the host
* Get ARP Table
* Get Process Tree
* Get all running services with status and start types
* Get information about Windows Service recovery options
* Get Network Configuration
* Get DNS Cache 
* Get Network Routes
* Get task list

## Usage:
- Place the PSIR folder under C:\ drive.
- Make sure Autoruns is whitin the same folder.
- Execute the PSIR.ps1 script.
- A folder will be created at the Desktop location

## To Do:
- [ ] Automate the analytics of the collected artifacts with Jupyter Notebooks
