# SuperWindowsServiceScanner
Windows Service and Security Log Control Script

Description
--------
This script helps detect suspicious services in the system by checking the services and security logs running in the Windows operating system. It basically performs the following tasks:

1. Administrator Rights Check:
- When the script is run, it is checked whether it has the necessary administrator rights.
- If you are not an administrator, you may be asked to run it again as an administrator.

2. Service List Comparison:
- The service list provided by the user (in TXT, CSV or JSON format) is read.
- The services running in the system are compared with the provided list. Services not on the list are marked as suspicious.

3. Security Log Query:

- Depending on the user's request, security logs are scanned over specific Event IDs (4697, 7030, 7031, 7045).

- If there are relevant log records, they are reported in CSV format.

4. Additional Query Options:
- The user can choose one of two options to perform additional research on suspicious services:

a) Google Search: Suspicious service names are searched via Google.

b) VirusTotal Scan: Executable files of suspicious services are scanned with a valid VirusTotal API key provided by the user.

- In this process, unnecessary arguments in the file path are cleaned and the correct hash calculation is performed.

5. Logging:
- All important steps, detections and error messages are recorded in the "Service_Check_Log.txt" file in the script directory.

How to Run?
-------------------
1. Prerequisites:
- PowerShell (Windows PowerShell or PowerShell Core).
- Administrator rights (required for some operations).
- A valid VirusTotal API key if VirusTotal scanning is to be performed.

2. Installing and Running the Script:
- Save the script (for example, SuperWindowsServiceScanner.ps1) to your computer.
- Open PowerShell (as an administrator if possible).
- Change to the directory where the script is located:
cd "Script Folder"
- Run the script with the following command:
.\SuperWindowsServiceScanner.ps1
- When the script starts, follow the on-screen instructions and enter the necessary information (for example, the path to the service list file, the VirusTotal API key, etc.).

3. User Interaction:
- Administrator rights check: Checks whether the script is running with administrator rights.
- Service list file path: Services in the system are compared with the specified list via the provided file path.

- Security log query: Logs are scanned and reported according to specific Event IDs, depending on user request.

- Additional query: Additional query is performed by selecting either Google search or VirusTotal scan options.

Purpose and Goals
--------------------
Purpose:
- To help detect unauthorized or suspicious services in the system by checking Windows services and security logs.
- To provide detailed research (Google and VirusTotal integration) for suspicious services in order to provide additional security to users.

Goals:
- To enable system administrators to detect possible security breaches early by examining services and logs.
- To detect unknown or unauthorized services in the system with the trusted service list provided by the user.
- To provide automatic reporting on suspicious services and integration with external sources (VirusTotal).

Additional Information
------------
- During service detection, the script cleans unnecessary command line arguments from file paths to obtain the correct executable path and performs hash calculation.
- All steps and error messages are recorded in the "Service_Check_Log.txt" file.
- This script is not a full-fledged antivirus solution; it is an additional check and information tool in the system.

Warning
------
- This script does not make automatic changes to the system, but provides information about suspicious services it detects. Be careful when evaluating the results!
- The usage is entirely at the user's own risk! It is recommended to take a system backup before performing any action.
**Remember, the Script is there to HELP you, DO NOT TRUST the results 100%!!!**
