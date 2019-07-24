# SEP_Application_Control

Documentation will be updated. Please use the WORD document meanwhile






APPLICATION CONTROL RULES FOR DEFENDING AGAINST ADVANCED ATTACKS BY MALWARE AND HACKERS 
By Gleb Glazkov
https://twitter.com/Gl3bGl4z  | glebglaz@protonmail.com
Supported product: Symantec Endpoint Protection 14+
App control rules: Version: (6 GTA)

TABLE OF CONTENTS
Intro	2
Use cases:	3
Notes:	3
Download:	4
Features:	4
Recommendations for use:	5
Known possible issues:	6
Rules:	7
Adversary simulation using Endgame RTA	8
Testing conditions:	9
You Cant fully disable the "Suspicious Behavior Detection" feature but you can change it to "prompt":	10
Reference	13










INTRO
Big changes were made to the new version after a lot of feedbacks that I got from a friend who has implemented the rules in a big organization that tested my last version number 5 and got lots of false positives.


The big changes in this version are:
The testing/implementation flexibility by creating a rules for each windows executable.


The use of arguments in case complete (ZERO TRUST) blocking of executables is not an option, which lowers the false positive rates.





The friend works in a highly discrete defense company so the credit will unfortunately stay untold ;)
Thanks friend!























USE CASES:
•	ZERO TRUST methodology implementation in endpoint protection.
•	Can be used as a secondary security control for prevention or monitoring.
•	For testing EDR/ATP/EPP products against malware samples or RED teaming.
•	For stopping/monitoring RED teaming activity.
•	 For enriching SIEM/MSSP/MDR/SOC logs.


















NOTES:
•	Added PWSH.exe (PowerShell Core).
•	Added Powershell_ISE.exe (Editor).
•	Script types currently include: scr, pif, ps1, bat, vba/vbs.
•	The 6 (GA) version will be tested before release against "Atomic Red by Red Canary" or/and "RTA by Endgame" which are adversary simulation frameworks.
https://github.com/endgameinc/RTA
https://atomicredteam.io/
•	The 6 (GA) version will be released after getting community inputs for false positives and other suggestions.
•	Version 7 (GA) will be compared to "MITRE ATT&K" matrix. https://attack.mitre.org/
•	I highly recommend reviewing the new version of the official Symantec "Hardening Endpoint Protection with an Application and Device Control Policy to increase security" - https://support.symantec.com/us/en/article.tech132337.html
It adds many useful protections.
The most recommended by me are:
Prevents changes to Windows Shell load points (HIPS) [AC12]
Block applications from running out of the recycle bin [AC-25]
HIGH FALSE POSITIVE COUNT:
Prevents changes to system using browser and office products (HIPS) [AC13]
Prevent vulnerable Windows processes from writing code [AC17]




DOWNLOAD:

https://github.com/Gl3bGl4z/SEP_advanced_application_control










FEATURES:
•	"ZERO TRUST" methodology – Block high risk LOLBINS(Living-Off=The-Land-Binaries).
•	Detect lateral movement.
•	Detect reconnaissance commands.
•	Prevent OFFICE exploitation for executing commands or scripts.
•	Prevent Internet Browser exploitation for executing commands or scripts.
•	Prevent popular 3rd party apps exploitation for executing commands or scripts.














RECOMMENDATIONS FOR USE:
1.	Import the rules to SEPM
 
2.	Put in TEST mode
 
3.	Review the "Microsoft recommended blacklist" for executables that may be used in your organizations. https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules
4.	Assign the policy to one testing endpoint or a small test group of testing endpoints.
You may want to create a new group to which you will move the test endpoints.
5.	Watch over the logs for false positives.
6.	In case of false positives. you have the following options:
•	Delete a process/folder/file from the policy.
•	Add an exclusion.
•	Delete the rule.
I personally recommend adding an explicit exclution as much precise as possible. For example: not "myprogram.exe" but rather "%pragramfiles%\myprogram\myprogram.exe".
7.	
•	Edit the rule "compromised CMD"  "known legitimate folder or file"
o	If you are not using Forescout NACm delete the following entries:
%windir%\Temp\fstmpsc\*
C:\Users\*\AppData\Local\Temp\fstmpsc\*
C:\Users\*\AppData\Local\Temp\fstmp\*
%windir%\Temp\fstmp\*
o	If you are not using logon scripts, delete the following entries:
\\\\DOMAIN\.LOCAL\\[^\]*
\\DOMAIN.LOCAL\sysvol\DOMAIN.LOCAL\Policies\{????????-????-????-????-????????????}\User\Scripts\Logon\*.bat
\\DOMAIN.LOCAL\SysVol\DOMAIN.LOCAL\Policies\*.bat
o	If you are not using VNWARE View, delete the following entries:
C:\Program Files\VMware\VMware View\Agent\DCT\*.bat
C:\Program Files\VMware\VMware View\Agent\DCT\*.vbs
8.	After no false positives have been seen, move for testing the policies on more endpoints.
The testing endpoints should represent as much versatility as possible to represent the company/organization. That means – operating systems, software user types.
9.	After enough endpoints have been tested which represent most of the endpoint types in the organization, you may start moving rules to "block" while taking a grace period between each rule change.
10.	Enable sending mail alerts on block events so you can quickly know about a problem that is chased by an application control rule on a new endpoint for different reasons.
11.	After all rules have been moved to "block" you may start a slow migration process by adding more endpoints the group in which your new application control rule is assigned.















KNOWN POSSIBLE ISSUES:
Many rules use REGEX for finding arguments, it my impact endpoint system resource consumption.
If you see an impact try disabling some rules for troubleshooting.

All rules have logging enabled, which may impact disk IO performance on endpoint and other LOG collection mechanisms.














RULES:











ADVERSARY SIMULATION USING ENDGAME RTA

Failed  attack failed
Executed  attack was successful

Results:
at_command	failed
certutil_file_obfuscation	executed
certutil_webrequest	failed
delete_catalogs	executed
delete_usnjrnl	executed
delete_volume_shadow	failed
disable_windows_firewall	executed
enum_commands	failed
findstr_pw_search	executed
installutil_network	failed
Lateral_commands	failed
msbuild_network	failed
mshta_network	failed
msiexec_http_installer	executed
msxsl_network	executed
net_user_ad	failed
office_applicaiton_startup	failed
persistent_scripts	failed
run task	failed
powershell_args	failed
process_extension_anomalies	partial execution
Processname_masquerade	executed
recyclebin_process	executed, can be blocked by official symantec rule
registry hive export	failed
registry_persistence_create	failed
regsvr32_scrobj.y	failed
rundll32+inf_callback	executed
rundll32_ordinal	failed
schtask_escalation	failed
scrobj_com_hijack	executed
sip_provider	failed
smb_connection	executed
suspicious_officE_children	executed but real app will be blocked
system_restore_process_evasion	failed
trust_provider	failed
uac_eventviewer	failed
uca_sdclt	failed
unusual_ms_tool_network	failed
unusual_parent	executed
unusual_process_path	failed
user_dir_escalation	failed
wevtutil_log_clear	failed
wmi_tool_execution	failed







Testing conditions:

 
 
 
 




You Cant fully disable the "Suspicious Behavior Detection" feature but you can change it to "prompt":

 
 

 

 

 





















REFERENCE
https://mgreen27.github.io/posts/2018/02/18/Sharing_my_BITS.html
https://bytesoverbombs.io/living-off-the-land-windows-command-line-downloading-without-powershell-6b3a2b8acd97
https://github.com/pwndizzle/CodeExecutionOnWindows
https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md
https://support.symantec.com/us/en/article.tech188597.html
https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules
https://github.com/endgameinc/RTA
https://github.com/LOLBAS-Project/LOLBAS
https://gtfobins.github.io/
https://github.com/xapax/security/blob/master/privilege_escalation_windows.md

Recommended read:
https://support.symantec.com/us/en/article.tech132337.html
