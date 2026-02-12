# CloudEyE
CloudEyE / GULOADER - targeted campaigns (INFOSTEALERS)    

Today we have a CloudEyE, also known as GuLoader, is a downloader malware that gains entry into a system and then downloads stealer trojans, keyloggers, and Remote Access Tools (RATs).    
CloudEyE is written in Visual Basic and primarily uses legitimate servers like OneDrive, Google Drive or controls compromised servers to execute and deliver additional payloads to devices.    

CloudEyE’s main stage, the shellcode, is known to implement many anti-analysis, anti-debugging tactics and the code is heavily obfuscated.    

In 2026 we saw more and more campaigns in Lithuania.        
__Initial access - Spearphishing email message with a malicious attachment (all campaigns targeted SME).__                

# The interesting things    

Why is this malware unique and interesting?        

__Because it's quite unique, very targeted (spearphishing), hard to detect and pretty sophisticated - multi-stage attack.__    

__ESET Threat Intelligence, APT__ - these specific CloudEyE campaigns are currently classified as "Unattributed Activity," which is used by ESET to categorize and track activities that have not been attributed to a specific known threat actor or group.    

# Malware analysis from code perspective (few examples)    

- Malware is distributed as spearphishing email.    
- Code is heavily obfuscated JavaScript.    
- The code is designed to execute a series of anti-analysis checks, retrieve data from the system, decode a malicious payload, and finally execute it.    
- The initial segments define numerous seemingly random variables and perform pointless mathematical operations (like the while(Bobsledsbandagethallo174<236) loop, which just initializes a variable without affecting execution flow significantly).        
This is classic junk code intended to waste the time of an automated sandbox or confuse a human analyst.    

- Reading Registry (Persistence/Location):    
```
function Mnda() {
    return Ured.RegRead(sludrehove+"\\SOFTWARE\\Mic"+recon+"osoft\\Windows\\CurrentVersion\\App Paths\\Powe"+recon+"Shell.exe\\");
}
```    

```Noreenshjo10 = Mnda()```    
This attempts to read a registry key, likely to find the path to powershell.exe or wscript.exe. The key structure ``` HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\PowerShell.exe\ ``` is a common path used to locate the PowerShell executable on the system. The use of recon (derived from the initial math) is to reconstruct the string "PowerShell" or similar system utility names, again thwarting simple string matching.    

•	Checking for Running Windows (Anti-Analysis):    
```
var Spiritle = Korrekt138.Windows();
// ...
```
It does a lot more things and various tactics (Heavy Obfuscation, Layered Decoding, Anti-Analysis Checks, Leveraging Native Windows Tools, Dropper Functionality).      

__End-to-end chain:__    
1.	Decrypts strings using Base64+XOR key.     
4.	Downloads ``` hxxp://104.168.115[.]74/Osteo.cur``` to ```%APPDATA%\Biocen.Def```      
5.	Reads that file as base64 → decode to ASCII.      
6.	Extracts embedded stage-2 via Substring(228589, 14674)      
7.	Executes stage-2 via IEX.      

# Malware in action        
C&C Server is not very known to the security vendors:            

__2026-02-05 08:52:27 UTC__            

<img width="1624" height="525" alt="Screenshot 2026-02-12 212325" src="https://github.com/user-attachments/assets/5884a61a-2cc2-439a-95b1-f626bc3e125e" />        

__2026-02-05 11:08:15 UTC__            

<img width="1312" height="462" alt="Screenshot 2026-02-12 161641" src="https://github.com/user-attachments/assets/8c98e3c2-4433-4f93-bb5b-95a67d56a214" />      

Reation and execution of secondary payloads via PowerShell, registry-based persistence, cryptographic API abuse, process injection techniques, and potential keylogging behavior. The combination of these behaviors, especially the dynamic PowerShell execution and C2 communication = characteristic of modern fileless malware.        

- Malicious Network Communication: The sample initiates outbound HTTP communication to hxxp://104.168.115[.]74/Osteo.cur

<img width="524" height="151" alt="Screenshot 2026-02-12 211619" src="https://github.com/user-attachments/assets/11816180-39da-471e-9c32-ec0add661768" />            

Exit node: NZ            
IIS Windows Server and open RDP.     
Windows Server 2022            

<img width="767" height="369" alt="image" src="https://github.com/user-attachments/assets/a356922e-7f1b-4c31-af63-619bc57b115b" />            

- Suspicious File Creation in User Profile: ```C:\Users\Administrator\AppData\Roaming\Biocen.Def``` and ```C:\Users\Administrator\AppData\Roaming\Chel```            
- Execution of PowerShell Payloads: The sample launches PowerShell with a command that reads and executes content from the file ```C:\Users\Administrator\AppData\Roaming\Chel```, using dynamic code construction.
- Additionally runs ```C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_mdmkmtkc.kp2.ps1```                 
- Extensive System and File Enumeration: The sample performs broad file and directory enumeration (e.g., via ```FindFirstFileExW``` and ```FindNextFileW``` on system and user directories). Typical of reconnaissance or preparation for further malicious actions.            
- Cryptographic API Abuse: There is heavy use of cryptographic APIs ```CryptAcquireContextA, CryptImportKey, CryptExportKey, CryptCreateHash, CryptHashData```            
- Process Injection and Manipulation Techniques: API calls such as ```NtQueueApcThread``` and ```NtOpenProcess``` with high privileges attempts at process injection or manipulation            
- Potential Keylogging or Input Capture: Frequent use of GetKeyState and installation of window hooks ```SetWindowsHookExW with WH_CALLWNDPROC and WH_GETMESSAGE```            
- Anti-Analysis and Evasion Behavior: The sample repeatedly queries system information classes related to code integrity and uses ```NtDelayExecution```.            

<img width="563" height="558" alt="Screenshot 2026-02-12 210437" src="https://github.com/user-attachments/assets/f2aea13a-16ea-4b8a-a56d-9ea2a1fa3c6c" />            

__Pieces of malware__          

<img width="279" height="66" alt="Screenshot 2026-02-12 205538" src="https://github.com/user-attachments/assets/e2f9fd7b-a4fc-4ae8-96cf-31d022ad3b54" />            
<img width="269" height="110" alt="Screenshot 2026-02-12 205716" src="https://github.com/user-attachments/assets/ae8b5987-ee28-4d28-8aed-599a927f3a50" />            

# IOC's            
- File name (the first stage): SKM_20260502_70631.js            
- SHA-256: 1A7DD5B0BC1E6C3B77625C7C68D2C325E4B0A1B9ADA82E847661C8E9741D2144            
- ESET Detection: PowerShell/CloudEye.DA trojan            

<img width="403" height="222" alt="Screenshot 2026-02-12 205830" src="https://github.com/user-attachments/assets/02b30c10-3bb9-46b0-9f67-ac62281a7e97" />            


# How to stay safe
- Cyber Security training - The easiest way to prevent malware from entering your systems is to make sure that employees don’t download any malicious files in the first place.            
- Keeping your Endpoint Security up-to-date and use best security practices (policies).            
- For advanced security, traceability and investigation - use EDR/XDR solutions.
- Cyber Security services - MDR/SOC.   
