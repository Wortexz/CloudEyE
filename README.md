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
- The initial segments define numerous seemingly random variables and perform pointless mathematical operations (like the while(Bobsledsbandagethallo174<236) loop, which just initializes a variable without affecting execution flow significantly). This is classic junk code intended to waste the time of an automated sandbox or confuse a human analyst.    

- Reading Registry (Persistence/Location):    
```
function Mnda() {
    return Ured.RegRead(sludrehove+"\\SOFTWARE\\Mic"+recon+"osoft\\Windows\\CurrentVersion\\App Paths\\Powe"+recon+"Shell.exe\\");
}
```    

```Noreenshjo10 = Mnda()```    
This attempts to read a registry key, likely to find the path to powershell.exe or wscript.exe. The key structure ``` HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\PowerShell.exe\ ``` is a common path used to locate the PowerShell executable on the system. The use of recon (derived from the initial math) is to reconstruct the string “PowerShell” or similar system utility names, again thwarting simple string matching.    

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
C&C Server is not very known to the security vendors (2026-02-05 11:08:15 UTC):      
<img width="1312" height="462" alt="Screenshot 2026-02-12 161641" src="https://github.com/user-attachments/assets/8c98e3c2-4433-4f93-bb5b-95a67d56a214" />      





