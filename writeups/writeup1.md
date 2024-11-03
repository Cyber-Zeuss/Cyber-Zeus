# Suspicious Activity Investigation in SRL Network - Based on FOR508 Methodology

## 1. Introduction 
Welcome to part one of our investigation series into some strange happenings at the Stark Research Labs network. We will solve the case of the FOR508 following a structured approach based on the SANS FOR508 course, breaking down our findings into a series of chapters and labs. If you've taken the FOR508 course, you'll see how closely our writeups align with its systematic methodology, showcasing how we can apply the skills and techniques from the classroom to real-world scenarios.

How? By deep diving into this investigation, with the right tools and workflows to find out what really went wrong. This series of writeups will be both a technical analysis and a how-to guide for the person who wants to learn the ins and outs of Digital Forensics and Incident Response (DFIR).

## 2. Background of Case
So, let's set the scene. SRL is a government-supported research facility committed to the most advanced developments in the field of metal alloys and bioengineering technologies. Currently, they are working on a top-secret project connected with the reproduction of the formula of the Carbonadium alloy, widely known for its outstanding properties. About two years of painstaking work headed by T.A. finally brought its first fruit. Dungan, the project was almost at the finish line when the SRL network suddenly started malfunctioning and raised alarms about possible espionage or sabotage.

## 3. Timeline of Incident
Following is a short summary of what happened:

- **September 5, 2018**: The IT staff sensed that something was wrong. They reported that the Exchange server was down, and the web server was unstable.
- **September 6, 2018**: IT Security Analyst C. Barton initiated a preliminary investigation. He utilized the Kansa Incident Response Framework in order to obtain memory images with F-Response.
- **Days Following**: Soon realizing that this was a bit beyond their realm of expertise, SRL decided to hire a third-party DFIR consulting firm for more comprehensive analysis.

## 4. Environment Overview
Now, about the configuration of the SRL network: It's your typical medium-sized enterprise architecture, but with a variety of advanced security controls, such as those listed below.

- **Domain**: "SHIELDBASE", Windows Server 2016
- **Event Log Forwarding**: Enabled on all systems; this greatly aids in central monitoring.
- **Win-RM**: Fully enabled to ensure ease of remote management.
- **PowerShell**: PowerShell 5 is installed on all systems.
- **Patching**: They ensure all systems stay up-to-date with auto-updates.
- **Endpoint Protection**: AV, HIPS, and management are provided by the McAfee Complete Endpoint Threat Protection suite via ePolicy Orchestrator.
- **User Privileges**: Users are standard users on their machines—no administrative rights.
- **Exchange Server**: An Exchange 2016 server running on Windows Server 2016.
- **Firewall Rules**: Inbound and outbound traffic is tightly controlled, and all systems access the web via proxy.
- **Unique Admin Credentials**: All local admin accounts are provided strong, unique passwords.

[Download SRL Network Architecture PDF](/images/writeup1/SRL_Diagram_and_Host_List_v2.pdf)

## 5. Initial Response and Data Collection
The initial response was remarkably quick, taking out memory dumps and disk images from central servers like the Exchange and web servers. Through subsequent days, they stepped up the pace of their work, capturing additional evidence like triage images and network logs to determine what actually happened.

## 6. Evidence in Hand to Date
What we have in our heap of evidence so far:

- **Memory Dumps**: These would be taken from key servers in order to identify any running processes, malicious code, or hidden artifacts.
- **Disk Images**: These are complete captures done to dig up hidden files, malware, and signs of lateral movement.
- **Network Artifacts**: Logs and packets collected during the suspected attack windows to track any command and control (C2) activity.
- **Triage Images**: Fast shots of file systems in order to spot something out of the ordinary.

## Roadmap of the Case 

### **Chapter 1: Malware Persistence**
**Brief:**  
In this chapter, we will investigate the presence of malware persistence mechanisms within the SRL environment. Attackers often establish persistence to survive system reboots and maintain access. We will focus on how malware may embed itself into the system by leveraging autoruns, scheduled tasks, services, and other operating system features.

**Tools and Techniques:**
- **Autoruns and Registry Checks:** Analyze autostart locations such as startup folders and registry keys.
- **Windows Services:** Investigate running and failed services for persistence.
- **Scheduled Tasks:** Review scheduled tasks that may be used to execute malicious payloads.
- **WMI Event Consumers:** Examine for any abnormal or malicious event subscriptions.
- **Kansa:** Perform Kansa stacking and collection to analyze system anomalies across the environment.
  
---

### **Chapter 2: Evidence of Execution**
**Brief:**  
We will identify and analyze artifacts that indicate the execution of malicious processes or tools on the compromised systems. Various Windows forensic artifacts will help trace back the attacker's activities and timeline.

**Tools and Techniques:**
- **Prefetch Analysis:** Examine prefetch files to identify recently executed programs.
- **Shimcache & Amcache:** Review these databases for forensic evidence of program execution.
- **AppCompatProcessor:** Utilize this tool to parse compatibility databases for evidence of historical executions.
- **EvtxECmd (Event Log Analysis):** Identify credential use and track lateral movement via Windows event logs.
- **PowerShell/WMI Logs:** Investigate logs for signs of malicious PowerShell or WMI usage.

---

### **Chapter 3: Memory Forensics and Rogue Process Identification**
**Brief:**  
This chapter will involve the analysis of memory dumps to detect rogue processes and evidence of code injection, a common method used by attackers to conceal their presence.

**Tools and Techniques:**
- **Volatility Framework:** Perform memory forensics to identify rogue processes and artifacts.
- **Memory Baseliner Tool:** Compare memory snapshots to baseline activities.
- **MemProcFS:** Use MemProcFS to detect code injection and hidden processes.
- **Rootkit Detection:** Investigate memory dumps for rootkit behavior and hidden drivers.

---

### **Chapter 4: Malware Discovery**
**Brief:**  
This chapter will focus on finding unknown malware binaries on the disk and determining their capabilities. We'll utilize signature-based and behavioral analysis techniques to classify and analyze malicious files.

**Tools and Techniques:**
- **DensityScout and Sigcheck:** Identify unusual files based on size and signature verification.
- **YARA Rules:** Apply YARA signatures to classify known malware.
- **CAPA:** Analyze binaries to determine their functionalities and potential malicious behavior.

---

### **Chapter 5: Timeline Creation and Analysis**
**Brief:**  
A forensic timeline is an invaluable tool in incident response. In this chapter, we will create a timeline of file system activity and super timeline on infected machines to understand what happened when and to correlate those events with the attacker’s actions.

**Tools and Techniques:**
- **Plaso (Super Timeline Creation):** Use Plaso to generate a comprehensive timeline of file activities.
- **ELK Stack:** Employ ELK for scalable timeline analysis across multiple systems.
  
---

### **Chapter 6: Volume Shadow Copy and Anti-Forensics Detection**
**Brief:**  
Attackers sometimes leverage Volume Shadow Copies (VSS) to hide or manipulate data. We will examine VSS images and analyze anti-forensics techniques such as timestomping and file deletion.

**Tools and Techniques:**
- **VSS Timeline Creation:** Create a timeline from VSS snapshots and examine crucial changes.
- **Velociraptor & Indx2Csv:** Analyze directory slack and $I30 files to identify manipulation attempts.
- **Timestomp Detection:** Use Velociraptor notebooks to detect altered timestamps.
  
---

### **Chapter 7: Advanced Data Recovery**
**Brief:**  
When attackers attempt to delete or overwrite data, forensic techniques can still recover critical information. This chapter will explore various carving and data recovery techniques to retrieve lost or hidden evidence.

**Tools and Techniques:**
- **NTFS Carving:** Recover deleted files and metadata from NTFS file systems.
- **Event Log (EVTX) Carving:** Recover logs that have been deleted or partially overwritten.
- **MFT and USN Journal Analysis:** Recover detailed file metadata and journaling records.
- **Volume Shadow Copy Carving:** Recover previous versions of files hidden within VSS snapshots.
  


Each chapter builds on the previous one, adding depth to the investigation and uncovering crucial forensic artifacts that will ultimately lead to understanding the full scope of the SRL network compromise. This structure ensures comprehensive coverage, from initial memory analysis to advanced recovery methods.
## As we prepare Chapter 1 we are expected to do two major write-ups:

### 1- Identifying Malware Persistence
First, we'll go over several persistence mechanisms by utilizing several methods:

- **AutoStart Locations**: Check the standard registry keys, startup folders, and autorun entries for malware.
- **Creation/replacement of Services**: Check Windows services for unauthorized or suspicious services.
- **Service Failure Recovery**: Search in services for mechanisms that ensure malware will restart in case of a crash.
- **Scheduled Tasks**: Search for tasks that may have been scheduled to run malicious binaries on a schedule.
- **DLL Hijacking**: Analyze DLL paths for any legitimate DLLs that have been removed or hijacked.
- **WMI Event Consumers**: Check WMI for any event subscriptions of a malicious nature that may be firing attacker code.
- **Advanced Searches**: Look for persistence methods such as Local Group Policy changes, MS Office Add-Ins, and BIOS Flashing.


This write-up will go in-depth into each method as we detail the tools and steps that we will take in finding the persistence techniques hidden within the SRL environment.

### 2- Kansa Stacking Collection and Analysis
The second write-up will cover Kansa Stacking Collection and Analysis. With it, we will:

- Use stacking techniques to find data anomalies across the environment.
- Correlate our findings for any verification of whether similar indicators of compromise pop up on other systems.

Each write-up will be a detailed account of our process, the tools we utilized, and our findings as each progresses through the exact structure and analysis methodology presented within the FOR508 course.

Well, stay tuned as we do a deep dive into Chapter 1 and start unwinding all the suspicious activities running in the background at SRL!
