# Sigma
Sigma-based rule development for platform-agnostic threat detection and SIEM query translation.

By Ramyar Daneshgar


### **What is Sigma?**  
Sigma abstracts the complexities of log-based detections by providing a unified YAML-based structure. This modular design enables analysts to develop detection rules that can be translated into backend-specific SIEM queries, such as Splunk SPL or Elastic Query DSL.

#### **Key Features**:  
- **Vendor Independence**: Sigma removes reliance on proprietary query languages, ensuring cross-platform compatibility.  
- **Behavioral and IOC Detection**: Supports identification of malicious behaviors and known indicators of compromise.  
- **Threat Intelligence Integration**: Facilitates rule-sharing across organizations and teams, aligned with standards like MITRE ATT&CK.  

#### **Sigma Detection Workflow**:  
1. **Rule Format**: Structure detections in YAML, focusing on modularity.  
2. **Conversion**: Leverage tools like **Sigmac** or **Uncoder.io** to generate backend-specific queries.  
3. **Execution**: Deploy translated queries to SIEM environments and monitor for triggered alerts.

---

### **Sigma Rule Syntax**  
Understanding Sigma's structure was essential for create effective detections. Each element in the rule corresponds to a key component of the detection pipeline:  

- **Logsource**: Defines the data source (`product`, `category`, `service`) for log queries.  
- **Detection**: Describes the logic, including search identifiers (e.g., `CommandLine`, `Image`) and their modifiers (`contains`, `startswith`).  
- **False Positives**: Documents scenarios where benign activity might match the rule to reduce alert fatigue.  
- **Tags**: Maps rules to **MITRE ATT&CK** tactics and techniques, enhancing contextual relevance.  

**Example Structure**:  
```yaml
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: "malicious_string"
        CurrentDirectory|startswith: "C:\\Path\\"
    condition: selection
falsepositives:
    - Legitimate admin activity
tags:
    - attack.execution
```

---

### **Rule Writing & Conversion**  

#### **Scenario 1: AnyDesk Installation Detection**  
The first challenge was detecting the silent installation of AnyDesk—a legitimate remote access tool often misused by attackers.

**Steps Taken**:  
1. **Analyzed Threat Intelligence**:  
   - Noted command-line flags (`--install`, `--start-with-win`) used for stealthy installation.  
   - Identified `C:\ProgramData\AnyDesk.exe` as the execution directory.  

2. **Creating Sigma Rule**:  
   - Specified **process_creation** as the log source.  
   - Used `contains` and `all` modifiers for matching multiple conditions.  

**Example Rule**:  
```yaml
title: AnyDesk Installation
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: experimental
description: Detects AnyDesk remote desktop installation.
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all: 
            - '--install'
            - '--start-with-win'
        CurrentDirectory|contains:
            - 'C:\ProgramData\AnyDesk.exe'
    condition: selection
falsepositives:
    - Legitimate AnyDesk installations
level: high
tags:
    - attack.command_and_control
    - attack.t1219
```

3. **Converted and Tested Rule**:  
   - Used **Sigmac** to generate a Splunk query:  
     ```spl
     CommandLine="*--install*" CommandLine="*--start-with-win*" CurrentDirectory="*C:\\ProgramData\\AnyDesk.exe*"
     ```  
   - Validated the query against simulated logs in Kibana to ensure proper detection.

---

#### **Scenario 2: Practical Threats**  
The second task required creating Sigma rules for two distinct threats: malicious scheduled task creation and ransomware activity.

**Task 1: Scheduled Task Creation Detection**  
- **Focus**: Detect execution of `schtasks.exe` to create a task (`spawn`) scheduled for `20:10`.  
- **Detection Logic**:  
  - Targeted `process_creation` logs.  
  - Specified `schtasks.exe` and filtered based on parameters matching malicious usage.  

**Sigma Rule**:  
```yaml
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: 'C:\\Windows\\System32\\schtasks.exe'
        CommandLine|contains: 'create'
    condition: selection
falsepositives:
    - Legitimate scheduled tasks
level: medium
tags:
    - attack.persistence
```

**Task 2: Ransomware Detection**  
- **Focus**: Detect `.txt` file creation indicative of ransomware behavior.  
- **Detection Logic**:  
  - Monitored `file_event` logs.  
  - Correlated file creation with `cmd.exe` execution.  
  - Linked activity to **MITRE ATT&CK T1486** (Data Encrypted for Impact).  

**Sigma Rule**:  
```yaml
logsource:
    product: windows
    category: file_event
detection:
    selection:
        FileName|endswith: '.txt'
        ParentImage|contains: 'cmd.exe'
    condition: selection
falsepositives:
    - Legitimate `.txt` file creations
level: critical
tags:
    - attack.impact
    - attack.t1486
```

**Outcome**:  
The ransomware rule detected the creation of `YOUR_FILES.txt`, containing a note linked to Purelocker ransomware. Event logs revealed the file was created with event ID `11`.

---

### **Lessons Learned**  
1. **Log Source Precision**:  
   Accurately defining the `logsource` field ensures the rule targets relevant events, reducing noise.  

2. **Modifiers Enhance Fidelity**:  
   Leveraging value modifiers (`contains`, `endswith`, `all`) refines detections and minimizes false positives.  

3. **Environment-Specific Validation**:  
   Validating Sigma rules in the operational SIEM ensures compatibility and effectiveness, accounting for differences in field mappings (e.g., `CommandLine.keyword` vs. `process.command_line`).  

4. **MITRE ATT&CK Integration**:  
   Linking rules to tactics and techniques improves threat visibility and enhances reporting for incident response teams.  
