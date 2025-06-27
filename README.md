# 🚨 Automated SOC Workflows for Incident Response

This repository contains the implementation of my End-of-Studies project: **Automation of SOC Workflows for Incident Response**, built using open-source technologies.

## Introduction
As cyber threats grow in complexity and volume, Security Operations Center (SOC) face increasing pressure to detect, analyze, and respond to incidents quickly and accurately. This project presents a cloud-based solution that automates key SOC workflows from threat detection to incident response using open-source tools. The goal is to minimize manual intervention, reduce response time, and improve operational efficiency in modern cybersecurity environments.

## 📌 Overview

Cybersecurity incidents are rising, and traditional SOCs struggle with alert fatigue, manual workflows, and human error. This project aims to automate threat detection, enrichment, response, and case management to improve SOC efficiency.

By combining Wazuh (SIEM/XDR), Shuffle (SOAR), and TheHive (case management), the system enables:

- Real-time event monitoring from endpoints.
- Automated detection and alerting.
- IOC enrichment using threat intelligence source.
- Email notification and incident case creation.
- Scalable cloud deployment using DigitalOcean.

## 🧱 Architecture

The following diagram illustrates the architecture of the automated Security Operations Center (SOC) built using Wazuh, Shuffle, and TheHive, all hosted on the cloud.

![Architecture](https://github.com/user-attachments/assets/00f685ee-b318-49b9-bbe6-106819adc79f)

### Architecture Summary

Here is a summary of the architecture illustrated above:

1. **Send Events**  
   Endpoints with Wazuh agents installed continuously send telemetry data (logs and security events) to the Wazuh Manager over the internet.

2. **Receive Events**  
   The Wazuh Manager, deployed on the cloud, receives and processes these events in real time.

3. **Send Alerts**  
   When predefined detection rules are triggered, Wazuh sends alerts to the Shuffle SOAR platform.

4. **Enrich IOCs**  
   Shuffle enriches the alerts using threat intelligence sources (e.g., VirusTotal), adding context such as IP reputation or hash classifications.

5. **Create Alerts & Cases**  
   Shuffle forwards enriched alerts to TheHive, automatically generating a new case for the incident.

6. **Send Email**  
   Shuffle notifies the SOC analyst via email about the newly created case and detected threat.

7. **Receive Email**  
   The SOC analyst receives the email containing the alert and case details.

8. **Send Response Action**  
   Based on the analysis, the SOC analyst can initiate a response directly from the email, which is sent back to Shuffle.

9. **Send Response Action**  
   Shuffle processes the analyst's decision and sends a response command (e.g., block IP, isolate endpoint) to the Wazuh Manager.

10. **Perform Responsive Actions**  
   Wazuh executes the response on the target endpoint, effectively mitigating the threat.

## ⚙️ Tools & Technologies

<h3>🛠️ Tools & Their Roles</h3>

<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>Tool</th>
      <th>Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>SIEM + EDR</td>
      <td align="center">
        <img src="images/wazuh.png" alt="Wazuh" width="24" />
      </td>
      <td> Wazuh detects threats and generates alerts</td>
    </tr>
    <tr>
      <td>Case Management</td>
      <td align="center">
        <img src="images/thehive.png" alt="TheHive" width="66" />
      </td>
      <td> TheHive platform organizes alerts and manages security cases</td>
    </tr>
    <tr>
      <td>SOAR (Automation)</td>
      <td align="center">
        <img src="images/shuffle.png" alt="Shuffle" width="50" />
      </td>
      <td> Shuffle automate incident response workflows</td>
    </tr>
    <tr>
      <td>Threat Intelligence</td>
      <td align="center">
        <img src="images/virus-total.png" alt="VirusTotal" width="24" />
      </td>
      <td> VirusTotal enrich data by checking file hash classification or IP address reputation</td>
    </tr>
  </tbody>
</table>

<details>
<summary><strong>🔎 Understanding the Concepts</strong></summary>

#### 🔹 Wazuh
An open-source security platform that provides threat detection, integrity monitoring, incident response, and compliance. It acts as a SIEM and XDR tool.

#### 🔹 Wazuh Agent
Installed on client machines (Windows/Linux), it collects logs, monitors activity, and sends telemetry to the Wazuh Manager.

#### 🔹 Wazuh Manager
Deployed in a cloud environment, the Wazuh Manager serves as the central component for processing and analyzing logs/security events received from Wazuh agents. It evaluates incoming these events in real time using predefined rules and anomaly detection techniques to spot potential threats. When a suspicious activity is detected, it generates alerts and executes predefined actions to quickly respond to and contain the threat.

![6- dashboard](https://github.com/user-attachments/assets/bbfa5010-e4e6-459f-ae5f-07fa69e73ac9)

#### 🔹 Shuffle
Shuffle acts as the Security Orchestration, Automation, and Response (SOAR) component of our system, streamlining incident response through automation. When it receives alerts from the Wazuh Manager, Shuffle initiates a series of key actions:
- IOC Enrichment: Shuffle utilizes open-source intelligence to enhance the detected indicators of compromise (IOCs), improving threat understanding and analysis.
- Integration with TheHive for Case Management: It automatically creates cases in TheHive for each identified threat, facilitating organized investigations, collaborative response, and detailed incident tracking.
- Email Alerting: Shuffle sends notifications to SOC analysts when new alerts are generated, ensuring swift awareness and prompt reaction to potential threats.
- Automate incident responses.

#### 🔹 TheHive
An incident response and case management system where alerts become structured cases for SOC analysts to investigate and manage.

#### 🔹 Responsive Action
Predefined automated steps like isolating hosts, sending alerts, or blocking malicious IP addresses, executed without human intervention to minimize response time.

</details>

## ⚙️Setting up our Environment

The table below details our environment, system requirements, and the OS of each equipment.

| **Equipment**                         | **Type**          | **OS**                            | **Configurations**                                                                 
|---------------------------------------|-------------------|-----------------------------------|------------------------------------------------------------------------------------------------------------------
| **Wazuh Manager Server**              | Cloud (DigitalOcean) | Ubuntu Server 22.04 (LTS) x64  | - Memory: 8 GB  <br> - Storage: 160 GB <br> - Processor: 2 cores                    
| **TheHive Server**                    | Cloud (DigitalOcean) | Ubuntu Server 22.04 (LTS) x64  | - Memory: 8 GB  <br> - Storage: 160 GB <br> - Processor: 2 cores    
| **VM1 + Wazuh-Agent**                 | Virtual              | Windows 10                     | - Memory: 4 GB  <br> - Storage: 50 GB <br> - Processor: 1 core                
| **VM2 + Wazuh-Agent**                 | Virtual              | Ubuntu                         | - Memory: 4 GB  <br> - Storage: 50 GB <br> - Processor: 1 core                            
| **Attacker Machine**                  | Virtual              | Kali Linux                     | - Memory: 4 GB  <br> - Storage: 50 GB <br> - Processor: 2 cores               





