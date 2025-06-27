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

### 🖥️ System Configuration
The table below details our environment, system requirements, and the OS of each equipment.

| **Equipment**                         | **Type**          | **OS**                            | **Configurations**                                                                 
|---------------------------------------|-------------------|-----------------------------------|--------------------------------------------------------------------------------------------------------------
| **Wazuh Manager Server**              | Cloud (DigitalOcean) | Ubuntu Server 22.04 (LTS) x64  | - Memory: 8 GB  <br> - Storage: 160 GB <br> - Processor: 2 cores                    
| **TheHive Server**                    | Cloud (DigitalOcean) | Ubuntu Server 22.04 (LTS) x64  | - Memory: 8 GB  <br> - Storage: 160 GB <br> - Processor: 2 cores    
| **VM1 + Wazuh-Agent**                 | Virtual              | Windows 10                     | - Memory: 4 GB  <br> - Storage: 50 GB <br> - Processor: 1 core                
| **VM2 + Wazuh-Agent**                 | Virtual              | Ubuntu                         | - Memory: 4 GB  <br> - Storage: 50 GB <br> - Processor: 1 core                            
| **Attacker Machine**                  | Virtual              | Kali Linux                     | - Memory: 4 GB  <br> - Storage: 50 GB <br> - Processor: 2 cores               

> ⚠️ **Note:** I won't cover how to create the virtual machines in detail, as it's a standard procedure. We’ll focus instead on configuring Sysmon on the Windows 10 VM.

### ✅ Step-by-Step: Installing Sysmon on Windows 10

1. **Create the Windows 10 Virtual Machine**  
   Use a [Windows 10 ISO](https://www.microsoft.com/en-us/software-download/windows10) in your preferred virtualization software (VirtualBox, VMware, etc.).

2. **Download Sysmon**  
   - Get the latest [Sysmon release](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) from the Microsoft Sysinternals website.
   - Download the `sysmonconfig.xml` file from the [Sysmon Modular GitHub repository](https://github.com/olafhartong/sysmon-modular).

3. **Set Up Sysmon**  
   - Extract the `Sysmon.zip` archive to a folder.
   - Move the downloaded `sysmonconfig.xml` into that same folder.

4. **Install Sysmon**  
   Open PowerShell **as Administrator**, navigate to the Sysmon folder, and run the following command:
   ```powershell
   .\Sysmon64.exe -i .\sysmonconfig.xml
    ```
   ![sysmon installation on the cloud](https://github.com/user-attachments/assets/3445282c-c6c3-48f7-8615-d3874017169f)

   You can verify that Sysmon was installed successfully with:

   - **Services.msc:** Confirm the presence of Sysmon64 as showed below
     
   ![copy](https://github.com/user-attachments/assets/cb2afeae-0682-4375-8ab7-c261cd4dde1e)

### ☁️ In the Cloud (DigitalOcean): Creating Wazuh & TheHive Droplets

To deploy the SOC solution components in the cloud, we'll create two separate Droplets (virtual machines),  one for **Wazuh** and one for **TheHive**, using [DigitalOcean](https://www.digitalocean.com/).

#### 🔧 Droplet Configuration

- **Image:** Ubuntu 22.04 (LTS)
- **Plan:** Basic CPU
- **Memory:** 8 GB RAM
- **Storage:** 160 GB SSD
- **Processor:** 2 vCPUs
- **Hostname:** 
  - `Wazuh` for the Wazuh server
  - `TheHive` for the TheHive server
- **Authentication:** Set a strong root password or use SSH keys

#### 🔒 Securing Access: Configure a Basic Firewall

Since these Droplets are accessible over the internet via SSH, it's essential to limit exposure to potential threats using DigitalOcean's built-in firewall.

##### 🚧 Steps to Set Up a Firewall:

- Navigate to: Networking > Firewalls
- Create Inbound & Outbound rules to limit Incoming/Outcoming TCP and UDP traffic to your IP address.

  ![lastfirewall2](https://github.com/user-attachments/assets/2418f8d0-8242-4c89-91eb-dc94e6453d50)

  ![2- firewall](https://github.com/user-attachments/assets/2716c5e7-2871-4f6a-9576-df63c0ab93cb)

  ##### Apply the Firewall to Your Droplets:
   Select both `Wazuh` and `TheHive` droplets under **"Add Droplets"**.
   ![3- firewall](https://github.com/user-attachments/assets/cbc2b2ee-848f-45a5-a030-6130eddbdf1e)


#### 🔐 Connect to the Wazuh Server via SSH
Once our Droplets are created and the firewall applied to them, let's try to connect to our Wazuh server via SSH using this command :
````
  ssh root@<YOUR_WAZUH_DROPLET_IP>
````
With SSH access confirmed, let's update our system:

````
sudo apt-get update && sudo apt-get upgrade -y
````
Now we are ready to install and configure Wazuh with the curl command located on the [Wazuh Quickstart Guide](https://documentation.wazuh.com/current/quickstart.html).

````
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
````

After running this command, the installation process will begin. Don't forget to take note of the generated password for the "admin" user:

````
User: admin
Password: *******************
````

##### Access the Wazuh Web Interface:

We can now access the Wazuh Dashboard at https://[Wazuh-Droplet-IP]/ and use the credentials to sign in.

![1-connecting to wazuh sever2](https://github.com/user-attachments/assets/396b7379-59a1-42d6-a186-9e3df3292ae0)

Now we have our client machines and Wazuh server up and running. The next step is to install TheHive on our second droplet.


#### 🐝 Install TheHive

We start by installing the necessary dependencies for TheHive: 

````
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
````

Java Installation

````
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
````

Cassandra Installation: Cassandra is the database used by TheHive for storing data.

````
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
````

Elasticsearch Installation: Elasticsearch is used by TheHive for indexing and searching data.

````
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
````

Limit the ElasticSearch RAM usage (so it doesn't crash!):

- nano /etc/elasticsearch/jvm.options.d/jvm.options
- Paste the following:
````
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
````

TheHive Installation:
````
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
````

Once TheHive, Cassandra, and Elasticsearch are installed on your droplet, use the following steps to configure each component properly.

Configure Cassandra:
````
Edit the Cassandra configuration file:
1- sudo nano /etc/cassandra/cassandra.yaml
   - Change cluster_name (optional)
   - Change listen_address:, rpc_address:, and under seed_provider: seeds: to TheHive droplet’s public IP
2- systemctl stop cassandra.service
3- rm -rf /var/lib/cassandra/*
4- systemctl start cassandra.service
5- systemctl status cassandra.service

````




















