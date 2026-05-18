<h1>Incident Response in Sentinel - NIST 800-61</h1>

<h2>Objective</h2>

<h2>Environment</h2>
<ul>
  <li></li>
</ul>

<h2>Tasks Completed</h2>
<ul>
  <li></li>
  <li></li>
</ul>

<h2>Screenshots</h2>

<h2>Virtual Machine Brute Force Detection</h2>

<h3>Creating An Alert</h3>

`DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName 
| where  NumberOfFailures >= 10`

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) - Fill In General - Set Rule Logic (paste query created in log analytic workspace, shown above) - Select Entity Mapping (See screenshot below) - Review & Create`

<p>
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/b12acecd47cb5a35458f083a95eb1f7ad48321e2/Screenshot%202026-05-18%20at%2009.44.36.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/166041a45f01d65f1aa4b803178fdd91e111421d/Screenshot%202026-05-18%20at%2010.20.54.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/97345e06b44a6cab52570c6b53797a523a1ba28b/Screenshot%202026-05-18%20at%2010.44.47.png" width="300" height="300" /> 
</p>

<b>Screenshot1:</b> Shows me creating the alert using the KQL query that was tested in the log workspace analytics.<br>
<b>Screenshot2:</b> Shows the alert has been triggered as an incident under Threat Management.<br>
<b>Screenshot3:</b> Shows the investigation map breaking down all the Public IP address that attemped a Brute Force Attack, as well as the targeted Hosts. To obtain this map, I assigned the alert to myself and changed the status to active. *Important to write these note down the IP & targeted host addresses. 

In a real-world scenario, If the login was sucessfull, I would immediately isolate the affected host or device to help prevent lateral movement and stop any malware or ransomware that may have already been executed from spreading further across the environment. I would also initiate an anti-virus or endpoint scan as part of the containment process.

Using Microsoft Defender for Endpoint, I would navigate to the affected device under the Assets/Devices section and apply device isolation and containment actions before escalating the incident to a senior SOC analyst for further investigation and remediation activities.

To check to see if the brute force attempt was successful use the KQL query below, if nothing shows the attempt was unsucessful. 

`DeviceLogonEvents
| where RemoteIP in ("185.156.73.169")
| where ActionType != "LogonFailed"`


<h2>PowerShell Suspicious Web Request</h2>

<h2>Potential Impossible Travel</h2>

<h2>Excessive Resource Creation / Deletion</h2>

<h2>Outcome</h2>
