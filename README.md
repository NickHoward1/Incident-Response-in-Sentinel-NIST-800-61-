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
<b>Screenshot2:</b> Shows the alert has been triggered as an incident under Threat Management.
<b>Screenshot3:</b>


<h2>PowerShell Suspicious Web Request</h2>

<h2>Potential Impossible Travel</h2>

<h2>Excessive Resource Creation / Deletion</h2>

<h2>Outcome</h2>
