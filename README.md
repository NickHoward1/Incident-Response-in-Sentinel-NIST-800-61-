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

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) - Fill In General - Set Rule Logic (paste query created in log analytic workspace, shown above) - Select Entity Mapping (See screenshot below) - 

<p>
<img src= "" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "" width="300" height="300" /> 
</p>





<h2>PowerShell Suspicious Web Request</h2>

<h2>Potential Impossible Travel</h2>

<h2>Excessive Resource Creation / Deletion</h2>

<h2>Outcome</h2>
