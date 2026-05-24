<h1>Incident Response in Sentinel - NIST 800-61</h1>

<h2>Objective</h2>
To develop an understanding of Microsoft Sentinel and how to effectively navigate the platform, using KQL queries to investigate suspicious behaviour related to brute-force attacks, malicious PowerShell activity, impossible travel events, and excessive Azure resource creation or deletion. The aim of this lab was to understand where logs originate from, identify key indicators of suspicious activity, and gain practical experience with the investigation and alert triage process within a SOC environment.


<h2>Environment</h2>
<ul>
  <li>Microsoft Azure, Sentinel & Defender</li>
</ul>

<h2>Tasks Completed</h2>
<ul>
  <li>Brute Force: Created an alert in Sentinel using the KQL query to search for a failed login attemps that were greater than or equal to 10 attempts, triggering and incident in the SIEM. We later than analysed the attack and carried out the IR lifecycle in line with NIST.</li>
  <li> PowerShell Suspicious Web Request: Created an alert in Sentinel using a KQL query to search for a malicious command, Invoke-WebRequest to identify the logs and affected host, as well as searching to see if the command was executed. I then followed the IR lifecycle in line with NIST</li>
</ul>

<h2>Screenshots</h2>

<h2>Virtual Machine Brute Force Detection</h2>

<h3>Creating an Alert Rule</h3>

`DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName 
| where  NumberOfFailures >= 10`

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) -  Enable the Rule -  set Mitre ATT&CK Framework Categories based on the query - Run query every 4 hours - Lookup data for last 5 hours (can define in query) - Stop running query after alert is generated == Yes - Configure Entity Mappings for the Remote IP and DeviceName -Automatically create an Incident if the rule is triggered - Group all alerts into a single Incident per 24 hours - Stop running query after alert is generated (24 hours) - Review & Create`


<p>
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/b12acecd47cb5a35458f083a95eb1f7ad48321e2/Screenshot%202026-05-18%20at%2009.44.36.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/166041a45f01d65f1aa4b803178fdd91e111421d/Screenshot%202026-05-18%20at%2010.20.54.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/97345e06b44a6cab52570c6b53797a523a1ba28b/Screenshot%202026-05-18%20at%2010.44.47.png" width="300" height="300" /> 
</p>

<b>Screenshot1:</b> Shows me creating the alert using the KQL query that was tested in the log workspace analytics.<br>
<b>Screenshot2:</b> Shows the alert has been triggered as an incident under Threat Management.<br>
<b>Screenshot3:</b> Shows the investigation map breaking down all the Public IP address that attemped a Brute Force Attack, as well as the targeted Hosts. To obtain this map, I assigned the alert to myself and changed the status to active. *Important to write these note down the IP & targeted host addresses. 

In a real-world scenario, If the login was sucessfull, I would immediately isolate the affected host or device to help prevent lateral movement and stop any malware or ransomware that may have already been executed from spreading further across the environment. I would also initiate an anti-virus or endpoint scan as part of the containment process.

Using Microsoft Defender for Endpoint, I would navigate to the affected device under the Assets/Devices section and apply device isolation and containment actions before escalating the incident to a senior SOC analyst for further investigation and remediation activities.

To see if the brute force attempt was successful use the KQL query below, if nothing shows the attempt was unsucessful. 

`DeviceLogonEvents
| where RemoteIP in ("185.156.73.169")
| where ActionType != "LogonFailed"`

In some cases I would have to create a Network Security Group Rule in Azure in response to the brute force attack. Attackers scan for open RDP's so they can carry out repeated RDP attempts on port 3389 or SSH brute force on port 22. Process to create the rule below...

<b>Process:</b> `Azure - Network Security Group - Create Port Rule.`

For the final step of the Incident Response you want to declare your findings, you do this by - <b>Process:</b> `Sentinel - Incidents - Search for Incident - Select Incident - View Full Details - Select Activity Log - Post Comment`

<h2>PowerShell Suspicious Web Request</h2>

<h3>Creating an Alert Rule</h3>

`let TargetHostname = "nicks-vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated`

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) - Fill in: Name: - Description: - Enable the Rule - Use ChatGPT to set Mitre ATT&CK Framework Categories based on the query - Run query every 4 hours - Lookup data for last 24 hours (can define in query) - Stop running query after alert is generated == Yes- Configure Entity Mappings:	Account: Identifier: Name, Value: AccountName, Host: Identifier: HostName, Value: DeviceName, Process: Identifier: CommandLine, Value: ProcessCommandLine - Automatically create an Incident if the rule is triggered - Group all alerts into a single Incident per 24 hours - Stop running query after alert is generated (24 hours)`


<p>
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/086e14fe01c709b7d4c2f85a56458f33ee0fc243/Screenshot%202026-05-23%20at%2012.01.27.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/10959ae6b1ef6bdb77155da0647754de9ad061dd/Screenshot%202026-05-23%20at%2012.11.16.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/d4e13bb19febde831fb697856c9e2dd5aa29bb78/Screenshot%202026-05-23%20at%2013.24.14.png" width="300" height="300" /> 
</p>

<b>Screenshot1:</b> Shows me creating the KQL query to find the PowerShell Scripts containing the "Invoke-WebRequests".<br>
<b>Screenshot2:</b> Shows me creating the detection rule so that the incident shows up in Sentinel under Incidents .<br>
<b>Screenshot3:</b> Shows me gathering information and compiling it into notes to then send off to the senior SOC Analyst. <b>Process:</b> `Sentinel - Threat Management - Incidents - Target Host - Assign Owner (Me) - Change Status: Active - View Full Details - Investigate - Copy & Paste Commands found into notes (See below)`

<b>Detection & Analysis Section:</b> This is where you write notes on your findings. 

<b>Layout:</b> Present Investigation below...

<b>Heading:</b> Detection & Analysis

<b>Body:</b> Upon investigating the triggered incident.... (Number of event or name of host) write what you found

<b>Scripts:</b> Copy and paste the scripts 

<b>Commands:</b> For example (portscan.ps1) and then copy and past the URL of the that script into the web search to retrieve the raw command and paste into notes. 

<b>Executed:</b> see KQL query below, if there is a result, the command was executed meaning this will need to be written in the notes and passed of to the SOC2. Copy and paste the query used in the notes as well. 

<b>Containment, Eradication, and Recovery:</b>  

<b>Isolated:</b>  Write that the machine was isloated in MDE and a Anti Virus Scan was carried out. <b>Process:</b>  `MDE - Assets - Devices - Seach for device - Top right corner isolate & Run malware scan`

<b>Close out Incident:</b> Copy and paste notes and condense them using chatGPT. Once you have done this go back to Sentinel log notes in activity log and close Incident. <b>Process:</b> `Sentinel - Threat Management - Incidents - Search for Incident - View Full Details - Activity Log - Post notes - Change Status: Closed`


 `let TargetHostname = "windows-target-1"; // Replace with the name of your target host as it shows up in the logs
let ScriptNames = dynamic(["eicar.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine`

<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/2bfbf15eff46759ff9d5b0547001f546ebba15cf/Screenshot%202026-05-23%20at%2014.11.51.png" width="300" height="300" /> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;


<h2>Potential Impossible Travel</h2>

<h3>Creating an Alert</h3>

`let TimePeriodThreshold = timespan(7d); 
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed`

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) - Fill in: Name: - Description: - Enable the Rule -  set Mitre ATT&CK Framework Categories based on the query - Run query every 4 hours - Lookup data for last 24 hours (can define in query) - Stop running query after alert is generated == Yes- Configure Entity Mappings:	Account: Identifier: AadUserId, Value: UserId, Identifier: DisplayName, Value: UserPrincipalName - Automatically create an Incident if the rule is triggered - Group all alerts into a single Incident per 24 hours - Stop running query after alert is generated (24 hours)`

<p>
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/22ad8328ba34a036a885a92a147e3da329b42fd7/Screenshot%202026-05-24%20at%2011.05.00.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/f4fd0b2fb55173a897c36015c6ec65974803f215/Screenshot%202026-05-24%20at%2011.21.43.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "" width="300" height="300" /> 
</p>

<b>Screenshot1:</b> Shows .<br>
<b>Screenshot2:</b> Shows .<br>
<b>Screenshot3:</b> Shows  .<br>

<b>Detection & Analysis Section:</b> This is where you write notes on your findings. 

<b>Prepare:</b> Document roles, responsibilities, and procedures. Ensure tools, systems, and training are in place.
 

<h2>Excessive Resource Creation / Deletion</h2>

<h2>Outcome</h2>
