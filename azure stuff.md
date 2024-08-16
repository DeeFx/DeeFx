Lab overview: 

1. Create a Windows 11 VM
![[Pasted image 20240427113151.png]]

![[Pasted image 20240427113230.png]]

![[Pasted image 20240427113236.png]]

## PWDs: 
See all sizes, cheap-ish, strong password
Region: EAST US 2
Name the Resource Group: RG-Cyber-Lab
Name the Virtual Network. NAME IT “Lab-VNet”

windows-vm: 
labuser1
labuserfortuna!1

linux-vm:
labuser2
Labuserfortuna2

SQL server:
sa
labuser1

vm-attack:
labuser3
Labuserfortuna3

![[Pasted image 20240427114654.png]]

![[Pasted image 20240427114711.png]]

![[Pasted image 20240427115057.png]]

![[Pasted image 20240427115110.png]]

Created an Azure trial account and set up Windows 10 VM on EU server with following specs: 


Now to create our Linux VM on the same server: 
... .. .

![[Pasted image 20240427122907.png]]

Our Azure VM page looks lie this: 
![[Pasted image 20240427123738.png]]

Then we allow all inbound traffic by deleting the default rule that was set up by Azure: 
![[Pasted image 20240427125001.png]]
(RDP)
And creating a new rule: 
![[Pasted image 20240427125041.png]]



Priority of the rule has to be lower than the pre-existing rules created automatically: 
![[Pasted image 20240427125152.png]]

![[Pasted image 20240427125255.png]]
![[Pasted image 20240427125350.png]]

Same procedure for linux SSH port rule: 
![[Pasted image 20240427125530.png]]

BY this point we have created two VMs (linux + windows) and configured Network Security Groups for them by adding a new rule that will allow all inbound traffic & deleting previously generated rule. 


## 2nd LAB: 

Adding MS SQL server for the machine. Also turning off Windows Defender for the Win machine 

![[Pasted image 20240427130951.png]]


![[Pasted image 20240427131506.png]]

Executing ipconfig /all in the VM env:

![[Pasted image 20240427131658.png]]

pinging VM from pc

![[Pasted image 20240427131818.png]]

disabling MS.Firewall from the VM

new ping command with FW disabled: 
![[Pasted image 20240427131903.png]]
Installing SQL evaluation: 
![[Pasted image 20240427132238.png]]

![[Pasted image 20240427132407.png]]

![[Pasted image 20240427132509.png]]

![[Pasted image 20240427132549.png]]

creating a new SysAdmin acc for SQLserver: 
![[Pasted image 20240427132712.png]]

Instal SSMS: SQL Server Management Studio to connect to SQL and generate logs for us to analyze: 

Alowing SQL to log as per guide located in https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/write-sql-server-audit-events-to-the-security-log?view=sql-server-ver16: 
![[Pasted image 20240427135007.png]]

![[Pasted image 20240427135143.png]]

![[Pasted image 20240427135345.png]]

![[Pasted image 20240427135430.png]]

And now launch SSMS, login and enable auditing: 

![[Pasted image 20240427135623.png]]

![[Pasted image 20240427135718.png]]

Restart SQL Service now. Try to connect using wrong credentials to check if it works: 
![[Pasted image 20240427135835.png]]

Now we can check Event manager under Windows Logs -> applications to see that our failed login attempt was catalogued: 
![[Pasted image 20240427140001.png]]

Now we check if our Linux machine is working properly: 

![[Pasted image 20240427140338.png]]

## Lab 3

create a new Windows VM to try and connect to our servers to generate logs: 
![[Pasted image 20240427144206.png]]


Windows machine public IP: 20.224.68.238
Linux machine  IP: 51.105.240.228
![[Pasted image 20240427144830.png]]

try to connect to our win machine from our attacker machine using RDP:

![[Pasted image 20240427144843.png]]
several times. 

Download & install SSMS to our attacker machine as well to try to generate failed login log. 

Another failed attempts: 
![[Pasted image 20240427145901.png]]


![[Pasted image 20240427150114.png]]


trying to login to linux  server:
![[Pasted image 20240427150141.png]]Now we're going to check the logs that we've just generated with those failed attempts: 

![[Pasted image 20240427150406.png]]

we can filter out events with ID 4625 to leave out only failed login attempts via RDP![[Pasted image 20240427150837.png]]

Even though we can see our failed attempt - it's only one of many countless attempts that were  made in a short span of time that this VM was on. 

![[Pasted image 20240427151127.png]]

same goes for our MySQL server that we've tried to log in to. Many failed attempts to log in to the server were spotted. 


Now to check Linux VM logs: 

![[Pasted image 20240427151612.png]]
As this gives us all of the info in non-normalized form - we'll pipe this command into a grep command as well: 
This way we can clearly see that attemtps were made by actual threat actors to compromise our server: 
![[Pasted image 20240427151840.png]]


## Lab 4 

Microsoft Entra ID (Azure Active Directory)

![[Pasted image 20240428144959.png]]

Cloud version of MS Active Directory

![[Pasted image 20240428145409.png]]

![[Pasted image 20240428145424.png]]


![[Pasted image 20240428145528.png]]

![[Pasted image 20240428150735.png]]

Active directory users: 
globalreaderjohn - labreader1!
GRjohn@densavchgmail.onmicrosoft.com


subreaderjane - labuser2!
subreaderjane@densavchgmail.onmicrosoft.com

Created and tested two users with: Global Reader rights and Subscription Reader rights to them. 

rgcontributordave - labuser3! Yusu204617
rgcontributordave@densavchgmail.onmicrosoft.com


Lab5  

![[Pasted image 20240429111250.png]]

![[Pasted image 20240429111258.png]]

Create Log Analytics Workspace: 
![[Pasted image 20240429115256.png]]

Add Watchlist to MS Sentinel with geoip .csv file attached to it: 
![[Pasted image 20240429115337.png]]

Now we can query ![[Pasted image 20240429115456.png]]

Log analyticsworkspace 


Enabling Cloud Defender for Log Analytics Workspace: 
![[Pasted image 20240429120845.png]]

![[Pasted image 20240429120857.png]]

![[Pasted image 20240429120933.png]]

![[Pasted image 20240429120951.png]]

As well as turn on data collection for all events - basically event manager for every machine in cloud. 

Created an Azure Storage Account to make sure that we've got a storage for our NSG Flow Logs to be stored in. 

![[Pasted image 20240429124002.png]]

And enabled NSG flow logs for both of our VM machines running on WIndows and Linux. 


Now to create Data Collection Rules for our VMs: 
![[Pasted image 20240429124424.png]]

![[Pasted image 20240429124710.png]]

Also add additional custom rules to our Windows Machine: ![[Pasted image 20240429124952.png]]

**

Manually install the Log Analytics Agent on both windows-vm and linux-vm

** to make sure that the logs are really being transferred to the LAW 


wget https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh && sh onboard_agent.sh -w cb13bc2e-62b9-41a5-8446-acd23b85a81a -s cBtn7/FrR9zKLOIq3BUYaCX68sh5Go7cnrP53gAHOE+TxDPnnI9Qh6vtAWH0lhWkyDuak9Enl6+VZg1H1rBI4g== -d opinsights.azure.com

## Tennant level logging


![[Pasted image 20240430112403.png]]


Creating Tenant level logging for AZure: 
Entra ID -> ![[Pasted image 20240430112918.png]]
![[Pasted image 20240430112928.png]]


dummy_user - labuser4! - dummy_user@densavchgmail.onmicrosoft.com

After we've created a dummy user & logged in with it, as well as given this user Global Admin role & deleted it afterwards - we can see that logs are coming in. 

![[Pasted image 20240430114228.png]]

Now we can find assigning Global Administrator to our Dummy user: 
![[Pasted image 20240430120031.png]]

![[Pasted image 20240430120204.png]]
as well as all other changes we've made by querying AuditLog


attckusr - Hado274234

AuditLogs
| where OperationName == "Add member to role" and Result == "success"
| where TargetResources[0].modifiedProperties[1].newValue == '"Global Administrator"' or TargetResources[0].modifiedProperties[1].newValue == '"Company Administrator"' 
| order by TimeGenerated desc
| project TimeGenerated, OperationName, AssignedRole = TargetResources[0].modifiedProperties[1].newValue, Status = Result, TargetResources

SigninLogs
| where ResultDescription == "Invalid username or password or Invalid on-premise username or password."
| extend location = parse_json(LocationDetails)
| extend City = location.city, State = location.state, Country = location.countryOrRegion, Latitude = location.geoCoordinates.latitude, Longitude = location.geoCoordinates.longitude
| project TimeGenerated, ResultDescription, UserPrincipalName, AppDisplayName, IPAddress, IPAddressFromResourceProvider, City, State, Country, Latitude, Longitude
![[Pasted image 20240430125729.png]]


BREAKGLASS
fortunaTTTglass! - breakglass


## Subscription level logging

We go to Monitor -> Activity Log -> Export Activity Log -> 
![[Pasted image 20240430130504.png]]

![[Pasted image 20240430130539.png]]

And configure logs to be sent to our LAW 

Now to test our new logging - we will create Resource Groups & Delete them afterwards.

![[Pasted image 20240430130824.png]]
Critical infrastructure RG & Scratch RG were created here. 

// Querying for the deletion of critical Resource Groups
AzureActivity
| where ResourceGroup startswith "Critical-Infrastructure-"
| order by TimeGenerated

// Querying for changes to network security groups
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
// Optionally, specific Resource Groups:
// | where ResourceGroup in ("resource-group-1", "resource-group-2") 
| order by TimeGenerated

// Deletion activities within a certain timespan
AzureActivity
| where OperationNameValue endswith "DELETE"
| where ActivityStatusValue == "Success"
| where TimeGenerated > ago(30m)
| order by TimeGenerated

// From Microsoft Defender for Cloud Security Events
AzureActivity
| where CategoryValue == "Security"

// Just stuff happening on the Management Plane
AzureActivity
| where CategoryValue != "Administrative"


![[Pasted image 20240430133921.png]]

and we can see this activity being logged in our LAW

Creating Diagnostics settings for our storage account: 
![[Pasted image 20240430134853.png]]

creating a key vault and setting up logging for it as well: 
![[Pasted image 20240430135033.png]]

And a DS for key-vault as well: 
![[Pasted image 20240430135634.png]]


Based on all we've done - we'll create a world-maps that show how many attempts to log in were made during the past few days that VMs were active.![[Pasted image 20240501120051.png]]

Using the JSON files that were provided beforehand we go to MS Sentinel workbooks and -> 
![[Pasted image 20240501120616.png]]
Go to Advanced editor to input our JSON code

![[Pasted image 20240501125404.png]]

![[Pasted image 20240501125417.png]]

![[Pasted image 20240501125432.png]]

![[Pasted image 20240501125447.png]]


MS Sentinel Analytics Rules

SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, DestinationHostName = Computer
| where FailureCount >= 10

this queary rule tells us to look for SecurityEvent log entry (log for Windows) with an ID of 4625 (failed login) and sets an arbitrary variabl of Failure Count that counts each instance of log entry records that contain same IP address, Event ID, Activity and DestinationHostName parameters. Then it shows us only cases where FailureCount variable is more than 10. 


![[Pasted image 20240501131232.png]]

create a Azure Sentinel Query rule to make sure that we've got pop-ups. 

![[Pasted image 20240501131450.png]]

![[Pasted image 20240501131707.png]]

![[Pasted image 20240501131913.png]]

Now we're try to create an incident in Sentinel to check if rule is working.
![[Pasted image 20240501132239.png]]

here is our attempt. 

![[Pasted image 20240501132431.png]]

Automatic import of Rules for MS Sentinel 

![[Pasted image 20240501133210.png]]


Trying to trigger our Sentinel rules:


// Brute Force Success Windows
let FailedLogons = SecurityEvent
| where EventID == 4625 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer
| where FailureCount >= 5;
let SuccessfulLogons = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;
SuccessfulLogons
| join kind = inner FailedLogons on DestinationHostName, AttackerIP, LogonType
| project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount


ATTACKER user: labuser123!

Current Workbooks 02.05.2024: (last 24 hours)
![[Pasted image 20240502125151.png]]

![[Pasted image 20240502125236.png]]

![[Pasted image 20240502125259.png]]
![[Pasted image 20240502125324.png]]


Implementing Regulatory Compliance

![[Pasted image 20240503175121.png]]

Turned on checklist for NIST 800-53 in Azure.

Implementing SC-7 Boundary Protection in our environment to harden our security posture. 
![[Pasted image 20240503175527.png]]


![[Pasted image 20240503175530.png]]