This is a write-up on Josh Madakor's LeveledCareers course lab, that can be also found here: https://www.youtube.com/watch?v=RoZeVbbZ0o0

In this lab we'll achieve the following: 
1. Setting up and configuring Azure Entra and Azure Sentinel
2. Setting up and configuring three VMs within Azure (an Ubuntu server, user Windows VM with SQL Server on it, and adversary Windows VM)
3. Setting up and configuring Log Analytics Workspace, NSGs, Workbooks
4. 

# Creating VMs 

Created an Azure trial account and set up Windows 10 VM on EU server with the following specifications: 

![[Pasted image 20240427114711.png]]

![[Pasted image 20240427115057.png]]

![[Pasted image 20240427115110.png]]

As well as set up a virtual network for those machines to be part of: 

![[Pasted image 20240427114654.png]]

Now to create our Linux VM on the same server: 

![[Pasted image 20240427122907.png]]

Our Azure VM page looks lie this: 
![[Pasted image 20240427123738.png]]


# Configuring Azure

Next part is to allow all inbound traffic via Network Security Groups. In order to do so we'll have to create a new rule with low priority number, as it rules with lower priority numbers will always run first. 

We're deleting the default rule that was pre-set by Azure for RDP: 
![[Pasted image 20240427125001.png]]

And creating a new rule: 
![[Pasted image 20240427125041.png]]

Priority of the rule has to be lower than the pre-existing rules created automatically: 
![[Pasted image 20240427125152.png]]

![[Pasted image 20240427125255.png]]

It looks like this when we're creating a new rule. We can customize the rule as we wish, configuring source IPs, ports, destination IPs, Services and Protocols that will be filtered or allowed in: 

![[Pasted image 20240427125350.png]]

And we'll go through the same procedure to allow all inbound traffic for our Linux SSH: 
![[Pasted image 20240427125530.png]]

By this point we have created two VMs and configured Network Security Groups for them by adding a new rule that will allow all inbound traffic & deleting previously generated rule. 


# Adding MS SQL Server

In this part we're adding MS SQL server for the machine. Also turning off Windows Defender for the Windows machine so it does not interfere with our lab.

We can disable Defender from Control Panel of our newly set-up VM: 

![[Pasted image 20240427131818.png]]

This allows us to send ICMP packets from our other VM to this machine and makes it visible on the internet: 

![[Pasted image 20240427131903.png]]

Next, we'll download & install SQL evaluation Server 2019 from the official website: 

![[Pasted image 20240427132238.png]]

![[Pasted image 20240427132407.png]]

![[Pasted image 20240427132509.png]]

![[Pasted image 20240427132549.png]]

Creating a new SysAdmin acc for SQLserver: 
![[Pasted image 20240427132712.png]]

Next we'll instal SSMS: SQL Server Management Studio to connect to SQL and generate logs for us to analyze.

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

In this part we've created and configured our MS SQL Server and also set up log collection for it.
# Logs Generation

We'll create a new Windows VM to try and connect to our servers to generate logs: 
![[Pasted image 20240427144206.png]]


We'll use RDP connection that was open in the first part of this lab to connect to our server.

![[Pasted image 20240427144830.png]]


![[Pasted image 20240427144843.png]]
We'll need to try to log in several times, both failed and successful attempts. This is needed to generate more logs that we can analyze later on. 

Download & install SSMS to our attacker machine as well to try to generate failed login log. 

Another failed attempts: 
![[Pasted image 20240427145901.png]]

Also, just to generate logs - we'll try to SSH to our Linux server here as well: 

![[Pasted image 20240427150114.png]]



![[Pasted image 20240427150141.png]]

Now we're going to check the logs that we've just generated with those failed attempts: 

![[Pasted image 20240427150406.png]]

We can filter out events with **ID 4625** to leave out only failed login attempts via RDP:
Even though we can see our failed attempt - it's only one of many countless attempts that were  made in a short span of time that this VM was on. 


![[Pasted image 20240427150837.png]]


Same goes for our MySQL server that we've tried to log in to. Many failed attempts to log in to the server were spotted. 

![[Pasted image 20240427151127.png]]

Now to check Linux VM logs: 

![[Pasted image 20240427151612.png]]

As this gives us all of the info in non-normalized form - we'll pipe this command into a grep command as well. This way we can clearly see that attempts were made by actual threat actors to compromise our server: 

![[Pasted image 20240427151840.png]]


# Creating Log Analytics Workspace

We'll have to create LAW in order to analyze and ingest all of the logs our machines are generating: 

![[Pasted image 20240429115256.png]]

Add Watchlist to MS Sentinel with geoip.csv file attached to it. This watchlist maps actual IPs of adversaries trying to connect to us onto a map, so we can generate a visual infographic later on. 

![[Pasted image 20240429115337.png]]

Now we can query our LAW for logs collected and analyze them. Azure Sentinel LAW uses KQL that is similar to SQL in nature: 

![[Pasted image 20240429115456.png]]


Now we'll need to enable Cloud Defender for Log Analytics Workspace. 

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

Also add additional custom rules to our Windows Machine: 

![[Pasted image 20240429124952.png]]

**Manually install the Log Analytics Agent on both windows-vm and linux-vm** to make sure that the logs are really being transferred to the LAW 

We can do this by using the following command:

```
wget https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh && sh onboard_agent.sh -w cb13bc2e-62b9-41a5-8446-acd23b85a81a -s cBtn7/FrR9zKLOIq3BUYaCX68sh5Go7cnrP53gAHOE+TxDPnnI9Qh6vtAWH0lhWkyDuak9Enl6+VZg1H1rBI4g== -d opinsights.azure.com
```

# Tennant Level logging

Tennant level logging is required to monitor all of the activities in the Azure itself, not on the level of VMs.

![[Pasted image 20240430112403.png]]


Creating Tenant level logging for Azure: 
Entra ID > Diagnostic Settings > New Diagnostic Setting.

Here we'll need to enable AuditLogs as well as SignInLogs:

![[Pasted image 20240430112918.png]]
![[Pasted image 20240430112928.png]]

Now we'll create a dummy user, log in with it, give it Global Admin Role and remove it afterwards. 

After we've done all that - we can see that logs are coming in:

![[Pasted image 20240430114228.png]]

We can find assigning Global Administrator to our Dummy user: 

![[Pasted image 20240430120031.png]]

As well as all other changes we've made by querying AuditLog:

![[Pasted image 20240430120204.png]]



Queries used: 

- AuditLogs

```
| where OperationName == "Add member to role" and Result == "success"
| where TargetResources[0].modifiedProperties[1].newValue == '"Global Administrator"' or TargetResources[0].modifiedProperties[1].newValue == '"Company Administrator"' 
| order by TimeGenerated desc
| project TimeGenerated, OperationName, AssignedRole = TargetResources[0].modifiedProperties[1].newValue, Status = Result, TargetResources
```

- SigninLogs
```
| where ResultDescription == "Invalid username or password or Invalid on-premise username or password."
| extend location = parse_json(LocationDetails)
| extend City = location.city, State = location.state, Country = location.countryOrRegion, Latitude = location.geoCoordinates.latitude, Longitude = location.geoCoordinates.longitude
| project TimeGenerated, ResultDescription, UserPrincipalName, AppDisplayName, IPAddress, IPAddressFromResourceProvider, City, State, Country, Latitude, Longitude
```

![[Pasted image 20240430125729.png]]

# Subscription Level logging

We go to Monitor > Activity Log > Export Activity Log > Diagnostic Setting

![[Pasted image 20240430130504.png]]

And basically enable everything in here in order to monitor our Subscription activity. As well as configure logs to be sent to our LAW.

![[Pasted image 20240430130539.png]]

Now to test our new logging - we will create Resource Groups & Delete them afterwards. Critical infrastructure RG & Scratch RG were created here. 

![[Pasted image 20240430130824.png]]

Queries Used: 

// Querying for the deletion of critical Resource Groups
```
AzureActivity
| where ResourceGroup startswith "Critical-Infrastructure-"
| order by TimeGenerated
```

// Querying for changes to network security groups
```
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
// Optionally, specific Resource Groups:
// | where ResourceGroup in ("resource-group-1", "resource-group-2") 
| order by TimeGenerated
```

// Deletion activities within a certain timespan
```
AzureActivity
| where OperationNameValue endswith "DELETE"
| where ActivityStatusValue == "Success"
| where TimeGenerated > ago(30m)
| order by TimeGenerated
```

// From Microsoft Defender for Cloud Security Events
```
AzureActivity
| where CategoryValue == "Security"
```

// Just stuff happening on the Management Plane
```
AzureActivity
| where CategoryValue != "Administrative"
```

![[Pasted image 20240430133921.png]]

And we can see this activity being logged in our LAW.

Creating Diagnostics settings for our storage account: 


![[Pasted image 20240430134853.png]]

Creating a key vault and setting up logging for it as well: 

![[Pasted image 20240430135033.png]]

And a DS for key-vault as well: 
![[Pasted image 20240430135634.png]]

# World Maps

Based on all we've done - we'll create a world-maps that show how many attempts to log in were made during the past few days that VMs were active.

Using the JSON files that were provided beforehand we go to MS Sentinel workbooks and -> New Workbook

![[Pasted image 20240501120616.png]]

Go to Advanced editor to input our JSON code

![[Pasted image 20240501125404.png]]

![[Pasted image 20240501125417.png]]

![[Pasted image 20240501125432.png]]

![[Pasted image 20240501125447.png]]


MS Sentinel Analytics Rules:

```
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, DestinationHostName = Computer
| where FailureCount >= 10
```

This queary rule tells us to look for SecurityEvent log entry (log for Windows) with an ID of 4625 (failed login) and sets an arbitrary variable of Failure Count that counts each instance of log entry records that contain same IP address, Event ID, Activity and DestinationHostName parameters. Then it shows us only cases where FailureCount variable is more than 10. 


![[Pasted image 20240501131232.png]]

Create a Azure Sentinel Query rule to make sure that we've got pop-ups:

![[Pasted image 20240501131450.png]]

![[Pasted image 20240501131707.png]]

![[Pasted image 20240501131913.png]]

Now we're try to create an incident in Sentinel to check if rule is working:

![[Pasted image 20240501132239.png]]

Here is our attempt:

![[Pasted image 20240501132431.png]]

Automatic import of Rules for MS Sentinel:

![[Pasted image 20240501133210.png]]


The rule used to detect Brute Force attempt: 

// Brute Force Success Windows

```
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
```


Current Workbooks 02.05.2024 (last 24 hours): 

![[Pasted image 20240502125151.png]]

![[Pasted image 20240502125236.png]]

![[Pasted image 20240502125259.png]]

![[Pasted image 20240502125324.png]]


# Hardening the Environment

Now, we'll try to harden our environment by implementing Regulatory Compliance through Microsoft Defender for Cloud: 

![](Jmadakor/attachments/Pasted%20image%2020240817124453.png)

We're adding NIST 800-53 Rev.5 It will automatically add recommendations to achieve compliance with selected framework. And it will take some actions itself to harden the environment. 

![](Jmadakor/attachments/Pasted%20image%2020240817124539.png)

Turned on checklist for NIST 800-53 in Azure: 

![[Pasted image 20240503175121.png]]


Also we'll be implementing SC-7 Boundary Protection in our environment to harden our security posture

- We'll implement Azure Private Link and Firewall for your Azure Key Vault instance.
- We'll implement Azure Private Link and Firewall for your Azure Storage Account instance.


![[Pasted image 20240503175530.png]]


Current SC-7 according to NIST 800-53 compliance rev 5: 
![[Pasted image 20240504190607.png]]

NSG allowed in: 

![[Pasted image 20240504195347.png]]

Windows RPD Failed Logins: 

![[Pasted image 20240504195405.png]]

![[Pasted image 20240504195751.png]]


And this is how our Network looks after implementing all of the hardening recommendations, Azure Firewall and Private Links for our network. 
