# Project Name

## Overview
Briefly describe what the project is about and its purpose. 

Example:
This project helps to create analytic rules in Azure Security Center to monitor specific activities and generate incidents based on certain queries.

---

## Prerequisites
Before you begin, ensure you have met the following requirements:

- Azure subscription
- Access to Azure Security Center
- Appropriate permissions to create analytic rules

---

## Steps to Set Up

### Step 1: Create a New Analytic Rule
1. Navigate to **Azure Sentinel**.
2. Choose **Analytics** from the menu options.
3. Choose **Scheduled** query rule from the menu options.
4. Configure the rule to generate incident
   
![image](https://github.com/user-attachments/assets/dbff75cb-6d5e-43a8-94d5-3e811d0552ff)


### Step 2: Define Rule Settings
1. Under **Rule name**, enter a descriptive name for the rule (e.g., "Power Shell Encoded Commands Executed").
2. Set the rule Logic and paste KQL query provided
3. Set the **Query scheduling** to run every 10 minutes and Lookup data from the last 5 hours

### Step 3: Provide the Query
1. In the **Query** section, paste the query provided:
   ```kusto
   let EncodedList = dynamic(['-encodedcommand', '-enc']); 
   // For more results use line below en filter one above. This will also return more FPs.
   // let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
   let TimeFrame = 48h; //Customizable h = hours, d = days
   DeviceProcessEvents
   | where TimeGenerated > ago(TimeFrame)
   | where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
   | where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
   | extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
   | extend DecodedCommandLine = base64_decode_tostring(base64String)
   | extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
   | where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
   | summarize UniqueExecutionsList = make_set(DecodedCommandLineReplaceEmptyPlaces) by DeviceName
   | extend TotalUniqueEncodedCommandsExecuted = array_length(UniqueExecutionsList)
   | project DeviceName, TotalUniqueEncodedCommandsExecuted, UniqueExecutionsList
   | sort by TotalUniqueEncodedCommandsExecuted

