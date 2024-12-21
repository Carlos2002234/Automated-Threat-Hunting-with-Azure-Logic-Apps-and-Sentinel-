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
1. Navigate to **Azure Security Center**.
2. In the left pane, select **Security alerts**.
3. Choose **Analytics** from the menu options.
4. Click on **+ Add new** to create a new analytic rule.

### Step 2: Define Rule Settings
1. Under **Rule name**, enter a descriptive name for the rule (e.g., "Suspicious Sign-In Detection").
2. Choose the **Rule type** (e.g., Custom).
3. Set the **Severity** level based on your organization’s needs.

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

