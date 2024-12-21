# Project Name : PowerShell Command Encoding Detection and Analysis in Azure Sentinel

## Overview
This project uses Azure Sentinel to detect encoded PowerShell commands on devices. The query identifies events with encoded PowerShell flags, extracts and decodes base64 strings, and summarizes unique decoded commands. The results trigger incidents, activating a playbook that sends an email with detailed information for further investigation

Example:
This project helps to create analytic rules in Azure Sentinel to monitor specific activities and generate incidents based on certain queries.

---

## Prerequisites
Before you begin, ensure you have met the following requirements:

- Azure subscription
- Azure VM to run Powershell Script
- Appropriate permissions to create analytic rules and run PlayBooks

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

### Step 4: Establish a remote connection to the Windows VM using RDP
# Generate an Incident Using a Base64 Encoded PowerShell Command

This guide explains how to generate an incident using a base64 encoded PowerShell command, which will trigger a analytic rule in your monitoring system (e.g., Azure Sentinel).

## Steps:

### 1. Prepare the Encoded Command
- Example command: `Get-Process`
- Encode it in base64 using the following PowerShell script:
  
  ```powershell
  $command = 'Get-Process'
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $encodedCommand = [Convert]::ToBase64String($bytes)
  $encodedCommand
  
- Execute the Encoded Command
- Run the encoded command with the following:

   ```powershell
   powershell.exe -EncodedCommand <your_base64_encoded_command>

### Step 5: Check the generated Incident

<img width="614" alt="image" src="https://github.com/user-attachments/assets/95dff0c8-3a65-4b58-a21e-b8ae207e5b74" />

### Step 6: Create a Logic App to Respond to an Incident

1. Navigate to **Logic Apps** in the Azure portal.
2. Click on **+ Add** from the menu to create a new Logic App.
3. Select the **Consumption Plan** option.
4. Configure the Logic App settings (e.g., name, resource group) and click **Create**.
5. Once the Logic App is created, open the **Logic App Designer**.
6. In the Designer, click **+ New step**, then search for and select **Microsoft Sentinel**. Choose the trigger: **When an incident is created**.
7. Add a new step for **Outlook** to send an email. Select **Send an email (V2)**.
8. Configure the email parameters (e.g., recipient, subject, body) and authenticate with your email account.
9. In the email body, use dynamic content (such as **Description**, **URL**, **Title**) to personalize the message.
10. Test the Logic App workflow locally to ensure it runs correctly and check for any errors.

![image](https://github.com/user-attachments/assets/875e5fdd-b335-45ae-8a7b-f59081ae2ea3)

![image](https://github.com/user-attachments/assets/f4348a2e-969a-484a-a28d-cf22eb4cb277)

### Step 7: Create a Logic App to Respond to an Incident
1. Navigate to **Azure Sentinel**.
2. Choose **Automation** from the menu options.
3. Choose **Create + Automation Rule** 
4. Configure automation rule as shown in ss and create automation rule
![image](https://github.com/user-attachments/assets/6a5e3bd0-7fe2-48c7-bb43-d96587c128fe)









