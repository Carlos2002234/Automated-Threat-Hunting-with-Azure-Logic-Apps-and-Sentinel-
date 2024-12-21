# Automated-Threat-Hunting-with-Azure-Logic-Apps-and-Sentinel-

![image](https://github.com/user-attachments/assets/9353ecd1-5646-44a0-a036-acc854aeca23)


Create an automated threat hunting solution using Azure Sentinel and Azure Logic Apps to detect suspicious activities and take appropriate actions such as sending alerts or triggering a response.


# PowerShell Encoded Command Incident Generation

This repository demonstrates how to execute an encoded PowerShell command to trigger detection rules in monitoring systems like **Azure Sentinel**. This process helps you test configurations and ensure your detection rules are working as expected.

## Steps to Execute an Encoded PowerShell Command and Generate an Incident

### 1. Prepare the Encoded Command
First, create the PowerShell command you want to execute and encode it in base64.

#### Example:
Suppose you want to run the `Get-Process` command. To encode it:

1. Open PowerShell.
2. Run the following script:

```powershell
$command = 'Get-Process'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$encodedCommand

