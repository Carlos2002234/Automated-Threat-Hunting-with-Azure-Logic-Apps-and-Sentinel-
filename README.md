# Automated-Threat-Hunting-with-Azure-Logic-Apps-and-Sentinel-

![image](https://github.com/user-attachments/assets/9353ecd1-5646-44a0-a036-acc854aeca23)


Create an automated threat hunting solution using Azure Sentinel and Azure Logic Apps to detect suspicious activities and take appropriate actions such as sending alerts or triggering a response.


1. Prepare the Encoded Command
First, create the PowerShell command you want to execute and encode it in base64.

Example:
Let's say you want to run the Get-Process command. To encode this command:

Open PowerShell.
Run the following script:
powershell
Copy code
$command = 'Get-Process'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$encodedCommand
This will generate a base64-encoded string as output. For example:
JABnAGUAdAAtAHAAcgBvAGMAYwBlcwA=

2. Execute the Encoded Command
Now, you need to execute the encoded command in PowerShell to trigger the detection rule in your monitoring system.

Instructions:
Use the following format to run the encoded command:
powershell
Copy code
powershell.exe -EncodedCommand <your_encoded_command_base64>
Replace <your_encoded_command_base64> with the base64 string you obtained in the previous step.
Example:
powershell
Copy code
powershell.exe -EncodedCommand JABnAGUAdAAtAHAAcgBvAGMAYwBlcwA=
