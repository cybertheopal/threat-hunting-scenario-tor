
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cybertheopal/threat-hunting-scenario-tor/blob/1c76d82c12015d984dd81643066116d837db2905/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-07-14T19:08:13.458056Z`. These events began at `2025-07-14T17:31:55.6509567Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
|where DeviceName == "win10-vm-opal"
|where FileName contains "tor"
|where InitiatingProcessAccountName == "opal"
|where Timestamp >= datetime()| where Timestamp == datetime(2025-07-14T17:31:55.6509567Z)
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
|order by Timestamp desc
```
<img src="https://imgur.com/dB0KjZg.png">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.4.exe". Based on the logs returned, at `2025-07-14T17:31:55.6509567Z`, the user 'opal' on the device "win10-vm-opal" device ran the file `tor-browser-windows-x86_64-portable-14.5.4.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "win10-vm-opal"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img src="https://imgur.com/zTf3Fdw.png">    

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "opal" actually opened the TOR browser. There was evidence that they did open it at `2025-07-14T17:43:04.9369759Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "win10-vm-opal"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img src="https://imgur.com/MBggUJ2.png"> 

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-07-14T17:44:40.7822437Z`, an user on the "win10-vm-opal" device successfully established a connection to the remote IP address `46.166.187.77` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuseropal\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "win10-vm-opal"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img src="https://imgur.com/ygedfbd.png">   

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-14T17:31:55.6509567Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuseropal\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-14T17:31:55.6509567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe /S`
- **File Path:** `C:\Users\labuseropal\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-14T17:43:04.9369759Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuseropal\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-07-14T17:44:40.7822437Z`
- **Event:** A network connection to IP `46.166.187.77` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuseropal\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-07-15T22:42:18.3625916Z` - Connected to `64.65.0.8` on port `443`.
  - `2025-07-15T22:42:20.5677989Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-14T19:08:13.458056Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuseropal\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuseropal" on the "win10-vm-opal" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `win10-vm-opal` by the user `labuseropal`. The device was isolated, and the user's direct manager was notified.

---
