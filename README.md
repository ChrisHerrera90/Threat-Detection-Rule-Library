# KQL Threat-Detection-Rule-Library

### 🔎 Detecting Cryptoming Attack File Names, Command Line Process and Malicious Networking Activities

```kql
let miner_keywords = dynamic([
    "xmrig", "ethminer", "minerd", "cpuminer", "retea", "haiduc", "xrx", "blacku", "xMEu", "black opera", "diicot",
    "263839397", "cnrig", 
    "94c7c6ca6042201ba200a267a5e0aa4b2d467445bda35a234c1c23dc14359eb7",
    "cf7f7112b69767b79eba0a1cce0706945634392f0486bd55b12e044f4d2043ce", 
    "blah"
]);

let miner_processes =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any (miner_keywords)
    | where ProcessCommandLine has_any ("wget", "curl")
    | project ProcTime = Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ReportId;

let miner_network =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort in (333, 14444, 7777, 22, 3389, 4000, 5000, 80, 443)
        or RemoteUrl has_any ("pool", "miner", "xmr", "eth", "crypto")
    | project NetTime = Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, ReportId;

miner_processes
| join kind=inner (miner_network) on ReportId
| sort by ProcTime desc

```

### 🤓 Explanation

✅ "miner_keywords" is defined by several common names of cryptominer software that have been identified in the wild and through threat hunts:
```kql
let miner_keywords = dynamic([
    "xmrig", "ethminer", "minerd", "cpuminer", "retea", "haiduc", "xrx", "blacku", "xMEu", "black opera", "diicot",
    "263839397", "cnrig", 
    "94c7c6ca6042201ba200a267a5e0aa4b2d467445bda35a234c1c23dc14359eb7",
    "cf7f7112b69767b79eba0a1cce0706945634392f0486bd55b12e044f4d2043ce", 
    "blah"
]);
```

✅ "miner_processes" is defined by "miner_keywords" + the addition of any command line process that contains the "wget" and/or "curl" strings. This indicates malicious downloading of payloads onto the endpoint:
```kql
let miner_processes =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any (miner_keywords)
    | where ProcessCommandLine has_any ("wget", "curl")
    | project ProcTime = Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ReportId;
```

✅ "miner_network" is defined by common and known ports and URL strings that are used to maliciously download cryptomining software into an endpoint:
```kql
let miner_network =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort in (333, 14444, 7777, 22, 3389, 4000, 5000, 80, 443)
        or RemoteUrl has_any ("pool", "miner", "xmr", "eth", "crypto")
    | project NetTime = Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, ReportId;
```


---
---
