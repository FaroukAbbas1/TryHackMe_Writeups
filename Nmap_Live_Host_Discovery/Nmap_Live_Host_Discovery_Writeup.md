# Nmap_Live_Host_Discovery

# Introduction

**Nmap** is a (Network Mapper) is a open-source tool used for network discovery and security auditing. It also assists in the exploration of network hosts and services, providing information about open ports, operating systems, and other details.

**Nmap** contains a scripting engine can further extend its functionality, from fingerprinting services to exploiting vulnerabilities.

**Nmap** scan usually goes through the steps shown in the figure below, although many are optional and depend on the command-line arguments you provide.

# Subnetworks

**Definition:** A subnet is a smaller network carved out of a larger IP network. Each subnet has its own range of IP addresses and identifier.

**Purpose:** Subnetting makes routing more efficient, reduces congestion, and isolates traffic between groups of devices.

**Analogy:** Think of a city divided into neighborhoods. Delivering mail within the same neighborhood is faster than sending it across the entire city.

**Reconnaissance with ARP**: 

- ARP queries: Address Resolution Protocol is used to map IP addresses to MAC (hardware) addresses.
- Same subnet scanning: If your scanner is inside the same subnet (e.g., `10.1.100.0/24`), ARP can directly discover live hosts by resolving their MAC addresses.
- Different subnet scanning: If you’re on another subnet, packets are routed via the default gateway. ARP queries won’t cross routers because ARP is a link-layer protocol bound to its subnet.
- Implication: ARP-based discovery is powerful but limited to the local subnet. For remote subnets, Nmap must rely on ICMP, TCP, or UDP probes instead.
- Subnet size matters: Larger subnets mean more hosts to scan, which impacts time and noise.
- ARP is local only: Great for discovering devices in your subnet, but ineffective across routers.
- Routers block ARP: Once traffic leaves your subnet, discovery must rely on higher-layer probes.

## Questions:

### **Task 1:**

- From computer1
- To computer1 (to indicate it is broadcast)
- Packet Type: “ARP Request”
- Data: computer6 (because we are asking for computer6 MAC address using ARP Request)

1- How many devices can see the ARP Request: **4**

2- Did computer6 receive the ARP Request: **No**

### **Task 2:**

- From computer4
- To computer4 (to indicate it is broadcast)
- Packet Type: “ARP Request”
- Data: computer6 (because we are asking for computer6 MAC address using ARP Request)

1- How many devices can see the ARP Request: **4**

2- Did computer6 receive the ARP Request: **Yes**

# Enumerating Targets

Before running any scan, you need to tell Nmap *what* to scan. Targets can be specified in different formats depending on scope:

**Scan the List**:
Example:

```powershell
nmap MACHINE_IP scanme.nmap.org example.com
```

This scans 3 distinct hosts: one IP and two domain names.

**Scan the Range:**

Example:

```powershell
nmap 10.11.12.15-20
```

**Scan the Subnet:**
Example:

```powershell
nmap MACHINE_IP/30
```

This scans 4 IP addresses within the `/30` subnet. Subnet notation (CIDR) is powerful for covering entire network segments.

**Scan Files:**

Example:

```powershell
nmap -iL list_of_hosts.txt
nmap --ports-file list_of_ports.txt
```

**Previewing Targets:**

If you want to see which hosts Nmap will scan *without actually scanning them*, use:

```powershell
nmap -sL TARGETS Or Subnet
```

- Performs reverse-DNS lookups to resolve hostnames.
- Reveals naming conventions that may give hints about departments, services, or internal structure.
- To skip DNS resolution, add `n`

## Questions:

### Task 1:

What is the first IP address Nmap would scan if you provided `10.10.12.13/29` as your target?

**`nmap -sL -n 10.10.12.13/29`**

**10.10.12.8**

### Task 2:

How many IP addresses will Nmap scan if you provide the following range `10.10.0-255.101-125`

`nmap -sL -n 10.10.0-255.101-125`

**6400**

# Discovering Live Hosts

## Protocols Used in Scanning

When performing host discovery and reconnaissance, scanners rely on different protocols to check if systems are alive:

- ARP: Works at the link layer. Sends a broadcast asking “Who has this IP?” and receives the MAC address in reply. Effective only within the same subnet.
- ICMP: Commonly used for ping. Type 8 (Echo Request) and Type 0 (Echo Reply) help determine if a host is reachable. Typically preceded by ARP when pinging inside the same subnet.
- TCP: By sending crafted packets to common ports (like 80 or 443), scanners can infer if a host is alive even when ICMP is blocked.
- UDP: Similar to TCP, probes are sent to common UDP ports (like 53 for DNS). Responses or lack thereof help identify active systems.

### Key Point

- ARP is **local only** (cannot cross routers).
- ICMP is often filtered, so TCP/UDP probes are reliable alternatives.

## Questions:

### Task 1:

Send a packet with the following:

- From computer1
- To computer3
- Packet Type: “Ping Request”

1- What is the type of packet that computer1 sent before the ping?

**ARP Request**

2- What is the type of packet that computer1 received before being able to send the ping?

**ARP Response**

3- How many computers responded to the ping request?

**1**

## Task 2:

Send a packet with the following:

- From computer2
- To computer5
- Packet Type: “Ping Request”

What is the name of the first device that responded to the first ARP Request?

**router**

What is the name of the first device that responded to the second ARP Request?

**computer5**

Send another Ping Request. Did it require new ARP Requests? (Y/N)

**N**

# Nmap Host Discovery Using ARP

- **Purpose**: Before scanning ports, it’s crucial to identify which hosts are actually online. ARP (Address Resolution Protocol) is the fastest way to do this on a local subnet.
- **How it works**:
    - ARP sends a broadcast asking “Who has this IP?”
    - Any live host replies with its MAC address.
    - This confirms the host is up and reachable.
- **Scope**: ARP only works within the same subnet (Ethernet/WiFi). It cannot cross routers.

## Nmap ARP Scan

- Command:

```powershell
sudo nmap -PR -sn 10.10.210.6/24
```

- 
    - `PR`: Use ARP for discovery.
    - `sn`: Host discovery only, no port scan.
- Output: Shows which IPs responded with MAC addresses, confirming they are online.

### Example Result

- Nmap scanned 256 IPs in a `/24` subnet.
- Found 4 live hosts, each reporting a MAC address.
- Fast and accurate for local reconnaissance.

## Alternative Tool: arp-scan

- Specialized ARP-based scanner with more options.
- Example:

```powershell
sudo arp-scan -I eth0 -l
```

- Scans all valid IPs on interface `eth0`.
- Produces similar traffic patterns to Nmap ARP scans, visible in Wireshark/tcpdump.

## Key Takeaways

- ARP discovery is **local-only** but highly reliable.
- Nmap (`PR -sn`) and arp-scan both generate ARP queries to identify live hosts.
- Use ARP scans to avoid wasting time probing offline systems.

## Questions:

We will be sending broadcast ARP Requests packets with the following options:

- From computer1
- To computer1 (to indicate it is broadcast)
- Packet Type: “ARP Request”
- Data: try all the possible eight devices (other than computer1) in
the network: computer2, computer3, computer4, computer5, computer6,
switch1, switch2, and router.

How many devices are you able to discover using ARP requests?

**3**

# Nmap Host Discovery Using ICMP

- **Basic idea**: ICMP echo requests (Type 8) are sent to every IP in a subnet. Live hosts reply with ICMP echo replies (Type 0).
- **Command**:
    
    ```powershell
    sudo nmap -PE -sn 10.10.68.220/24
    ```
    
- `PE`: ICMP echo request.
- `sn`: Host discovery only, no port scan

## Variants of ICMP Scans

- **ICMP Echo (**`PE`**)**: Most straightforward, but often blocked by firewalls or host configurations.
- **ICMP Timestamp (**`PP`**)**: Uses Type 13/14 requests and replies. Helpful when echo is blocked.
- **ICMP Address Mask (**`PM`**)**: Uses Type 17/18 requests and replies. Rarely successful, often filtered.

### Example Results

- **Same subnet**: Nmap may rely on ARP replies, showing MAC addresses along with host status.
- **Different subnet**: ICMP packets are routed, so results show hosts up but without MAC addresses.
- **Firewall impact**: Some scans (like `PM`) may return zero hosts if packets are blocked.

## Key Takeaways

- ICMP scans are simple but not always reliable due to filtering.
- Always combine multiple discovery methods (ARP, ICMP, TCP/UDP probes) to avoid blind spots.
- Use `sn` to focus on host discovery without wasting time on port scans.

## Questions:

What is the option required to tell Nmap to use ICMP Timestamp to discover live hosts?

**-PP**

What is the option required to tell Nmap to use ICMP Address Mask to discover live hosts?

**-PM**

What is the option required to tell Nmap to use ICMP Echo to discover live hosts?

**-PE**

# Nmap Host Discovery Using TCP and UDP

## TCP SYN Ping (`-PS`)

- **How it works**: Sends a TCP packet with the SYN flag to a port (default: 80).
    - Open port → replies with SYN/ACK.
    - Closed port → replies with RST.
    - Any reply indicates the host is up.
- **Command**:
    
    ```powershell
    sudo nmap -PS -sn 10.10.68.220/24
    ```
    

**Notes**: Privileged users can send SYN packets without completing the handshake.

## TCP ACK Ping (`PA`)

- **How it works**: Sends a TCP packet with the ACK flag.
    - Target replies with RST (since no connection exists).
    - Response confirms host is online.
- **Command**:
    
    ```powershell
    sudo nmap -PA -sn 10.10.68.220/24
    ```
    

**Notes**: Requires privileged user; default port is 80 unless specified.

## UDP Ping (`PU`)

- **How it works**: Sends UDP packets to target ports.
    - Open UDP port → usually no reply.
    - Closed UDP port → ICMP “Port Unreachable” reply.
    - ICMP response indicates host is up.

## Masscan (Alternative Tool)

- **Approach**: Similar to Nmap but optimized for speed.
- **Examples**:

```powershell
masscan MACHINE_IP/24 -p443
masscan MACHINE_IP/24 -p80,443
masscan MACHINE_IP/24 -p22-25
masscan MACHINE_IP/24 --top-ports 100
```

**Notes**: Very aggressive; useful for large-scale discovery.

### Key Takeaways

- TCP SYN and ACK pings rely on expected TCP behavior to confirm hosts.
- UDP pings depend on ICMP “Port Unreachable” replies.
- Masscan is faster but noisier compared to Nmap.
- Always combine multiple discovery methods to avoid blind spots.

# Using Reverse-DNS Lookup

- **Purpose**: Reverse-DNS queries map IP addresses back to hostnames. Hostnames can reveal useful information about departments, services, or internal naming conventions.
- **Default behavior**: Nmap automatically performs reverse-DNS lookups on online hosts.
- **Options**:
    - `-n`: Skip DNS resolution entirely (faster, stealthier).
    - `-R`: Force DNS lookups even for offline hosts.
    - `-dns-servers DNS_SERVER`: Specify a custom DNS server for queries.

## Key Takeaways

- Reverse-DNS can provide valuable reconnaissance data beyond just IP addresses.
- Skipping DNS (`n`) avoids extra queries and reduces noise.
- Custom DNS servers can be used to bypass restrictions or improve accuracy.

## Questions:

We want Nmap to issue a reverse DNS lookup for all the possibles hosts on a subnet, hoping to get some insights from the names. What option should we add?

**-R**