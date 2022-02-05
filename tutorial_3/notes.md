Tutorial 3: Network Security Tools
==================================

Packet sniffing and analysis
-----------------------
After booting up the `listener` VM, we can see an exchange of 4 packets:
1. DHCP Discover, sent from 0.0.0.0 to 255.255.255.255 (everyone), which is a request for any DHCP servers on `dirtylan` to offer it a network configuration
2. DHCP Offer, sent from 10.6.66.1, which is `dirtylan`'s DHCP server responding. Within this packet, we can see the offered *client IP address* of **10.6.66.67**, and a *lease time* of 10 minutes. The *lease time* represents when `listener` is meant to ask the DHCP server for permission to continue using the IP address. Note that this can't me enforced by the DHCP server, it is only promising not to offer this IP address to anothre host during this period, unless `listener` releases it first.
3. DHCP Request, sent from 0.0.0.0 advertises that it wants to use the configuration offered.
4. DHCP Acknowledgment, sent from 10.6.66.1 confirms the request.

**Questions**
1. An attacker using `kali-vm` can act as an eavesdropper or participant on the network. However, using ARP poisoning an attecker could become a MITM.
2. An attacker could inpersonate the DHCP server, offering a different IP address to `listener`. For example if it gives `listener` its own IP address, whenever `listener` is meant to recieve packets from the router, the router would forward them to `kali-vm` instead. Alternatively, the attacker could give it the same IP that would be offered by the DHCP server with a higher lease time, and then take this IP address over once the lease provided by the DHCP expires for the same effect.

Port scanning and host discovery
--------------------------------
Running a **TCP SYN scan** on `listener` using the IP address sniffed in the previous section, using `nmap -sS 10.6.66.67`. We obtain the following results:
```
Nmap scan report for 10.6.66.67
Host is up (0.00026s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
53/tcp  open  domain
111/tcp open  rpcbind
MAC Address: 08:00:27:9F:16:45 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds
```
Looking at the packets captured by [**wireshark**](./TCP_SYN_scan_listener.pcapng), and filtering for `tcp.port == 22`, we can see a brief TCP exchange:
*NB: For these packets, the IP 10.6.66.64 corresponds to `kali-vm` (attacker), and 10.6.66.67 corresponds to `listener` (victim)*
1. SYN - sent from `kali_vm` to `listener`, trying to initiate a TCP connection.
2. SYN, ACK - sent in response from `listener` to `kali_vm`, indicating the port is open for TCP connections.
3. RST - sent from `kali_vm` to `listener` halting the connection, as we have gathered the information necessary.

We can note that for the other active ports, the exchange is the same as the one above.

In contrast, if we look at `tcp.port == 23`, which `nmap` has identified as a closed port, we can see the following exchange:
1. SYN - from `kali_vm` to `listener`, same as in the previous exchange trying to initiate a connection.
2. RST, ACK - sent from `listener` to `kali_vm` to indicate that this port is not open for TCP connections.

We now want to run a **UDP scan**. Since we are on the same subnet as `listener`, we don't care about packet loss or stealthiness, so we can make this scan more aggressive. Looking at the `nmap` manual, we can identify the following relevant options:
- `-sU` performs a UDP scan
- `-F` enables "fast mode", scanning rewer ports than the default scanned
- `-r` scans ports consecutively, without randomizing
- `--top-ports <n>` scans the n most common ports
- `-sV` proves open ports to determine service / version info
- `--version-intensity <level>` sets the probe intensity between 0 (light) and 9 (all probes)
- `-T<0-5>` sets a timing template, where higher is faster
- `--max-retries <tries>` caps the number of port scan probe retransmissions (since we don't care about packet loss this can be set to 0)?

Initial run was done using `nmap -sU -r -sV --version-all --max-retries 0`, took wayy too long. Found some extra information on optimizing UDP scans [*here*](https://nmap.org/book/scan-methods-udp-scan.html), tried running another pass using their suggested settings: `nmap -sUV -T4 --version-intensity 0`. This revealed the following:
```
Nmap scan report for 10.6.66.67
Host is up (0.00045s latency).
Not shown: 58 open|filtered udp ports (no-response), 40 closed udp ports (port-unreach)
PORT    STATE SERVICE VERSION
53/udp  open  domain  dnsmasq 2.72
111/udp open  rpcbind
MAC Address: 08:00:27:9F:16:45 (Oracle VirtualBox virtual NIC)
```
Here we see that 2 ports were reached using udp, which were also accessible via TCP as observed before, although we only scanned 100 ports. I tried one last command to scan the top 1000 ports: `sudo nmap -sUV -T4 --top-ports 1000 --version-intensity 0 -v 10.6.66.67`

Analysing some of the traffic using wireshark for `udp.port == 111` showed the following packets:
1. proc-0 Call - Sent by `kali_vm` to `listener`, this was a Portmap protocol packet, which is a protocol that maps the number or version of an Open Network Computing Remote Procedure Call (ONC RPC) program to a port used for networking by that version of the program.
2. Continuation - Sent by `kali_vm` to `listener`, using RPC (Remote Procedure Call) protocol, a message-passing protocol. Not really sure what this does.
3. proc-0 Reply - Sent in response by `listener` indicating a valid service is on this port.

For `udp.port == 53`, we see some more interesting exchanges (all using DNS protocol):
- `kali_vm` sends a server status request to `listener`, which is refused in a response from `listener`
- `kali_vm` sends different Standard query packets to `listener` for version.bind, which get responses from `listener`. Presumably this allows it to determine the version of the service running on port 53.

We are now asked to run a full **TCP and UDP** scan on ALL of `listener`'s ports. We can use the following command: `nmap -sU -sS -p0-65535 -T5 -v`, to try and scan all ports as fast as possible since it'll probably take a while...
The `-v` flag makes output verbose, and this allowed me to see that the TCP SYN scan finished in slightly under 4 seconds, and identified an open port on port 13337/tcp that was previously missed. The UDP scan will take about 2.5 hours -_- I tried re-running the UDP scan with a `--max-rtt-timeout` of 5ms in an effort to speed things up. Based on the wireshark packets inspected earlier, the largest latency seen was slightly under 2ms, with most responses being in less than 1ms. This greatly reduced the estimate scan time to 20 minutes (and growing) -- update, now it's at 1 hour.

Doing 1 more try for UDP using the following: `sudo nmap -sU -p0-65535 --max-rtt-timeout 0.005 --max-retries 2 --min-rate 200 --scan-delay 1 --max-scan-delay 5 -v 10.6.66.67`, this one seems quite stable at 15 mins (fingers crossed). This one actually terminated, and revealed the following:
```
Completed UDP Scan at 22:20, 981.99s elapsed (65536 total ports)
Nmap scan report for 10.6.66.67
Host is up (0.00041s latency).
Not shown: 64702 open|filtered udp ports (no-response), 832 closed udp ports (port-unreach)
PORT    STATE SERVICE
53/udp  open  domain
111/udp open  rpcbind
MAC Address: 08:00:27:9F:16:45 (Oracle VirtualBox virtual NIC)
```
So basically nothing new, although I may have missed some responses due to my low max-rtt-timeout value.

The service offered by port 13337 is unknown, so we need to do a bit more probing to try and identify the service being used. To do this the following command was run: `nmap -sSV --version-all -p13337 10.6.66.67`

This led to the identification of what the port was being used for:
```
PORT      STATE SERVICE VERSION
13337/tcp open  http    Apache httpd 2.4.10 ((Debian))
```
We can conclude that this port is being used to run a web server.

We now want to try to use nmap to scan an the dirtylan subnet. To do this, we first want to check our subnet mask, as follows:
```
$ ifconfig | grep netmask
  inet 10.6.66.64  netmask 255.255.255.0  broadcast 10.6.66.255
  inet 127.0.0.1  netmask 255.0.0.0
```
We have now identified our network as 10.6.66.1/24, so we can scan our local network using `nmap -sP 10.6.66.1/24`, which identified the following:
```
Nmap scan report for 10.6.66.1
Host is up (0.00031s latency).
MAC Address: 08:00:27:A2:E4:C2 (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.6.66.67
Host is up (0.00031s latency).
MAC Address: 08:00:27:9F:16:45 (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.6.66.64
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 1.92 seconds
```
As expected, we have detected 3 hosts, 10.6.66.1 (DHCP server), 10.6.66.67 (`listener`) and 10.6.66.64 (`kali_vm` or ourselves)

**Questions**
1. Nmap could determine if a TCP port was open by checking the response of `listener`, if the response was a **SYN, ACK** the port was open, but if it was a **SYN, RST** the port was closed.
2. Because otherwise the scan takes too long, because nmap is never sure if the response packets are lost and so it might keep trying the same ports. Since everything is on a local network this is not something we need to worry about.
3. No clue what they're on about, maybe I didn't notice anything odd because I just focused on 1 specific port? Tried to get more details on all the open ports: `nmap -sSV --version-all -p21,22,53,111,13337 10.6.66.67`. This did reveal some strange behaviour. We were able to identify some services:
```
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.2
22/tcp    open  ssh?
53/tcp    open  domain  dnsmasq 2.72
111/tcp   open  rpcbind 2-4 (RPC #100000)
13337/tcp open  http    Apache httpd 2.4.10 ((Debian))
```
However, ssh posed an issue, and caused the following to be printed to the terminal:
```
SF-Port22-TCP:V=7.92%I=9%D=1/31%Time=61F85E24%P=x86_64-pc-linux-gnu%r(NULL
SF:,43,"This\x20is\x20not\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"he
SF:llo\"\x20server\.\nType\x20your\x20name:\n")%r(GenericLines,58,"This\x2
SF:0is\x20not\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"hello\"\x20ser
SF:ver\.\nType\x20your\x20name:\nNice\x20to\x20meet\x20you,\x20\r!\n")%r(G
SF:etRequest,66,"This\x20is\x20not\x20an\x20SSH\x20server\x20-\x20it's\x20
SF:a\x20\"hello\"\x20server\.\nType\x20your\x20name:\nNice\x20to\x20meet\x
SF:20you,\x20GET\x20/\x20HTTP/1\.0\r!\n")%r(HTTPOptions,6A,"This\x20is\x20
SF:not\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"hello\"\x20server\.\n
SF:Type\x20your\x20name:\nNice\x20to\x20meet\x20you,\x20OPTIONS\x20/\x20HT
SF:TP/1\.0\r!\n")%r(RTSPRequest,6A,"This\x20is\x20not\x20an\x20SSH\x20serv
SF:er\x20-\x20it's\x20a\x20\"hello\"\x20server\.\nType\x20your\x20name:\nN
SF:ice\x20to\x20meet\x20you,\x20OPTIONS\x20/\x20RTSP/1\.0\r!\n")%r(RPCChec
SF:k,43,"This\x20is\x20not\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"h
SF:ello\"\x20server\.\nType\x20your\x20name:\n")%r(DNSVersionBindReqTCP,43
SF:,"This\x20is\x20not\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"hello
SF:\"\x20server\.\nType\x20your\x20name:\n")%r(DNSStatusRequestTCP,43,"Thi
SF:s\x20is\x20not\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"hello\"\x2
SF:0server\.\nType\x20your\x20name:\n")%r(Hello,5C,"This\x20is\x20not\x20a
SF:n\x20SSH\x20server\x20-\x20it's\x20a\x20\"hello\"\x20server\.\nType\x20
SF:your\x20name:\nNice\x20to\x20meet\x20you,\x20EHLO\r!\n")%r(Help,5C,"Thi
SF:s\x20is\x20not\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"hello\"\x2
SF:0server\.\nType\x20your\x20name:\nNice\x20to\x20meet\x20you,\x20HELP\r!
SF:\n")%r(SSLSessionReq,8A,"This\x20is\x20not\x20an\x20SSH\x20server\x20-\
SF:x20it's\x20a\x20\"hello\"\x20server\.\nType\x20your\x20name:\nNice\x20t
SF:o\x20meet\x20you,\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\xd7\xf7\xba,\xee\x
SF:ea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10
SF:n\0\0\(\0\x16\0\x13\0!\n")%r(TerminalServerCookie,78,"This\x20is\x20not
SF:\x20an\x20SSH\x20server\x20-\x20it's\x20a\x20\"hello\"\x20server\.\nTyp
SF:e\x20your\x20name:\nNice\x20to\x20meet\x20you,\x20\x03\0\0\*%\xe0\0\0\0
SF:\0\0Cookie:\x20mstshash=nmap\r!\n");
```
nmap said they were unable to recognize the service, not sure if this is why everything was weird.
4. We're flooding the network with a lot of traffic, in a very 'in-organic' way. For example, accessing all the ports on a given host is quite strange. Presumably a network administrator could have tools that look out for this sort of behaviour.

Communicating with a server using netcat
----------------------------------------
I initiated a connection with the web server on port 13337 of 10.6.66.67 (**listener**) using `nc 10.6.66.67 13337`. The web server was now waiting for a request from us, I fetched the page at /test using HTTP/1.0 by sending `GET /test HTTP/1.0`. The response was stored in [**test.html**](test.html), we can see that we connected successfully.

We now want to access a page at the path /browsercheck, pretending to use version 331 of the 'Awesome Imperial College London Browser'. I initially tried to spoof the version by specifying the `User-Agent` field of the HTTP request as follows:
```
GET /browsercheck HTTP/1.0
User-Agent: Awesome Imperial College London Browser/331
```
I initially had a typo in my request (specified version 313), but after solving this, I got the binary response I was looking for. Looking at the response header, I noted the content type:
```
HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 18:09:25 GMT
Server: Apache/2.4.10 (Debian)
Connection: close
Content-Type: image/jpeg
```
I resaved the data as a .jpeg
