# Tutorial 3: Network Security Tools

## Packet sniffing and analysis
After booting up the `listener` VM, we can see an exchange of 4 packets:
1. DHCP Discover, sent from 0.0.0.0 to 255.255.255.255 (everyone), which is a request for any DHCP servers on `dirtylan` to offer it a network configuration
2. DHCP Offer, sent from 10.6.66.1, which is `dirtylan`'s DHCP server responding. Within this packet, we can see the offered *client IP address* of **10.6.66.67**, and a *lease time* of 10 minutes. The *lease time* represents when `listener` is meant to ask the DHCP server for permission to continue using the IP address. Note that this can't me enforced by the DHCP server, it is only promising not to offer this IP address to another host during this period, unless `listener` releases it first.
3. DHCP Request, sent from 0.0.0.0 advertises that it wants to use the configuration offered.
4. DHCP Acknowledgment, sent from 10.6.66.1 confirms the request.

### **Questions**
1. An attacker using `kali-vm` could act as an eavesdropper, off-path attacker or man-in-the-middle:
    - *Eavesdropper:* Because promiscuous mode is enabled on `kali-vm`'s `dirtylan` virtual network adapter, they can passively monitor all traffic originating from and destined for hosts on `dirtylan`'s `10.6.66.0/24` subnet (as evidenced by the packet captures that can be performed in Wireshark).
    - *Off-path attacker:* An attacker can also inject new packets into the network.
    - *MITM:* If an attacker performs a rogue DHCP server attack, they may be able to manoeuvre themselves into becoming a MITM against selected hosts on the `dirtylan` network.
2. Two common attacks are DHCP starvation attacks and the rogue DHCP server attack:
    - *DHCP Starvation Attack:* The attacker floods the DHCP server with DHCP Discover/Request packets in an attempt to exhaust the finite supply of IP addresses that the server is able to assign, potentially spoofing the MAC address in each pair of the Discover/Request packets so the server believes that each request is being made by a different client. If this attack is successful, it leads to a denial of service to genuine hosts on the network attempting to use DHCP to configure their networking stack, and they may be unable to use the network unless they can fall back onto a manually-specified networking configuration.
    - *Rogue DHCP Server Attack:* This attack involves setting up a fake DHCP server and convincing hosts on the network to accept configurations offered by it instead of those offered by the genuine DHCP server. It's usually enough to do this by responding to DHCP Discover requests faster than the genuine server, since most hosts will choose between multiple DHCP offers simply by using the configuration offered by the server that responded first. If this attack is successful, it can potentially lead to a man-in-the-middle attack against the host that accepts the rogue configuration. A DHCP offer usually proposes a default gateway to the client, and if the client uses a default gateway under the control of the attacker, all of the client's communication with hosts outside the local subnet will be forwarded via the attacker.

   An attacker could inpersonate the DHCP server, offering a different IP address to `listener`. For example if it gives `listener` its own IP address, whenever `listener` is meant to recieve packets from the router, the router would forward them to `kali-vm` instead. Alternatively, the attacker could give it the same IP that would be offered by the DHCP server with a higher lease time, and then take this IP address over once the lease provided by the DHCP expires for the same effect.

## Port scanning and host discovery
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
- `-F` enables "fast mode", scanning fewer ports than the default scanned
- `-r` scans ports consecutively, without randomizing
- `--top-ports <n>` scans the n most common ports
- `-sV` probes open ports to determine service / version info
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
We have now identified our network as 10.6.66.0/24, so we can scan our local network using `nmap -sP 10.6.66.0/24`, which identified the following:
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

### **Questions**
1. Nmap determines whether a given TCP port is open by attempting to perform the first two legs of the TCP connection handshake. Nmap sends a **SYN** packet to the remote host on the port, and by checking the response of`listener`, it can determine if the port is open or not. If the response was a **SYN, ACK** the port was open, but if it was a **SYN, RST** the port was closed. Nmap also determines whether an intermediate firewall is interfering with traffic between the two hosts, as if neither response is received within a reasonable timeframe, Nmap assumes that a firewall is blocking either the outbound **SYN** packet or the response from the remote host.
2. Unlike TCP, UDP has no concept of a connection. If a packet is sent to a closed UDP port, the remote host's networking stack may reply with an ICMP Destination unreachable packet but isn't compelled to reply at all. Even if a packet is sent to an open port, the service may decide not to reply for arbitrary reasons. This makes it difficult for Nmap to distinguise open ports from closed ports, because nmap is never sure if the response packets are lost (due to network congestion or immediate firewalls for example) and so it might keep trying the same ports.  

   Nmap therefore waits for a response for a short time after sending a UDP probe and retransmits further probes if no response is received to be more certain that the lack of a response is not caused by adverse network effects. Even if this delay only lasts for a couple seconds per port, this means that a full 65,535-port UDP scan could take over 50 hours. Because of this, a timeout (or something more sophisticated) should be applied to the UDP scan of `listener`.  

   Since we're performing a port scan on a local subnet with no firewall, we don't need to worry about adverse network effects, so we can tell Nmap not to retry in the event that a probe goes unanswered (`--max-retries 1`). To complicate matters further, Nmap rate-limits UDP probes (to avoid flooding the network with huge numbers of packets and making it more likely that remote hosts respond with ICMP Destination unreachable packets when closed ports are scanned), wich causes the scan to take even longer. The low default rate limit can be overridden manually (`--min-rate 10000`) to speed up the UDP scan further, at the possible cost of a less accurate scan.

3. No clue what they're on about, maybe I didn't notice anything odd because I just focused on 1 specific port? Tried to get more details on all the open ports: `nmap -sSV --version-all -p21,22,53,111,13337 10.6.66.67`. This did reveal some strange behaviour. We were able to identify some services:  
    ```
    PORT      STATE SERVICE VERSION
    21/tcp    open  ftp     vsftpd 3.0.2
    22/tcp    open  ssh?
    53/tcp    open  domain  dnsmasq 2.72
    111/tcp   open  rpcbind 2-4 (RPC #100000)
    13337/tcp open  http    Apache httpd 2.4.10 ((Debian))
    ```
    While processes listening on TCP port 22 are typically SSH servers, the `?` indicates that Nmap sent commands conforming to a number of different protocols to `listener` on port 22, but the responses did not conform to any protocol known to Nmap, and it was therefore unable to establish what type of service is listening on port 22.
4. Althoough the volume of network traffic generated by a port scan of a single host is low in comparison to benign network traffic, it usually has a distincct signature: one host attempting to establish TCP/UDP connections to another host  on a large number of ports (typically in sequential order) in a narrow timeframe. Unless the scan is deliberately made stealthier (e.g. using Nmap's `-T` option), this makes it easier for an IDS to detect a port scan taking place. The traffic that occurs on scanned ports is especially suspicious when version detection is being performed (e.g. Nmap sending SSH, HTTP, RTSP and DNS protocol traffic in the same connection to TCP port 22 when it was trying to identify it in the previous step). The volume of traffic can increase significantly when an entire subnet is being scanned, and this traffic has its own distinct signature (e.g. ARP requests for each IP address in turn in the subnet), which makes subnet-wide scans more noticeable.

## Communicating with a server using netcat
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
I resaved the data as a .jpeg, but that didn't help. After looking at the raw binary data, I noticed `EF BF BD` at the start of my file, which is the REPLACEMENT CHARACTER � encoded in UTF-8. By opening the file in atom (or some other text editor), the parsing replaced the illegal bytes, removing the data. After trying again, this time saving in [**data**](data), and looking at the bytes, after the header, I noticed the sequence `FF D8`, which is the header of a jpeg! The challenge is now removing the bytes at the front which belong to the HTTP response header, without reformatting the other bytes.

To do this I wrote a [**recover_jpeg.py**](recover_jpeg.py) script that will do this. This saved the resulting jpeg in [**data.jpeg**](data.jpeg), which contains the successfully decoded jpeg!

## IP Address & DNS spoofing
Our challenge for this section is to intercept and read the secret message being sent by `listener` to `mothership.dirty.lan`. In order to do this, we will need to intercept `listener`'s DNS request and respond with our own IP address.

Kali comes with the tool `dnschef`, which can hopefully be used to accomplish this. The `--fakedomains` flag allows us to specify domain names which will be resolved to FAKE values, specified by the `--fakeip` flag. A `--logfile` flag can be used to specify a logfile. The following command was used as a first try:
```
sudo dnschef --fakedomains mothership.dirty.lan --fakeip 10.6.66.64 --logfile dns.log
```
Wireshark will also be used to monitor packets sent on the lan.

Looking at these packets, we can see that 10.6.66.67 (`listener`), is sending DNS requests to 10.6.66.1 for `mothership.dirty.lan`. We essentially need to poison the DNS server entry to point to DNSChef (running on kali). We also need to specify the `--interface` flag to use 10.6.66.64 (our IP), and that `--nameservers` to 10.6.66.1 (the DNS server we are impersonating)
```
sudo dnschef --fakedomains mothership.dirty.lan --fakeip 10.6.66.64 --logfile dns.log --interface 10.6.66.64 --nameservers 10.6.66.1
```
Unfortunately, this doesn't seem to work. Some random on EdStem said that `listener` will not accept other DNS servers from DHCP since 10.6.66.1 is hardcoded in it's configuration, but I don't know if that's true or not. They were able to setup a partly working solution with another tool `dnsspoof`:
```
sudo dnsspoof -i eth0 -f hosts.txt udp port 53
```
Where the `hosts.txt` contains:
```
10.6.66.65      mothership.dirty.lan
```
However, the issue here was that the reponses were slower than the `dirtylan`'s DHCP server, so their alternative IP address wasn't accepted.
