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
Running a **TCP SYN scan** on `listener` using the IP address sniffed in the previous section, we obtain the following results:
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
