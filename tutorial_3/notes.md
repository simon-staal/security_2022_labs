Tutorial 3: Network Security Tools
==================================

Initial Network Traffic
-----------------------
After booting up the `listener` VM, we can see an exchange of 4 packets:
1. DHCP Discover, sent from 0.0.0.0 to 255.255.255.255 (everyone), which is a request for any DHCP servers on `dirtylan` to offer it a network configuration
2. DHCP Offer, sent from 10.6.66.1, which is `dirtylan`'s DHCP server responding. Within this packet, we can see the offered *client IP address* of 10.6.66.67, and a *lease time* of 10 minutes. The *lease time* represents when `listener` is meant to ask the DHCP server for permission to continue using the IP address. Note that this can't me enforced by the DHCP server, it is only promising not to offer this IP address to anothre host during this period, unless `listener` releases it first.
3. DHCP Request, sent from 0.0.0.0 advertises that it wants to use the configuration offered.
4. DHCP Acknowledgment, sent from 10.6.66.1 confirms the request.

**Questions**
1. An attacker using `kali-vm` can act as an eavesdropper or participant on the network. However, using ARP poisoning an attecker could become a MITM.
2. An attacker could inpersonate the DHCP server, offering a different IP address to `listener`. For example if it gives `listener` its own IP address, whenever `listener` is meant to recieve packets from the router, the router would forward them to `kali-vm` instead. Alternatively, the attacker could give it the same IP that would be offered by the DHCP server with a higher lease time, and then take this IP address over once the lease provided by the DHCP expires for the same effect.
