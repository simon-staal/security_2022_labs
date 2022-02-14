Tutorial 4: Server-Side Web Vulnerabilities
===========================================

Gathering information on `dvwa`
-------------------------------
We are exploiting a web application hosted on `dvwa`. As such, we want to gather the following information:
1. `dvwa`'s IP address
2. The operating system it's running
3. The web server software (and version) it's using to serve content
4. The version of PHP being used to execute PHP scripts hosted on the web server

This can be done using `nmap`:
1. I tried `nmap -sP 10.6.66.1/24`, like in the previous lab to try and find `dvwa`'s IP. However this only revealed 10.6.66.1 (DHCP server) and 10.6.66.64 (`kali_vm` or ourselves). That's cause I didn't launch `dvwa` (I might be slightly retarded). After launching it, I identified its IP as **10.6.66.42**.
2. To identify the OS, I used `nmap -O 10.6.66.42`, which provided the following relevant information:
```
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel.:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
```
This identifies the OS as anything between Linux 3.2 and 4.9.
3. `nmap -sSV 10.6.66.42` was used to perform a scan of the popular TCP ports and identify their versions:
```
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.10 ((Debian) PHP/5.6.29-0+deb8u1)
111/tcp open  rpcbind 2-4 (RPC #100000)
MAC Address: 08:00:27:05:A6:4D (Oracle VirtualBox virtual NIC)
```
This not only identified the web server software as **Apache 2.4.10**, but also identified the PHP version as **5.6**
