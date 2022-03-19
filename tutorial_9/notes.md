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
We therefore need a way to get the the token from the webpage, then include it in our GET request to change the username.
