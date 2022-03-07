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
```
while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];
        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
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
We have now confirmed that this is indeed the hash of Gordon Brown. Doing this without the knowledge of the hash would've taken a really long time, so this would normally be done using an automated approach (python script or whatever).
