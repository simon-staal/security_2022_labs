#!/bin/bash

# First run
# john --format=md5crypt --wordlist=/usr/share/dict/wordlist-probable.txt ./shadow

# Second run - word mangling enabled
john --format=md5crypt --wordlist=/usr/share/dict/wordlist-probable.txt --rules ./shadow
