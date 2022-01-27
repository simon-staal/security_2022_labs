#!/bin/bash

set -euo pipefail

IP="10.6.66.65" # Set to desired IP

input="./cracked_passwords.txt"
fail=""
passed=0
total=0
while IFS= read -r line
do
  linearray=($line)
  pass=${linearray[0]}
  user=${linearray[1]}
  user=$(sed -e 's/^(//' -e 's/)$//' <<< "$user")
  echo "Testing ${user} with password: ${pass}"
  set +e
  sshpass -p ${pass} ssh -n -q ${user}@${IP} exit
  RESULT=$?
  set -e
  if [[ ${RESULT} -eq 0 ]]; then
    passed=$((${passed}+1))
  else
    fail="${fail} ${user}:${pass}"
  fi
  total=$((${total}+1))
done < "${input}"

echo "Successfully logged in with ${passed} out of ${total} users"
if [[ ${total} -gt ${passed} ]]; then
  echo "Failed: ${fail}"
fi
