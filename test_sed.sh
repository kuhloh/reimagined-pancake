#!/usr/bin/env bash
echo 'password=hunter2isabadpassword' | sed -E 's/(password[[:space:]]*[:=][[:space:]]*)[[^";&[:space:]]+/\1REDACTED/gi'
