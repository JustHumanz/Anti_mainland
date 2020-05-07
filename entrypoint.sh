#!/bin/bash
/apps/setup_db.sh &
nohup /apps/api &>/dev/null &

/apps/honeypot --listen 0.0.0.0:22
