#!/bin/bash

source /home/pi/.bashrc
source /home/pi/deamon_export_pi4/.env

REPO_URL=$(grep REPO_URL /home/pi/deamon_export_pi4/.env | cut -d '=' -f2)

files_to_commit=("wss_messages.json" "requests.json")

for file in "${files_to_commit[@]}"; do
    cp /home/pi/lorawan_capture/"$file" /home/pi/deamon_export_pi4/
done

cd /home/pi/deamon_export_pi4 || exit

for file in "${files_to_commit[@]}"; do
    /usr/bin/git add "$file"
done

/usr/bin/git commit -m 'deamon - Add wss_messages.json and requests.json'
/usr/bin/git pull "$REPO_URL" main --rebase

if [ -d ".git/rebase-apply" ]; then
    /usr/bin/git rebase --abort
    exit 1
fi

/usr/bin/git push "$REPO_URL" main

if [ ! -d ".git" ]; then
    /usr/bin/git init
    /usr/bin/git remote add origin "$REPO_URL"
    /usr/bin/git checkout -b main
fi

if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
    /usr/bin/git rebase --abort
fi

/usr/bin/git push "$REPO_URL" main

