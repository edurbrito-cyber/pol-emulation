#!/bin/sh

password_file="/root/.password"
keystore_dir="/root/.ethereum/keystore/"

# create password file if it does not exist
if [ ! -f "$password_file" ]; then
  echo "Creating password file"
  touch "$password_file"
fi

# create directory for geth if it does not exist
if [ ! -d "$keystore_dir" ]; then
  echo "Creating directory for geth"
  mkdir -p "$keystore_dir"
fi

# create new account if none exists
if [ ! "$(ls -A "$keystore_dir")" ]; then
  echo "Creating new account"
  geth --datadir /root/.ethereum account new --password /root/.password
else
  echo "Account already exists"
fi

# remove old genesis.json if it exists and geth and history directories
rm -rf /root/.ethereum/geth /root/.ethereum/history /root/.ethereum/genesis.json
