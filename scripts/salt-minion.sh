# Install the salt minion

curl -o bootstrap_salt.sh -L https://bootstrap.saltstack.com
sudo sh bootstrap_salt.sh -Z -A 10.102.128.128 stable
rm -f bootstrap_salt.sh
