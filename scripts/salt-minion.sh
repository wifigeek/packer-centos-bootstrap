# Install the salt minion

curl -o bootstrap_salt.sh -L https://bootstrap.saltstack.com
sudo sh bootstrap_salt.sh -G -Z stable
rm -f bootstrap_salt.sh
