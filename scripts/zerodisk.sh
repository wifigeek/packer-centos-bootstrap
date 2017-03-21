# Zero out the free space to save space in the final image:
dd if=/dev/zero of=/EMPTY bs=1M oflag=direct
dd if=/dev/zero of=/app/EMPTY bs=1M oflag=direct
dd if=/dev/zero of=/home/EMPTY bs=1M oflag=direct
dd if=/dev/zero of=/var/EMPTY bs=1M oflag=direct
dd if=/dev/zero of=/var/log/EMPTY bs=1M oflag=direct

rm -f /EMPTY
rm -f /app/EMPTY
rm -f /home/EMPTY
rm -f /var/EMPTY
rm -f /var/log/EMPTY

