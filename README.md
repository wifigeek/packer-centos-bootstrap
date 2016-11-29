what it is
----------

This directory contains files to let you build a turnkey centos 6.8 ova
install from ISO, totally automated. Run a script, go get lunch, when
you come back you have a file ready to import.

where its from
--------------

This is derived from https://github.com/INSANEWORKS/centos-packer

what it needs
-------------

Install prerequisites are vagrant, packer and ovftool, both available
for free on the internet.
Also required for this setup is VMware Fusion. 

what it does
------------

Run build.sh to make the magic happen.
This takes about 20 minutes on my desktop. It might take closer
to 30 if it is your first run, as it has to download the CD.

what it makes
-------------

The output of this process is a single .ova file.
The resulting VM has the CIS-recommended partitioning scheme across
2 32 gb drives. The only user is the "ea" user, with password "ea".
You should change that. Seriously.
The salt minion is also installed with default settings.

what is is for
--------------

It is expected the resulting VM will be fed to saltstack for further
processing and configuration.

where it was tested
-------------------

This works on my macos 10.12 box. I expect it will work in any similar
environment that has the prereq tools.
