#!/bin/sh

VERSION=v20161017 packer build -only vmware-iso CentOS_6.json
mkdir build
cd build
tar -zxvf ../build.tgz
cd ..
rm -f build.tgz
ovftool build/packer-vmware-iso.vmx NCR-Centos-6.8.ova
rm -rf build
