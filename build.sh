#!/bin/sh
ovftool="/Applications/vmware_ovf_tool/ovftool"
VERSION=v20170217
packer build -only vmware-iso $1.json
mkdir build-$1-$VERSION
mkdir -p output
cd build-$1-$VERSION
tar -zxvf ../build.tgz
rm ../build.tgz
$ovftool --targetType=OVF --overwrite --compress=9 --shaAlgorithm=sha1 --noImageFiles packer-vmware-iso.vmx ../output/packer-$1-$VERSION.ovf



#$ovftool --overwrite --datastore="DSCL-DCA-PROD01" --network="Cloud_VM_IP_01 DPortGroup" NCR-$1-$VERSION.ova vi://dcacloudvc.diginsite.net/DCACLOUD/host/DCACLOUDRESCL01
