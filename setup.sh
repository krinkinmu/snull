#!/bin/bash

SN0_IP=192.168.0.1
SN1_IP=192.168.1.2
MASK=255.255.255.0

sudo insmod ./snull.ko
sudo ifconfig sn0 ${SN0_IP} netmask ${MASK} up
sudo ifconfig sn1 ${SN1_IP} netmask ${MASK} up

# ping 192.168.0.2 or ping 192.168.1.1 to test
