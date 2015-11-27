#!/bin/bash

sudo ifconfig sn0 down
sudo ifconfig sn1 down
sleep 2
sudo rmmod snull
