#!/bin/sh -l
sudo -E ./dns-proxy-action > /tmp/dns-proxy-action.out 2>&1 &
sleep 3