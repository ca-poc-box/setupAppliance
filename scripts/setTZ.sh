#!/bin/bash

CLOCK_FILE=/etc/sysconfig/clock
TZ=$1
TZ_UTC=$2

if [ -n "${TZ}" ]; then
    # Soft-linking localtime file to timezone file
    rm -f /etc/localtime
    ln -sf /usr/share/zoneinfo/$TZ /etc/localtime

    # Changeing entry for ZONE in clock file to POC timezone
    sed -ie "/ZONE=.*/d" $CLOCK_FILE
    echo "ZONE=$TZ" >> $CLOCK_FILE
    if [ -n "${TZ_UTC}" ]; then
        sed -ie "s/UTC.*/UTC=$TZ_UTC/g" $CLOCK_FILE
    fi
    /sbin/hwclock --systohc --utc
        
fi
