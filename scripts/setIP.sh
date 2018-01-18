#!/bin/bash

NSFILEDIR="/etc/sysconfig/network-scripts"

MAC=$1
PROTO=${2:-dhcp}
IPADDR=$3
NETMASK=$4
GATEWAY=$5
DNS1=$6
DNS2=$7

IFACE=

if  [ -n "${MAC}" ]; then
    echo "Find interface with HWaddr=$MAC"
    IFACE=$(ifconfig | grep $MAC | awk '/HWaddr/ {print $1}')
fi

if [ -n "${IFACE}" ]; then
    echo "Using interface $IFACE"
    IFCFG=$NSFILEDIR/ifcfg-$IFACE

    chkconfig NetworkManager off
    service NetworkManager stop
    
    echo "Backing up current network settings" 
    mkdir -p $NSFILEDIR/backup
    cp -vp $IFCFG $NSFILEDIR/backup/ifcfg-$IFACE.backup

    sed -ie '/\(DEVICE\|ONBOOT\|TYPE\|BOOTPROTO\|IPADDR\|NETMASK\|GATEWAY\|HWADDR\)=.*/d' $IFCFG
    echo "DEVICE=$IFACE" >> $IFCFG
    echo "ONBOOT=yes" >> $IFCFG
    echo "TYPE=Ethernet" >> $IFCFG

    if [ "$PROTO" = "dhcp" ]; then
        echo "BOOTPROTO=dhcp" >> $IFCFG
    else
        echo "BOOTPROTO=static" >> $IFCFG
        echo "IPADDR=$IPADDR" >> $IFCFG
        echo "NETMASK=$NETMASK" >> $IFCFG
        echo "GATEWAY=$GATEWAY" >> $IFCFG
    fi

    if [ -n "${DNS1}" ]; then
        echo "nameserver $DNS1" > /etc/resolv.conf
        if [ -n "${DNS2}" ]; then
            echo "nameserver $DNS2" >> /etc/resolv.conf
        fi
    fi

    echo "Restarting network service"
    ifdown $IFACE
    ifup $IFACE

    #if [ "$PROTO" = "dhcp" ]; then
    #    IP=$(ifconfig $IFACE | grep inet | grep -v inet6 | cut -d ":" -f)
    #    echo "DHCP-assigned address is $IP"
    #fi
    
    echo ""
    ifconfig
    echo ""
fi


