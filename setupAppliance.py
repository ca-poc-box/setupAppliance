#!/usr/bin/env python

from __future__ import print_function
from POC import POCAdmin

display_width = 80
col1_width = 20

def printinfo(heading, items):
    if isinstance(items, list):
        if not items: items = [""]
        print("{0:>{1}} {2:<{3}}".format(heading,col1_width,items[0],display_width-col1_width))
        for l in items[1:]:
            print("{0:>{1}} {2:<{3}}".format("",col1_width,l,display_width-col1_width))
    else:
        print("{0:>{1}} {2:<{3}}".format(heading,col1_width,items,display_width-col1_width))
    
with POCAdmin("root", "CAdemo123") as poc:
    print("Importing information from setupAppliance.properties")
    poc.glean()
    
    vms = poc.VMs
    printinfo("Host time:",str(poc.dateTime))
    printinfo("POC TZ:",poc.timezone)
    printinfo("Default Gateway:", poc.gateway)
    printinfo("Netmask:", poc.netmask)
    printinfo("DNS Servers:", ",".join(poc.dns))
    # printinfo("NTP Servers:", poc.ntp)
    print("")
    for v in vms:
        printinfo("Name:", v.name)
        printinfo("UUID:", v.uuid)
        printinfo("Guest:", v.guestId)
        if v.guestReady:
            printinfo("State:", "Guest is ready")
            printinfo("Hostname:", v.hostname)
            printinfo("IP Address:", v.getIP()) #("VM Network"))
            #printinfo("Notes:", v.notes)
            #poc.checkBuild(v)
            #printinfo("Build:", v.build)
                
            printinfo("", "...staging files for version " + poc.build)
            poc.stageFiles(v)
            ncfg = v.getNet("VM Network")                                              
            if ncfg is None:                                                           
                printinfo("", "Error: missing configuration for 'VM Network'")
            else:                                                                                               
                printinfo("", "...configuring IP address {1} on {2}".format("", ncfg.ipaddr, ncfg.network))       
                ncfg.gateway = poc.gateway
                ncfg.netmask = poc.netmask                                                            
                ncfg.dns = poc.dns                                                                    
                poc.applyNet(v, ncfg)                                                                           
                                                                                                                    
            printinfo("", "...configuring timezone " + poc.timezone)
            poc.applyTZ(v, poc.tzCfg)
        else:
            printinfo("State:", "Guest NOT ready")
            printinfo("Power:", v.powerState)
            printinfo("VM Tools:", v.toolsStatus)
            printinfo("Net State:", v.netState)
            printinfo("IP Address:", v.getIP())            
        print("")

    for v in vms:
        if v.guestReady:
            printinfo("","...configuring host resolution for " + v.name)
            poc.applyHosts(v)
        
    poc.save() 
