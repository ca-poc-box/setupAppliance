#!/bin/sh

#################################################
# PoC Appliance Setup Script
#
# Used to setup external network, hosts files,
# DNS, NTP & Time Zones for ESXi and PoC VMs.
#################################################

. ./setupAppliance.properties
. ./lib/setupAppliance_lib.sh

mainSetup()
{
	echo "STARTED PoC Appliance Setup"
	echo "PoC Appliance Version: $POC_APP_VER"
	
	SETUPAPPL_DIR="$( cd "$( dirname "$0" )" && pwd )"
	echo "setupAppliance working directory is $SETUPAPPL_DIR"
	
	if [ -n "$SETUPAPPL_LOGFILE" ]; then
		echo "Writing output to $SETUPAPPL_LOGFILE"
	fi
	
	echo ""

        ./setupAppliance.py

	echo "FINISHED PoC Appliance Setup"
	echo "NOTE: For each VM that was updated, it is recommended to restart its application, to pick up all changes."
}

if [ -n "$SETUPAPPL_LOGFILE" ]; then
	mainSetup 2>&1 | writeToLog
else
	mainSetup 2>&1 | writeToScreenOnly
fi
