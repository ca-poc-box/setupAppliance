####################################
# Library of functions for setup
# Used by setupAppliance.sh to setup external network 
# and NTP for ESXi and APM PoC VMs.


# Writes all output to log and screen with timestamp
writeToLog()
{
	while read line ; do
		echo "$(date +'%F %T') : ${line}" | awk '{sub(/\r$/,"");print}' | tee -a $SETUPAPPL_LOGDIR/$SETUPAPPL_LOGFILE
	done
}

# Writes all output to screen with timestamp
writeToScreenOnly()
{
	while read line ; do
		echo "$(date +'%F %T') : ${line}"
	done
}

