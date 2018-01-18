#!/usr/bin/env python

from __future__ import print_function
from POC import POCAdmin, POCArchive, NetConfig, TZConfig, AuthConfig
from cmd import Cmd
import readline
# from sys import stdout


class POCCmd(Cmd):
    _hist = []
    _cmd_alias = {}

    def __init__(self, poc):
        Cmd.__init__(self)
        self._poc = poc
        self.undoc_header = None

    @classmethod
    def stash_hist(cls):
        cls._hist = [ readline.get_history_item(i+1) for i in range(readline.get_current_history_length()) ]

    @classmethod
    def unstash_hist(cls):
        readline.clear_history()
        for line in cls._hist:
            if line is not None:
                readline.add_history(line)

    def precmd(self, line):
        cmd, arg, line2 = self.parseline(line)
        if cmd is None:
            return line
        if cmd.lower() in self._cmd_alias:
            cmd = self._cmd_alias[cmd]
        return cmd + " " + arg

    def emptyline(self):
        pass

    def print_topics(self, header, cmds, cmdlen, maxcol):
        if header is not None:
            Cmd.print_topics(self, header, cmds, cmdlen, maxcol)

    def get_vm_config(self, vm):
        conf = ["vm {0}".format(vm.name)]
        if vm.auth is None:
            conf.append("!! {0} is an incompatible guest. The VM cannot be configured".format(vm.guestId))
        else:
            ncfg = vm.getNet("VM Network")
            if ncfg is not None:
                conf.append("ip addr {0}{1}".format(ncfg.ipaddr, " mask {0}".format(ncfg.netmask) if not ncfg.dhcp else ""))
                gw = "gateway "+ncfg.gateway if len(ncfg.gateway) > 0 else "inherited gateway "+self._poc.gateway
                conf.append(gw)
                #mask = "netmask "+ncfg.netmask if len(ncfg.netmask) > 0 else "inherited netmask "+self._poc.netmask
                #conf.append(mask)
                dns = "dns "+ " ".join(ncfg.dns) if len(ncfg.dns) > 0 else "inherited dns "+ " ".join(self._poc.dns)
                conf.append(dns)

            tz = "timezone "+vm.tzCfg.tz if vm.tzCfg else "inherited timezone "+self._poc.timezone
            conf.append(tz)
            auth = "auth " + vm.auth.username + " " + vm.auth.password
            conf.append(auth)

        return conf

    def do_help(self, args):
        """
    'help' or '?' with no arguments prints a list of commands for which help is available
    'help <command>' or '? <command>' gives help on <command>
        """
        ## This removes 'help' from the undocumented list
        Cmd.do_help(self, args)

    def print_help_topics(self, topics):
        print()
        for topic in topics:
            print("{0:>4}{1}".format("",topic))
        print()

class SystemCli(POCCmd):
    _hist = []
    _cmd_alias = { "sh" : "show",
                   "tz" : "timezone",
                   "gw" : "gateway",
                   "quit" : "end",
                   "q" : "end",
                   "h" : "help",
                   "exit" : "end"}

    def __init__(self, poc):
        POCCmd.__init__(self, poc)
        #self._poc = poc
        self.prompt = "config# "
        self.intro = ""

    def default(self, line):
        cmd, arg, line2 = self.parseline(line)
        if line.startswith('!'):
            return
        Cmd.default(self, line)


    def _show_vm(self, args):
        VMs = self._poc.getVM("name", args)
        if not VMs:
            print("no VM found that matches '{0}'".format(args))
            print()
        else:
            #TODO check if len(VMs) > 1 and do something smart, otherwise ...
            print("!")
            conf = self.get_vm_config(VMs[0])
            print("\n".join(conf))
            print("!")

    def _show_(self, line):
        #print system level settings: timezone, gateway, dns
        print("!")
        print("timezone {0}".format(self._poc.timezone))
        print("gateway {0}".format(self._poc.gateway))
#        print("netmask {0}".format(",".join(self._poc.netmask)))
        print("dns {0}".format(" ".join(self._poc.dns)))
        print("!")
        #print VM settings: ipaddr, gateway, dns, timezone, auth
        for vm in self._poc.VMs:
            print("\n".join(self.get_vm_config(vm)))
            print("!")

    def do_show(self, line):
        parts = line.partition(' ')
        action = parts[0].strip()
        args = parts[2]
        try:
            getattr(self, '_show_'+action)(args)
        except AttributeError:
            print("% Unrecognized command 'show {0}'".format(action))
            self.help_show()

    def complete_show(self, text, line, begidx, endidx):
        options = ['<ENTER>', 'vm']
        if line.lower().startswith('show vm ') :
            options = [vm.name for vm in self._poc.VMs]
            line = line.partition(' ')[2]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def help_show(self):
        self.print_help_topics([
            "'show' display the current configuration",
            "'show vm [Virtual Machine]' display the configuration of a specific VM",
            "    <TAB> assists with auto-completion and listing VMs"
            ])

    def do_vm(self, args):
        VMs = self._poc.getVM("name", args)
        if not VMs:
            print("no VM found that matches '{0}'".format(args))
            print()
        else:
            #TODO check if len(VMs) > 1 and do something smart, otherwise ...
            SystemCli.stash_hist()
            vmcli = VMCli(self._poc, VMs[0])
            vmcli.cmdloop()
            SystemCli.unstash_hist()

    def complete_vm(self, text, line, begidx, endidx):
        options = [vm.name for vm in self._poc.VMs]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def help_vm(self):
        self.print_help_topics([
            "'vm [Virtual Machine]' enter configure mode for a specific Virtual Machine",
            "    <TAB> assists with auto-completion and listing VMs"
            ])

    def do_import(self, line):
        self._poc.glean()

    def help_import(self):
        self.print_help_topics([
            "'import' imports the settings from setupAppliance.properties"])

    def do_dns(self, line):
        dns = line.replace(';',' ').replace(',',' ').split()
        for ip in dns:
            if not NetConfig.isValidIP(ip):
                print("% '{0}' is not a valid IP address".format(ip))
                self.help_dns()
                return

        self._poc.dns = dns

    def help_dns(self):
        self.print_help_topics([
            "'dns [IP address list]' configure the global, default DNS name servers",
            "    up to two name servers can be specified, space separated",
            "    VMs that do not have a dns configured will inherit this setting"])

    def do_gateway(self, line):
        if not NetConfig.isValidIP(line):
            print("% '{0}' is not a valid IP address".format(line))
            self.help_gateway()
            return

        self._poc.gateway = line

    def help_gateway(self):
        self.print_help_topics([
            "'gateway [IP address]' configure the global, default gateway",
            "    VMs that have no gateway configured will inherit this setting"])

    def do_timezone(self, line):
        tz = TZConfig.tz_map.get(line, None)
        if tz is None:
            print("no timezone found that matches '{0}'".format(line))
            print()
        else:
            self._poc.tzCfg = TZConfig(line)

    def help_timezone(self):
        self.print_help_topics([
            "'timezone [timezone]'  configure the global, default timezone",
            "    VMs that have no timezone configured will inherit this setting",
            "    <TAB> assists with auto-completion and lists the timezones"])

    def complete_timezone(self, text, line, begidx, endidx):
        options = TZConfig.tz_map.keys()
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def do_end(self, line):
        return True

    def help_end(self):
        self.print_help_topics(["'end' exits configuration mode"])

    do_EOF = do_end

    def preloop(self):
        SystemCli.unstash_hist()

    def postloop(self):
        SystemCli.stash_hist()

class VMCli(POCCmd):

    _hist = []
    _cmd_alias = { "sh" : "show",
                   "tz" : "timezone",
                   "gw" : "gateway",
                   "quit" : "end",
                   "q" : "end",
                   "h" : "help",
                   "exit" : "end"}

    def __init__(self, poc, vm):
        POCCmd.__init__(self, poc)
        self._vm = vm
        self.prompt = "config " + self._vm.name + "# "
        self.intro = ""

    def default(self, line):
        cmd, arg, line2 = self.parseline(line)
        if line.startswith('!') or cmd.lower() == "inherited":
            return
        Cmd.default(self, line)

    def do_show(self, line):
        print("!")
        conf = self.get_vm_config(self._vm)
        print("\n".join(conf))
        print("!")

    def help_show(self):
        self.print_help_topics([
            "'show' displays the configuration of the current Virtual Machine"])

    def _ip_addr(self, line):
        parts = line.partition(' ')
        ipaddr = parts[0].strip()
        if ipaddr.lower() == "dhcp":
            # configure dhcp on VM Network
            self._vm.networks = NetConfig("VM Network")
            return

        if not NetConfig.isValidIP(ipaddr):
            print("% '{0}' is not a valid IP address".format(ipaddr))
            self.help_ip()
            return

        args = parts[2]
        parts = args.partition(' ')
        if parts[0].strip() != "mask":
            print("% Unrecognized command '{0}': missing keywork 'mask'".format(line))
            self.help_ip()
            return

        netmask = parts[2]
        #print(ipaddr, netmask)
        if not NetConfig.isValidMask(netmask):
            print("% '{0}' is not a valid network mask".format(netmask))
            self.help_ip()
            return

        ncfg = self._vm.getNet("VM Network")
        if ncfg is None:
            ncfg = NetConfig("VM Network")

        ncfg.ipaddr = ipaddr
        ncfg.netmask = netmask
        self._vm.setNet(ncfg)

    def do_ip(self, line):
        parts = line.partition(' ')
        action = parts[0].strip()
        if action != "addr":
            print("% Unrecognized command 'ip {0}'".format(action))
            self.help_ip()
            return

        args = parts[2]
        try:
            getattr(self, '_ip_'+action)(args)
        except AttributeError:
            print("% Unrecognized command 'ip {0}'".format(action))

    def complete_ip(self, text, line, begidx, endidx):
        options = ['addr']
        
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def help_ip(self):
        self.print_help_topics([
            "'ip addr [IP address] mask [subnet mask]' configure the IP address and subnet mask for the VM"])

    def do_dns(self, line):
        # TODO: maybe look for different separators like semi-colon, comma, space.  Prolly need to use re
        dns = []
        if line:
            dns = line.replace(';',' ').replace(',',' ').split()
            for ip in dns:
                if not NetConfig.isValidIP(ip):
                    print("% '{0}' is not a valid IP address".format(ip))
                    self.help_dns()
                    return

        ncfg = self._vm.getNet("VM Network")
        if ncfg is None:
            print("% you must configure the VM 'ip addr' prior to dns")
            return

        ncfg.dns = dns
        self._vm.setNet(ncfg)

    def help_dns(self):
        self.print_help_topics([
            "'dns [IP address list]' configure DNS name servers for the VM",
            "    up to two name servers can be specified, space separated",
            "    if not configured (or empty), the VM will inherit this setting from the global default",
            "    the VM 'ip addr' must be configured prior to setting dns"
            ])

    def do_gateway(self, line):
        if line:
            if not NetConfig.isValidIP(line):
                print("% '{0}' is not a valid IP address".format(line))
                self.help_gateway()
                return

        ncfg = self._vm.getNet("VM Network")
        if ncfg is None:
            print("% you must configure the VM ip addr prior to the gateway")
            return

        ncfg.gateway = line
        self._vm.setNet(ncfg)

    def help_gateway(self):
        self.print_help_topics([
            "'gateway [IP address]' configures the default gateway for the Virtual Machine",
            "    if not configured (or empty), the VM will inherit this setting from the global default",
            "    the VM 'ip addr' must be configured prior to setting the gateway"
            ])


    def do_timezone(self, line):
        tzCfg = None
        if line:
            tz = TZConfig.tz_map.get(line, None)
            if tz is None:
                print("no timezone found that matches '{0}'".format(line))
                print()
                return
            else:
                tzCfg = TZConfig(line)

        self._vm.tzCfg = tzCfg

    def help_timezone(self):
        self.print_help_topics([
            "'timezone [timezone]' configures the timezone for the Virtual Machine",
            "    if not configured (or empty), the VM will inherit this setting from the global default",
            "    <TAB> assits with auto-completion and lists timezones"
            ])

    def complete_timezone(self, text, line, begidx, endidx):
        options = TZConfig.tz_map.keys()
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def do_auth(self, args):
        parts = args.partition(' ')
        usr = parts[0].strip()
        pwd = parts[2].strip()
        parts = pwd.partition(' ')[0].strip()
        if pwd != parts:
            print("% Unrecognized option in '{0}'".format(args))
            self.help_auth()
            return

        self._vm.auth = AuthConfig(usr, pwd)

    def help_auth(self):
        self.print_help_topics([
            "'auth [username] [password]' provides the credentials used by this tool to configure the VM"])

    def do_vm(self, args):
        VMs = self._poc.getVM("name", args)
        if not VMs:
            print("no VM found that matches '{0}'".format(args))
            print()
        else:
            #TODO check if len(VMs) > 1 and do something smart, otherwise ...
            self._vm = VMs[0]
            self.prompt = "config " + self._vm.name + "# "

    def complete_vm(self, text, line, begidx, endidx):
        options = [vm.name for vm in self._poc.VMs]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def help_vm(self):
        self.print_help_topics([
            "'vm [Virtual Machine]' enter configure mode for a specific Virtual Machine",
            "    <TAB> assists with auto-completion and listing VMs"
            ])

    def do_end(self, line):
        return True

    def help_end(self):
        self.print_help_topics(["'end' exits Virtual Machine configuration mode"])

    def preloop(self):
        VMCli.unstash_hist()

    def postloop(self):
        VMCli.stash_hist()

    do_EOF = do_end

class POCConsole(POCCmd):
    _hist = []
    _cmd_alias = { "sh" : "show",
                   "conf" : "config",
                   "quit" : "exit",
                   "q" : "exit",
                   "h" : "help",
                   "end" : "exit"}

    _sneaky_cmd = [ "deploy" ]

    def __init__(self, poc):
        POCCmd.__init__(self, poc)
        self.prompt = "# "
        self.intro = ""

    def default(self, line):
        cmd, arg, line2 = self.parseline(line)
        if line.startswith('!'):
            return
        elif cmd.lower() in POCConsole._sneaky_cmd:
            getattr(self, "_" + cmd.lower())(arg)
        else:
            Cmd.default(self, line)

    def __completedefault_delete_me__(self, text, line, begidx, endidx):
        cmd, arg, l = self.parseline(line)
        options = [s[len(cmd):].strip() for s in commands if s.startswith(cmd)]
        #line = line[len(cmd):].strip()
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]

        return completes

    def _show_bom(self, args):
        print()
        for item in self._poc.bom:
            info = [ ("Product", item["product"]),
                 ("Suite", ",".join(item["suite"])),
                 ("Archive", item["archive"]) ]
            print('\n'.join("{0:>10}: {1}".format(line[0], line[1]) for line in info))
            print()

    def _show_host(self, args):
        print()
        print(self._poc.hostName)
        info = [ ("IP Address:", self._poc.hostIP),
                 ("Product:", self._poc.product),
                 ("License:", self._poc.license),
                 ("Datastore:", self._poc.dataStoreURL),
                 ("Config:", "timezone {0}".format(self._poc.timezone)),
                 ("", "gateway {0}".format(self._poc.gateway)),
                 ("", "dns {0}".format(" ".join(self._poc.dns))) ]
        print('\n'.join("{0:>15} {1}".format(line[0], line[1]) for line in info))
        print()

    def _show_config(self, line):
        #print system level settings: timezone, gateway, dns
        print("!")
        print("timezone {0}".format(self._poc.timezone))
        print("gateway {0}".format(self._poc.gateway))
#        print("netmask {0}".format(",".join(self._poc.netmask)))
        print("dns {0}".format(" ".join(self._poc.dns)))
        print("!")
        #print VM settings: ipaddr, gateway, dns, timezone, auth
        for vm in self._poc.VMs:
            print("\n".join(self.get_vm_config(vm)))
            print("!")

    def _show_the_vm_(self, vm):
        info =[("Name:", vm.name),
               ("IP Address:", ",".join(vm.getIP("VM Network"))),
               ("UUID:", vm.uuid),
               ("Guest:",vm.guestId),
               ("VM Tools:", vm.toolsStatus),
               ("Power:", vm.powerState),
               ("Notes:", " | ".join(vm.notes))]
        cfg = self.get_vm_config(vm)
        if len(cfg) >1:
            info.append(("Config:", cfg[1]))
            for line in cfg[2:]:
                info.append(("", line))
        print('\n'.join("{0:>12} {1}".format(line[0], line[1]) for line in info))

    def _show_vm(self, args):
        VMs = self._poc.getVM("name", args)
        print()
        if not VMs:
            print("no VM found that matches '{0}'".format(args))
            print()
        else:
            for vm in VMs:
                self._show_the_vm_(vm)
                print()

    def _show_vms(self, args):
        print()
        for vm in self._poc.VMs:
            self._show_the_vm_(vm)
            print()

    def do_show(self, line):
        parts = line.partition(' ')
        action = parts[0].strip()
        args = parts[2]
        try:
            getattr(self, '_show_'+action)(args)
        except AttributeError:
            print("% Unrecognized command 'show {0}'".format(action))
            self.help_show()

    def help_show(self):
        self.print_help_topics([
            "'show config' displays the configuration",
            "'show host' displays information regarding the VMware host",
            "'show vms' displays information regarding all Virtual Machines",
            "'show vm [Virtual Machine]' displays information regarding a specific VM",
            "    <TAB> assists with auto-completion and listing VMs"
            ])

    def complete_show(self, text, line, begidx, endidx):
        options = ['config','host', 'vm', 'vms']
        #options += ['vm ' + vm.name for vm in self._poc.VMs]
        if line.lower().startswith('show vm ') :
            options = [vm.name for vm in self._poc.VMs]
            line = line.partition(' ')[2]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def do_save(self, line):
        self._poc.save()

    def help_save(self):
        self.print_help_topics(["'save' writes the configuration to disk"])

    def _apply_the_vm_(self, v):
        print("{0:>4}apply config for {1}".format("",v.name))
        if not v.guestReady:
            print("{0:>6}guest is not ready".format(""))
            if v.auth is None:
                print("{0:>6}{1} is not compatible".format("", v.guestId))
            print("{0:>8}power: {1}".format("", v.powerState))
            print("{0:>8}tools: {1}".format("", v.toolsStatus))
            print("{0:>8}net: {1}".format("", v.netState))
            return

        print("{0:>6}{1} is ready".format("", v.guestId))
        print("{0:>6}...staging files for version {1}".format("", self._poc.build))
        self._poc.stageFiles(v)
        ncfg = v.getNet("VM Network")
        if ncfg is None:
            print("{0:>6}...'VM Network' has no configuration. Configure the VM using 'ip addr'".format(""))
        else:
            print("{0:>6}...configuring IP address {1} on {2}".format("", ncfg.ipaddr, ncfg.network))
            if len(ncfg.gateway) < 1:
                ncfg.gateway = self._poc.gateway
            if len(ncfg.dns) < 1:
                ncfg.dns = self._poc.dns
            poc.applyNet(v, ncfg)

        tzCfg = v.tzCfg if v.tzCfg else self._poc.tzCfg
        print("{0:>6}...configuring timezone {1}".format("",tzCfg.tz))
        poc.applyTZ(v, tzCfg)
        
    def _apply_vm(self, args):
        VMs = self._poc.getVM("name", args)
        if not VMs:
            print("no VM found that matches '{0}'".format(args))
            print()
        else:
            for vm in VMs:
                print()
                self._apply_the_vm_(vm)
            print()

    def _apply_(self, args):
        self._poc.save()
        for v in self._poc.VMs:
            print()
            self._apply_the_vm_(v)

        print()            
        print("{0:>4}configuring host resolution".format(""))
        self._apply_hosts(args)
        print()

    def _apply_hosts_vm(self, vm):
        print("{0:>6}...configuring host resolution for {1}".format("", vm.name))
        if vm.guestReady:                
            self._poc.applyHosts(vm)
        else:
            print("{0:>6}...SKIPPING configuration of host resolution: guest not ready".format(""))
            if vm.auth is None:                                      
                print("{0:>6}{1} is not compatible".format("", vm.guestId))                                  
            print("{0:>8}power: {1}".format("", vm.powerState))                                              
            print("{0:>8}tools: {1}".format("", vm.toolsStatus))                                             
            print("{0:>8}net: {1}".format("", vm.netState))

    def _apply_hosts(self, args):
        for vm in self._poc.VMs:
            self._apply_hosts_vm(vm)

    def do_apply(self, line):
        parts = line.partition(' ')
        action = parts[0].strip()
        args = parts[2]
        try:
            getattr(self, '_apply_'+action)(args)
        except AttributeError:
            print("% Unrecognized command 'apply {0}'".format(action))
            self.help_apply()

    def complete_apply(self, text, line, begidx, endidx):
        options = ['<ENTER>', 'vm']
        #options += ['vm ' + vm.name for vm in self._poc.VMs]
        if line.lower().startswith('apply vm ') :
            options = [vm.name for vm in self._poc.VMs]
            line = line.partition(' ')[2]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def help_apply(self):
        self.print_help_topics([
            "'apply' applies the configuration",
            "'apply vm [Virtual Machine]' applies the configuration to a specific VM",
            "    <TAB> assists with auto-completion and listing VMs"
            ])

    def __config_vm_delete_me__(self, args):
        VMs = self._poc.getVM("name", args)
        if not VMs:
            print("no VM found that matches '{0}'".format(args))
            print()
        else:
            #TODO check if len(VMs) > 1 and do something smart, otherwise ...
            POCConsole.stash_hist()
            vmcli = VMCli(self._poc, VMs[0])
            vmcli.cmdloop()
            POCConsole.unstash_hist()

    def _config_system(self, args):
        #readline.write_history_file()
        POCConsole.stash_hist()
        syscli = SystemCli(self._poc)
        syscli.cmdloop()
        POCConsole.unstash_hist()

    _config_ = _config_system

    def do_config(self, line):
        parts = line.partition(' ')
        action = parts[0].strip()
        args = parts[2]
        try:
            getattr(self, '_config_'+action)(args)
        except AttributeError:
            print("% Unrecognized command 'config {0}'".format(action))
            self.help_config()

    def help_config(self):
        self.print_help_topics(["'config' enters configuration mode. To exit type 'end'"])

    #def complete_config(self, text, line, begidx, endidx):
    #    options = ['system', 'vm']
    #    #options += ['vm ' + vm.name for vm in self._poc.VMs]
    #    if line.lower().startswith('config vm ') :
    #        options = [vm.name for vm in self._poc.VMs]
    #        line = line.partition(' ')[2]
    #    mline = line.partition(' ')[2]
    #    offs = len(mline) - len(text)
    #    completes = [s[offs:] for s in options if s.startswith(mline)]
    #    return completes

    def _deploy_vm(self, args):
        vm = self._poc.bom[args]
        print()
        if not vm:
            print("no VM found that matches '{0}'".format(args))
            print()
        else:
            # if the VM already exists don't do anythng
            # lookup the VM by name and by vmx
            if self._poc.getVM("name", args) or self._poc.getVM("vmx", vm["vmx"]):
                print("'{0}' already exists".format(args))
            else:
                safeCopies = self._poc.dataStoreURL + '/safecopies/'
                self._poc.deployVM(args, safeCopies)

    def _deploy_suite(self, args):
        for vm in self._poc.bom:
            if args in vm["suite"] :
                self._deploy_vm(self, vm["product"])

    def _deploy(self, line):
        parts = line.partition(' ')
        action = parts[0].strip()
        args = parts[2]
        try:
            getattr(self, '_deploy_'+action)(args)
        except AttributeError:
            print("% Unrecognized command 'deploy {0}'".format(action))
            self._help_deploy()
        
    def _help_deploy(self):
        print('\n'.join(["deploy vm\tdeploy a virtual machine",
                        "deploy suite\tdeploy a suite of VMs"]))

    def complete_deploy(self, text, line, begidx, endidx):
        options = ['suite', 'vm']
        if line.lower().startswith('deploy vm ') :
            options = [vm["product"] for vm in self._poc.bom]
            line = line.partition(' ')[2]
        elif line.lower().startswith('deploy suite ') :
            suites = [ vm["suite"] for vm in self._poc.bom ]
            options = set( option for suite in suites for option in suite )
            line = line.partition(' ')[2]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        completes = [s[offs:] for s in options if s.startswith(mline)]
        return completes

    def do_exit(self, line):
        return True

    def help_exit(self):
        self.print_help_topics("'exit' or 'quit' stops this crazy thing.")

    do_EOF = do_exit


if __name__ == '__main__':
    with POCAdmin("root", "CAdemo123") as poc:
        cli = POCConsole(poc)
        cli.cmdloop()

