#!/usr/bin/env python

from pyVim.connect import SmartConnect, Disconnect
import pyVmomi
from pyVmomi import vim, vmodl
import json
import six
from utils import byteify, ToJSON
import re
from os.path import split as splitpath, isdir
from os import makedirs, listdir
from time import sleep
from threading import Thread
import tarfile
import urllib.request
from urllib.parse import urlsplit, urlunsplit
from socket import inet_pton, AF_INET, error as socket_error
from struct import unpack

def getVMs(si):

    # collector = si.content.propertyCollector
    # objSpec = pyVmomi.vmodl.query.PropertyCollector.ObjectSpec()
    view = si.content.viewManager.CreateContainerView(
               container=si.content.rootFolder,
               type=[vim.VirtualMachine],
               recursive=True)
    # objSpec.obj = view
    # objSpec.skip = True
    
    # travSpec = pyVmomi.vmodl.query.PropertyCollector.TraversalSpec()
    # travSpec.name = 'traverseVirtualMachines'
    # travSpec.path = 'view'
    # travSpec.skip = False
    # travSpec.type = view.__class__
    
    # objSpec.selectSet = [travSpec]
    
    # propSpec = pyVmomi.vmodl.query.PropertyCollector.PropertySpec()
    # propSpec.type = vim.VirtualMachine
    
    # filterSpec =  pyVmomi.vmodl.query.PropertyCollector.FilterSpec()
    # filterSpec.objectSet = [objSpec]
    # filterSpec.propSet = [propSpec]
    
    # content = collector.RetrieveContents([filterSpec])
    # print([vm.summary for vm in view.view])
    VMs = [v for v in view.view]
    view.Destroy()
     
    return VMs

def getHosts(si):
    view = si.content.viewManager.CreateContainerView(si.content.rootFolder,
                         [vim.HostSystem],
                         True)
    hosts = [h for h in view.view]
    view.Destroy()
    return hosts

"""
 Waits and provides updates on a vSphere task
"""
def taskWait(task):

    while task.isRunning:
       sleep(2)
    
    if task.info.state == vim.TaskInfo.State.error:
        raise task.info.error

    return task.info.result

vim.Task.wait = taskWait
vim.Task.isRunning = property(lambda t: t.info.state == vim.TaskInfo.State.running)

vim.Task.isAlive = property(lambda t: t.info.state not in [
    vim.TaskInfo.State.success, vim.TaskInfo.State.error])
                  
class VMConfig(object) :
    
    def __init__(self, vm, netcfg = None, tz = None, auth = None) :
        self._vm = vm
        self._guest = None
        self._build = ""
        self._nets = {} if netcfg is None else dict( (n.network, n) for n in netcfg )
        
        try:
            guest = guestIds[self.guestId]
        except KeyError as e:
            # raise NotImplementedError(self.guestId + " is not a supported guest")
            pass
        else:
            try:
                self._guest = globals()[guest](self._vm.guest)
                if tz is not None:
                    self.tz = tz

                if auth is not None:
                    self.auth = auth

            except KeyError as e:
                pass
                # raise NotImplementedError("The class " + guest + " for " + self.guestId + " does not exist")
            except TypeError as e:
                raise NotImplementedError("TypeError: " + e.args)

    def __repr__(self) :
        return repr(self._vm.summary)

    def __call__(self):
        return self._vm

    @property        
    def name(self):
        return self._vm.config.name

    @property
    def hostname(self):
        return self._vm.guest.hostName

    @property        
    def vmx(self):
        vmx = splitpath(re.sub(r'\[.+?\] ', '', self._vm.summary.config.vmPathName))[1]
        return vmx

    @property        
    def uuid(self):
        return self._vm.config.uuid

    @property        
    def notes(self):
        return self._vm.config.annotation.split('\n')

    @property
    def powerStateOn(self):
        return self._vm.runtime.powerState == 'poweredOn'

    @property
    def powerState(self):
        return self._vm.runtime.powerState

    @property
    def toolsOk(self):
        return self._vm.guest.toolsStatus == 'toolsOk'

    @property
    def toolsStatus(self):
        return self._vm.guest.toolsStatus

    @property
    def guestId(self):
        id = self._vm.summary.guest.guestId
        if id is None:
            id = self._vm.summary.config.guestId
            
        return id
        
    @property
    def guestState(self):
        return self._vm.guest.guestState

    @property
    def guestReady(self):
        return self._vm.guest.guestState == "running" and self.netState == "guestNetReady" and self.auth is not None

    @property
    def build(self):
        return self._build

    @property
    def tzCfg(self):
        if self._guest is not None:
            return self._guest.tzCfg 

    @tzCfg.setter
    def tzCfg(self, tzCfg):
        if self._guest is not None:
            self._guest.tzCfg = tzCfg

    @property
    def timezone(self):
        if self._guest is not None:
            return self._guest.timezone

    @property
    def auth(self):
        if self._guest is not None:
            return self._guest.auth 

    @auth.setter
    def auth(self, auth):
        if self._guest is not None:
            self._guest.auth = auth

    @property
    def networks(self):
        return list(self._nets.values())

    @networks.setter
    def networks(self, netcfg):
        if netcfg is None or not netcfg:
            self._nets = {}
        else:
            self._nets[netcfg.network] = netcfg

    @property
    def netState(self):
        for net in self._nets:
            for n in self._vm.guest.net:
                if net == n.network:
                    break
            else:
                return "guestNetNotReady"

        return "guestNetReady"

    def getNet(self, network):
        return self._nets.get(network, None) 

    def setNet(self, netcfg):
        self.networks = netcfg

    def applyNet(self, pm, netcfg = None):
        if self._guest is not None:
            if netcfg is not None:
                #self._nets[netcfg.network] = netcfg
                self.runCmd(pm, self._guest.setIP(netcfg))
            else:
                for n in self._nets:
                    self.runCmd(pm, self._guest.setIP(n))

    def getIP(self, network = None):
        ips = []
        if network is None:
            if self._vm.guest.ipAddress is not None:
                ips = [ self._vm.guest.ipAddress ]
        else:
            ips = [ip for nic in self._vm.guest.net for ip in nic.ipAddress if nic.network == network]
            
        return ips
        
    def applyTZ(self, pm, tzCfg):
        if self._guest is not None:
            self.runCmd(pm, self._guest.setTZ(tzCfg))

    def deployHosts(self, hosts, fm):
        if self._guest is not None:
            self._guest.hostsFile
        # self.uploadFile(hosts, self._guest.hostsFile, file[2], fm)

    def addHost(self, host, ip, pm):
        if self._guest is not None:
            todo = self._guest.todoAddHost(host, ip)
            auth = vim.vm.guest.NamePasswordAuthentication(username=self._guest.auth.username,
                                                       password=self._guest.auth.password)
            for spec in todo:
                #pm.StartProgramInGuest(self._vm, auth, spec)
                self.runCmd(pm, spec)

    def runCmd(self, pm, ps):
        if self._guest is not None:
            auth = vim.vm.guest.NamePasswordAuthentication(username=self._guest.auth.username,
                                                       password=self._guest.auth.password)
            res = pm.StartProgramInGuest(self._vm, auth, ps)
            return res
        
    def uploadFile(self, src, dst, attrs, fm):
        if self._guest is None:
            return

        with open(src, 'rb') as f:
            data = f.read()

        auth = vim.vm.guest.NamePasswordAuthentication(username=self._guest.auth.username,
                                                       password=self._guest.auth.password)
        url = fm.InitiateFileTransferToGuest(self._vm, auth, dst, attrs, len(data), True)

        opener = urllib.request.build_opener(urllib.request.HTTPHandler)
        parts = list(urlsplit(url))
        parts[0] = 'http'
        parts[1] = 'localhost'
        url = urlunsplit(parts)
        req = urllib.request.Request(url, data = data)
        req.add_header('Content-Type', 'application/octet-stream')
        req.get_method = lambda: 'PUT'
        resp = opener.open(req)

    def downloadFile(self, fm, src, dst = None):
        if self._guest is None:
            return

        data = None
        auth = vim.vm.guest.NamePasswordAuthentication(username=self._guest.auth.username,
                                                       password=self._guest.auth.password)
        try:
           fti = fm.InitiateFileTransferFromGuest(self._vm, auth, src)

        except vim.fault.FileNotFound:
            pass
        else:
            url = fti.url
            parts = list(urlsplit(url))
            parts[0] = 'http'
            parts[1] = 'localhost'
            url = urlunsplit(parts)
            resp = urllib.request.urlopen(url)
            if resp.getcode() == 200:
                if dst:
                    with open(dst, "wb") as fh:
                        fh.write(resp.read())
                else:
                    data = resp.read()

        return data

    def getBuild(self, fm):
        if self._guest is None:
            return

        data = self.downloadFile(fm, self._guest.verFile)
        if data:
            # data = json.load(data, object_hook=byteify)
            data = json.load(data, object_hook=byteify)
            self._build = data["version"]

        return self._build

    def checkFiles(self, fm):
        if self._guest is None:
            return

        ret = False
        files = []
        auth = vim.vm.guest.NamePasswordAuthentication(username=self._guest.auth.username,
                                                       password=self._guest.auth.password)
        try:
            files = fm.ListFilesInGuest(self._vm, auth, self._guest.dir).files
        except vim.fault.FileNotFound:
            print((self._guest.dir))
            pass

        for i in files:
            pass
        
        return ret

    def stageFiles(self, fm):
        if self._guest is None:
            return

        auth = vim.vm.guest.NamePasswordAuthentication(username=self._guest.auth.username,
                                                       password=self._guest.auth.password)
        try:
            fm.MakeDirectoryInGuest(self._vm, auth, self._guest.dir, False)

        except vim.fault.FileAlreadyExists:
            pass

        for file in self._guest.files:
            self.uploadFile(file[0], file[1], file[2], fm)

    def to_json(self):
        tojson = { "name" : self.name,
                   "uuid" : self.uuid,
                   "vmx" : self.vmx,
                   "networks" : self.networks,
                   "timezone" : self.tzCfg,
                   "authentication" : self.auth
                 }
        return tojson


guestIds = { 'windows7Server64Guest' : 'WindowsGuest',
             'windows8Server64Guest' : 'WindowsGuest',
             'rhel6_64Guest' : 'LinuxGuest',
             'centos64Guest' : 'LinuxGuest',
             'centos6_64Guest' : 'LinuxGuest',
             'centos7_64Guest' : 'LinuxGuest',
             'otherLinux64Guest' : 'LinuxGuest'
           }

class Guest(object) :
    def __init__(self):
        raise NotImplementedError("Subclasses should implement this!")

    @property 
    def auth(self):
        raise NotImplementedError("Subclasses should implement this!")

    @auth.setter
    def auth(self, creds):
        raise NotImplementedError("Subclasses should implement this!")

    @property
    def files(self):
        raise NotImplementedError("Subclasses should implement this!")

    @property 
    def dir(self):
        raise NotImplementedError("Subclasses should implement this!")

    @property
    def tzCfg(self):
        raise NotImplementedError("Subclasses should implement this!")

    @property
    def timezone(self):
        raise NotImplementedError("Subclasses should implement this!")

    @property
    def verFile(self):
        raise NotImplementedError("Subclasses should implement this!")

    def getCustomizeSpec(self, network):
        raise NotImplementedError("Subclasses should implement this!")
        
    def applyTZ(self, tz):
        raise NotImplementedError("Subclasses should implement this!")
        
    @property    
    def hostsFile(self):
        raise NotImplementedError("Subclasses should implement this!")
        
    def runCmd(self, cmd):
        raise NotImplementedError("Subclasses should implement this!")
        
    def copyFile(self, src, dst):
        raise NotImplementedError("Subclasses should implement this!")

    def checkFiles(self):
        raise NotImplementedError("Subclasses should implement this!")


class WindowsGuest(Guest):
    def __init__(self, guest):
        self._guest = guest
        self._fileloc = 'c:\POCsetup'
        self._files = ('setIP.cmd', 'setTZ.cmd')
        self._auth = AuthConfig(username='Administrator', password='CAdemo123')
        self._shell = "c:\windows\system32\cmd.exe" #"%COMSPEC%"
        self._tzCfg = None #TZConfig()
        
    @property
    def auth(self):
        return self._auth

    @auth.setter
    def auth(self, creds):
        self._auth = creds

    @property
    def files(self):
        attrs = vim.vm.guest.FileManager.FileAttributes()
        flist = [("./scripts/" + f, "{0}\{1}".format(self._fileloc, f), attrs) for f in self._files]
        flist.append(("POC_BUILD_ID", self._fileloc + "\POC_BUILD_ID", attrs))
        return flist

    @property 
    def dir(self):
        return self._fileloc

    @property
    def verFile(self):
        return self._fileloc + "\POC_BUILD_ID"

    def getCustomizeSpec(self, network):
        spec = vim.vm.customization.Specification()
        spec.globalIPSettings = vim.vm.customization.GlobalIPSettings()

        opts = vim.vm.customization.WinOptions()
        opts.changeSID = False
        opts.deleteAccounts = False
        opts.reboot = vim.vm.customization.WinOptions.SysprepRebootOption.noreboot
        spec.options = opts

        id = vim.vm.customization.Sysprep()
        id.identification = vim.vm.customization.Identification()

        id.guiUnattended = vim.vm.customization.GuiUnattended()
        id.guiUnattended.autoLogon = False
        id.guiUnattended.timeZone = 35
        id.guiUnattended.password = vim.vm.customization.Password()
        id.guiUnattended.password.plainText = True
        id.guiUnattended.password.value = "CAdemo123"
        spec.identity = id

        udata = vim.vm.customization.UserData()
        udata.fullName = "CA Technologies"
        udata.orgName = "CA Technologies"
        udata.computerName = self._guest.hostName
        udata.productId = "489J6-VHDMP-X63PK-3K798-CPX3Y"
        spec.userData = udata
        
        print((len(self._vm.guest.net)))
        
        for n in networks:
            net = None
            for nic in self._vm.guest.net:
                if nic.network == n.network:
                    net = nic
                    print((n.network))
                    break

            if net is None:
                raise KeyError

        adapter = vim.vm.customization.AdapterMapping()
        ipProps = vim.vm.customization.IPSettings()
        ipProps.ip = network.ipaddr
        ipProps.subnetMask = network.netmask
        ipProps.gateway = network.gateway
        ipProps.dnsServerList = network.dns
        adapter.adapter = ipProps
        spec.nicSettingMap = [adapter]
        
        return spec

    @property
    def tzCfg(self):
        return self._tzCfg

    @tzCfg.setter
    def tzCfg(self, tzCfg):
        self._tzCfg = tzCfg

    @property
    def timezone(self):
        tz = ""
        if self._tzCfg is not None:
            tz = self._tzCfg.tzW
        return tz

    def setTZ(self, tzCfg):
        cmd = "{0}\{1}".format(self._fileloc, "setTZ.cmd")
        args = "\"" + tzCfg.tzW + "\""
        
        # print("{0} {1}".format(cmd,args))
        return vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments=args)

    @property
    def hostsDir(self):
        return "" #'%SYSTEMROOT%\system32\drivers\etc\'

    @property
    def hostsFile(self):
        # finfo = vim.vm.guest.FileManager.FileInfo()
        # print(finfo)
        return "%SYSTEMROOT%\system32\drivers\etc\hosts"

    def todoAddHost(self, host, ip):
        todo = []

        args = "/c (copy /y {0} {0}.sav)".format(self.hostsFile)        
        args += ' & (type {0} | findstr /v /i /c:"{1}" | findstr /v /i /c:"{2}" > {0}.wrk)'.format(self.hostsFile, host, ip)
        args += " & (echo {2}\t{1} >> {0}.wrk)".format(self.hostsFile, host, ip)
        args += " & (move /y {0}.wrk {0})".format(self.hostsFile)

        todo.append(vim.vm.guest.ProcessManager.ProgramSpec(programPath=self._shell, arguments=args))

        return todo

    def setIP(self, net):
        # return the command to set the IP address
        # Get the MAC address of the interface connected to the network
        mac = ""
        for n in self._guest.net:
            if n.network == net.network:
                mac = n.macAddress.replace(":", "-").upper()
                break
        else:
            raise ValueError

        #cmd = self._shell
        cmd = "{0}\{1}".format(self._fileloc, "setIP.cmd")
        args = '{0} {1} {2} {3} {4}'.format(mac, net.proto, net.ipaddr, net.netmask, net.gateway)
        for dns in net.dns:
            args = args + " " + dns

        args += ' > {0}\setIP.log'.format(self._fileloc)

        #print("{0} {1}".format(cmd,args))
        return vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments=args)

    def todoCheckFile(self):
        shell = 'c:\windows\system32\cmd.exe'
        shell = "%COMSPEC%"
        args = '/c if exist {0}\{1} (echo "True") else (echo "False")'
        return [vim.vm.guest.ProcessManager.ProgramSpec(
                programPath=shell,
                arguments=args.format(self._fileloc, f)) for f in self._files]

    
class LinuxGuest(Guest):

    def __init__(self, guest):
        self._guest = guest
        self._fileloc = '/opt/POCsetup'
        self._files = ('setIP.sh', 'setTZ.sh')
        self._auth = AuthConfig(username='root', password='CAdemo123')
        self._shell = '/bin/bash'
        self._tzCfg = None #TZConfig()

    @property
    def auth(self):
        return self._auth

    @auth.setter
    def auth(self, creds):
        self._auth = creds

    @property
    def files(self):
        attrs = vim.vm.guest.FileManager.PosixFileAttributes()
        attrs.permissions = 511
        flist = [("./scripts/" + f, "{0}/{1}".format(self._fileloc, f), attrs) for f in self._files]
        flist.append(("POC_BUILD_ID", self._fileloc + "/POC_BUILD_ID", vim.vm.guest.FileManager.PosixFileAttributes()))
        return flist

    @property 
    def dir(self):
        return self._fileloc

    @property
    def verFile(self):
        return self._fileloc + "/POC_BUILD_ID"

    def getCustomizeSpec(self, network):
        spec = vim.vm.customization.Specification()

        globals = vim.vm.customization.GlobalIPSettings()
        globals.dnsServerList = network.dns
        spec.globalIPSettings = globals

        id = vim.vm.customization.Linuxprep()
        spec.identity = id

        adapter = vim.vm.customization.AdapterMapping()
        ipProps = vim.vm.customization.IPSettings()
        ipProps.ip = network.ipaddr
        ipProps.subnetMask = network.netmask
        ipProps.gateway = network.gateway
        adapter.adapter = ipProps
        spec.nicSettingMap = [adapter]
        
        return spec

    def setIP(self, net):
        # return the command to set the IP address
        # Get the MAC address of the interface connected to the network
        mac = ""
        for n in self._guest.net:
            if n.network == net.network:
                mac = n.macAddress.upper()
                break
        else:
            raise ValueError

        cmd = "{0}/{1}".format(self._fileloc, "setIP.sh")
        args = "{0} {1} {2} {3} {4}".format(mac, net.proto, net.ipaddr, net.netmask, net.gateway)
        for dns in net.dns:
            args = args + " " + dns
        args += " > {0}/setIP.log".format(self._fileloc)
        # print("{0} {1}".format(cmd,args))
        return vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments=args)


    @property
    def tzCfg(self):
        return self._tzCfg

    @tzCfg.setter
    def tzCfg(self, tzCfg):
        self._tzCfg = tzCfg

    @property
    def timezone(self):
        tz = ""
        if self._tzCfg is not None:
            tz = self._tzCfg.tz
        return tz

    def setTZ(self, tzCfg):
        cmd = "{0}/{1}".format(self._fileloc, "setTZ.sh")
        args = "\"" + tzCfg.tz + "\""
        
        # print("{0} {1}".format(cmd,args))
        return vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments=args)

    @property    
    def hostsFile(self):
        return "/etc/hosts"

    def todoAddHost(self, host, ip):
        todo = []
        cmd = self._shell
        args = "-c \"sed -ie '/{0}/Id' {1}".format(host, self.hostsFile)
        args += "; sed -ie '/{0}/d' {1}".format(ip, self.hostsFile)
        args += "; echo -ne '{0}\t\t{1}\n' >> {2}\"".format(ip, host, self.hostsFile)
        # print("{0} {1}".format(cmd,args))
        todo.append(vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments=args))

        #cmd = '/bin/echo'
        #args = "-ne '{0}\t{1}\n' >> {2}".format(ip, host, self.hostsFile)
        #todo.append(vim.vm.guest.ProcessManager.ProgramSpec(programPath=cmd, arguments=args))
        
        return todo

    def checkFileCmds(self):
        shell = self._shell
        args = 'if [ -e {0}/{1} ] ; then echo "True" ; else echo "False" ; fi'
        return [vim.vm.guest.ProcessManager.ProgramSpec(
                programPath=shell,
                arguments=args.format(self._fileloc, f)) for f in self._files]

class AuthConfig(object):
    def __init__(self, username, password):
        self._username = username
        self._password = password

    def to_json(self):
        tojson = { "username" : self._username, "password" : self._password }
        return tojson

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, user):
        self._username = user

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, pwd):
        self._password = pwd

    def __str__(self):
        return '{ "username" : {0}, "password" : {1} }'.format(self._username, self._password)

    def __repr__(self):
        return self.__class__.__name__ + "(username={0}, password={1}".format(self._username, self._password)

class HostConfig(object) :
    def __init__(self, si):
        self._si = si
        self._host = getHosts(self._si)[0]
        
    def __repr__(self):
        return repr(self._host.summary)

    def __call__(self):
        return self._host

    @property
    def dateTimeInfo(self):
        dtSystem = self._host.configManager.dateTimeSystem 
        return dtSystem.dateTimeInfo

    @property
    def dateTime(self):
        return self._host.configManager.dateTimeSystem.QueryDateTime()

    @property
    def product(self):
        return self._host.summary.config.product.fullName

    @property
    def ipaddr(self):
        vnics = self._host.configManager.networkSystem.networkConfig.vnic
        #if not vnic:
        #    return ""
        #try:
        #    vmk0 = [ nic for nic in vnics if nic.device == "vmk0" ][0]
        #except IndexError:
            #vmk0 = vnics[0]

        ips = ",".join([ nic.spec.ip.ipAddress for nic in vnics])
        return ips    #vmk0.spec.ip.ipAddress

    def UpdateDateTimeConfig(self, tz, ntp):
        dtSystem = self._host.configManager.dateTimeSystem
        dtConfig = vim.host.DateTimeConfig()
        dtConfig.timeZone = tz
        ntpConfig = vim.host.NtpConfig()
        ntpConfig.server = ntp
        dtConfig.ntpConfig = ntpConfig
        dtSystem.UpdateDateTimeConfig(dtConfig)

    def QueryAvailableTimeZones(self):
        dts = self._host.configManager.dateTimeSystem
        return dts.QueryAvailableTimeZones()

    @property
    def license(self):
        manager = self._si.content.licenseManager
        return manager.licenses[0].licenseKey

    @license.setter
    def license(self, key):
        self._si.content.licenseManager.UpdateLicense(key)

    @property
    def name(self):
        return self._host.name

    @property
    def datastore(self):
        return self._host.datastore[0]

    def to_json(self):
        tojson = '{ "username" : {0}, "password" : {1} }'.format(self.username, self.password)
        return tojson


class TZConfig(object):
    from tzmap import tz_map

    def __init__(self, tz = 'UTC', tzWin = None):
        self._tz = tz
        self._tzWin = tzWin
        self._dst = True

    @property
    def tz(self):
        return self._tz

    @tz.setter
    def tz(self, tz):
        self._tz = tz

    @property
    def tzW(self):
        if self._tzWin is None:
            return TZConfig.tz_map.get(self._tz, None)
        else:
            return self._tzWin

    @tzW.setter
    def tzW(self, tzW):
        self._tzW = tzW

    def to_json(self):
        tojson = { "tz" : self.tz, "tzWin" : self.tzW }
        return tojson #self.tz

    def __str__(self):
        return self._tz

    def __repr__(self):
        return self.__class__.__name__ + "(tz={0}, tzWin={1}".format(self._tz, self._tzWin)

class NetConfig(object):
    def __init__(self, network, ipaddr=None, netmask="", gateway="", dns=[]):
        self._network = network
        self._ip = "dhcp" if ipaddr is None else ipaddr.lower()
        self._mask = netmask
        self._gw = gateway
        self._dns = dns

    @staticmethod
    def isValidIP(ip):
        try:
            inet_pton(AF_INET, ip)
        except socket_error:  # not a valid address
            return False

        return True

    @staticmethod
    def isValidMask(netmask):
        try:
            addr = inet_pton(AF_INET, netmask)
        except socket_error:  # not a valid address
            return False

        bits = format(0xffffffff, 'b')
        mask = format(unpack('>I',addr)[0], 'b').rstrip('0')
        bits = bits[:len(mask)]
        return mask == bits

    @property
    def network(self):
        return self._network

    @network.setter
    def network(self, netname):
        self._network = netname

    @property
    def ipaddr(self):
        return self._ip

    @ipaddr.setter
    def ipaddr(self, ip):
        self._ip = "dhcp" if ip is None else ip.lower()
        
    @property
    def netmask(self):
        return self._mask

    @netmask.setter
    def netmask(self, mask):
        self._mask = mask

    @property
    def gateway(self):
        return self._gw

    @gateway.setter
    def gateway(self, gw):
        self._gw = gw

    @property
    def dns(self):
        return self._dns

    @dns.setter
    def dns(self, hosts):
        self._dns = hosts

    @property
    def dhcp(self):
        return self._ip is None or self._ip.lower() == "dhcp"

    @dhcp.setter
    def dhcp(self, bool):
        if bool: self._ip = "dhcp"

    @property
    def proto(self):
        ret = "static"
        if self._ip is None or self._ip.lower() == "dhcp":
            ret = "dhcp"
        return ret

    def __repr__(self):
        return self._network

    def __str__(self):
        return self._network

    def to_json(self):
        tojson = { "network" : self._network,
                 "gateway" : self._gw,
                 "dns" : self._dns,
                 "netmask" : self._mask,
                 "ipaddr" : self._ip }
        return tojson

class Archive(object):

    @property
    def name(self):
        raise NotImplementedError("Subclasses should implement this!")

    @name.setter
    def name(self, val):
        raise NotImplementedError("Subclasses should implement this!")

    def open(self):
        raise NotImplementedError("Subclasses should implement this!")

    def deploy(self):
        raise NotImplementedError("Subclasses should implement this!")

    def close(self):
        raise NotImplementedError("Subclasses should implement this!")

class OVAArchive(Archive) :
    def __init__(self, filename):
        self._fname = filename
        self._ovfd = None
        self._lease = None
        self._cisp = vim.OvfManager.CreateImportSpecParams()
        self._cisp.diskProvisioning = "thin"
        self._tar = None

    @property
    def name(self):
        return self._cisp.entityName

    @name.setter
    def name(self, name):
        self._cisp.entityName = name

    def _update_status(self):
        while(True):
            sleep(5)
            try:
                # Choosing arbitrary percentage to keep the lease alive.
                if (self._lease.state == vim.HttpNfcLease.State.done):
                    self._lease.HttpNfcLeaseProgress(100)
                    return

                self._lease.HttpNfcLeaseProgress(50)

            # If the lease is released, we get an exception.
            # Returning to kill the thread.
            except:
                return

    def open(self):
        self._tar = tarfile.open(self._fname)

    def deploy(self, si, progress):
        #try:
        for item in self._tar.getmembers():
            name = item.name
            if name.endswith('.ovf'):
                self._ovfd = self._tar.extractfile(item).read()
                break
        else:
            #self._tar.close()
            raise IOError("No OVF descriptor found")

        manager = si.content.ovfManager
        dc = si.content.rootFolder.childEntity[0]

        # host = dc.hostFolder.childEntity[0].host[0]
        dstore = dc.datastoreFolder.childEntity[0]

        # folder = dc.vmFolder
        pool= dc.hostFolder.childEntity[0].resourcePool
        spec = manager.CreateImportSpec(self._ovfd, pool, dstore, self._cisp)

        self._lease = pool.ImportVApp(spec.importSpec) #, folder, host)

        vm = None
        while(True):
            if (self._lease.state == vim.HttpNfcLease.State.ready):
                # Spawn a dawmon thread to keep the lease active while POSTing
                status_thread = Thread(target=self._update_status, args=[])
                status_thread.start()

                # POST the items to the corresponding urls
                # opener = urllib2.build_opener(urllib2.HTTPHandler)
                for i in range(len(spec.fileItem)):                           
                    item = spec.fileItem[i]                                   
                    url = self._lease.info.deviceUrl[i].url                   
                    parts = list(urlsplit(url))                               
                    parts[0] = 'http'                                         
                    parts[1] = 'localhost'                                    
                    url = urlunsplit(parts)

                    try:
                        file = self._tar.extractfile(item.path)
                        req = urllib.request.Request(url, data = file)
                        req.add_header('Content-Type', 'application/x-vnd.vmware-streamVmdk')
                        req.add_header('Content-length', item.size)
                        #req.get_method = lambda: 'POST'
                        resp = urllib.request.urlopen(req) #opener.open(req)
                    except:
                        self._lease.HttpNfcLeaseAbort()
                        status_thread.join()
                        raise

                vm = self._lease.info.entity
                self._lease.HttpNfcLeaseComplete()
                status_thread.join()
                break

            elif (self._lease.state == vim.HttpNfcLease.State.error):
                raise self._lease.error

        return vm

    def close(self):
        self._tar.close()

class TGZArchive(Archive) :
    def __init__(self, filename):
        self._fname = filename
        self._name = splitpath(filename)[1][:-4]
        self._tar = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    def open(self):
        self._tar = tarfile.open(self._fname)

    def deploy(self, si, progress = None):
        #Create a directory for the files based on self._name
        dc = si.content.rootFolder.childEntity[0]
        dstore = dc.datastoreFolder.childEntity[0]
        dstoreUrl = dstore.summary.url
        if not dstoreUrl.endswith('/'):
            dstoreUrl +='/'

        path = dstoreUrl + self._name + '/'

        # Does this directory already exist
        if isdir(path):
            raise Exception("'{0}' already exists!".format(path))

        # makedirs(path)
        self._tar.extractall(dstoreUrl)
        #Now find the vmx file and add the VM to inventory
        vmx = ""
        for file in listdir(path):
            if file.endswith(".vmx"):
                vmx = file
                break
        else:
            raise IOError("No VMX file could be found")

        pool= dc.hostFolder.childEntity[0].resourcePool
        folder = dc.vmFolder
        path = "[{0}] {1}/{2}".format(dstore.name, self._name, vmx)
        task = folder.RegisterVM_Task(path,name=self._name,asTemplate=False, pool=pool)
        vm = task.wait()
        return vm

    def close(self):
        self._tar.close()

class POCArchive(object):
    _archiveTypes = { ".ova" : "OVAArchive", ".tgz" : "TGZArchive" }

    def __init__(self, filename):
        self._fname = filename
        self._archive = None
        
        try:
            aType = POCArchive._archiveTypes[filename[-4:]]
        except KeyError as e:
            raise NotImplementedError(filename + " is not a supported archive")
            
        else:
            self._archive = globals()[aType](self._fname)

    def __enter__(self):
        
        self._archive.open()
        return self._archive

    def __exit__(self, type, value, traceback):
        if self._archive is not None:
            self._archive.close()
            
        if type is not None: return False
        return self

class BOM(object):
    def __init__(self):
        try:
            with open("BOM.json", 'r') as f:
                self._bom = json.load(f) #,  object_hook=byteify)
            # index by vmx
            self._view = dict( (v["product"], v) for v in self._bom )
        except IOError:
            pass

    def __iter__(self):
        i = 0
        s = len(self._bom)
        while i < s:
            yield(self._bom[i])
            i+=1
        #return self

    def __getitem__(self, product):
        return self._view.get(product, {})


class POCConfig(object):
    def __init__(self, si):
        self._si = si
        # Retrieve the processManager
        self._pm = self._si.content.guestOperationsManager.processManager
        self._fm = self._si.content.guestOperationsManager.fileManager

        self._host = HostConfig(self._si)

        self._system = {}
        self._system["timezone"] = TZConfig()
        self._VMs = []
        self._config = {}

        # self._index = 'uuid'

        self._build = "0"
        self._load_config()
        #self._load_bom()
        self._bom = BOM()

    def _load_config(self):
        self._VMs = [VMConfig(v) for v in getVMs(self._si)]
        self._config = dict( (vm.uuid, vm) for vm in self._VMs )
        #self._config = dict( (getattr(vm, 'uuid'), vm) for vm in self._VMs )
        try:
            with open("POC_BUILD_ID", 'r') as fh:
                build = json.load(fh, object_hook=byteify)
                #self._build = build["version"]

        except IOError as e:
            pass
    
        try:
            with open("config.json", 'r') as fh:
                config = json.load(fh, object_hook=byteify)
                #self._build = build["version"]
                self._system = config.get("system", {})
                tz = self._system.pop("timezone", None)
                self.tzCfg = TZConfig(tz.get("tz", 'UTC')) if tz is not None else TZConfig()

                view = dict( (v['uuid'], v) for v in config.get("VMs", []) )
                for vm in self._VMs:
                    v = view.get(vm.uuid, {})

                    # if not v, config has no reference to this vm. 
                    if v:
                        #
                        tz = v.get("timezone", None)
                        if tz is not None:
                            vm.tzCfg = TZConfig(tz.get("tz", self._system["timezone"].tz))
                        #else:
                        #    vm.tzCfg = self._system["timezone"]

                        auth = v.get("authentication", None)
                        if auth is not None:
                            vm.auth = AuthConfig(auth["username"], auth["password"])
                        
                        nets = v.get("networks", [])
                        for net in nets:
                            vm.networks = NetConfig(**net)


        except IOError as e:
            pass
        except ValueError as e:
            pass

    def glean(self):
        sys = {'POC_TIMEZONE' : '', 'POC_TIMEZONE_WIN' : '', 'POC_TIMEZONE_UTC' : '',
              'GATEWAY_ALL' : '', 'NETMASK_ALL' : '', 'DNS_ALL_1' : '', 'DNS_ALL_2' : '',
              'ESXI_NTPD_SERVER_1' : '', 'ESXI_NTPD_SERVER_2' : '', 'ESXI_NTPD_SERVER_3' : ''}
        props = {}

        try:
            with open("setupAppliance.properties", 'r') as f:
                props = dict((k.strip().strip('"' "'"),v.strip().strip('"' "'")) for (k, v) in [line.strip().split('=', 1) for line in f if not line.strip().startswith("#") and '=' in line])
                sys_props = dict((k, props[k]) for k in sys if k in props)

            self.tzCfg = TZConfig(sys_props.get("POC_TIMEZONE", 'UTC'))
            self._system["timezone"].tzW = sys_props.get("POC_TIMEZONE_WIN", 'UTC')
            self.dns = list(filter(len,set([sys_props.get('DNS_ALL_1',""),sys_props.get('DNS_ALL_2',"")])))
            self.netmask = sys_props.get('NETMASK_ALL',"")
            self.gateway = sys_props.get('GATEWAY_ALL', "")
                
        except IOError as e:
            pass

        try:
        
            # The config is indexed by VM uuid; but BOM only knows about vmx filename
            # get a view of the VMs indexed by vmx
            view = dict( (v['vmx'], v) for v in self._bom )

            for vm in self._VMs:
                v = view.get(vm.vmx, {})

                # if not v, the BOM has no reference to this vm. This vm is out of scope of setupAppliance
                if v:
                    #
                    tz = v.get("timezone", None)
                    if tz is not None:
                        vm.tzCfg = TZConfig(tz)
                    #else:
                        #vm.tzCfg = self.tzCfg

                    auth = v.get("authentication", None)
                    if auth is not None:
                        vm.auth = AuthConfig(auth["username"], auth["password"])
                        
                    if "ipVar" in v and v["ipVar"] in props:
                        net = {}
                        net["network"] = "VM Network"
                        net["ipaddr"] = props[v["ipVar"]]
                        net["netmask"] = self.netmask
                        net["gateway"] = self.gateway
                        net["dns"] = self.dns
                        v["networks"] = [net]
                    #print(v["product"],v.get("networks",[]))
                    nets = [NetConfig(**n) for n in v.get("networks",[])]
                    for net in nets:
                        vm.networks = net

        except IOError as e:
            pass

    def getNetConfig(self, vm):
        return vm.networks

    def deployVM(self, product, archiveloc, progress=None):
        vm = self._bom[product]
        if vm:
            if self.getVM("name", product) or self.getVM("vmx", vm["vmx"]):
                raise vim.fault.VmAlreadyExistsInDatacenter(self._host.name, self._host.name, product)
            else:
                if not archiveloc.endswith('/'):
                    archiveloc += '/'
                try:
                    with POCArchive(archiveloc + vm["archive"]) as archive:
                        archive.name = product
                        v = archive.deploy(self._si, progress)
                        if v:
                            self._VMs.append(VMConfig(v))
                    
                except IOError:
                    print(("{0} cannot be found in archive location, {1}".format(vm["archive"], archiveloc)))
                    raise vim.fault.NotAFile

    def save(self, file='config.json'):
        with open(file, 'w') as fh:
            #config = self._config.values()
            #for v in config:
            #    v["networks"] = v.get("networks", {}).values()
            json.dump({ "system" : self._system, "VMs" : self._VMs }, fh, cls=ToJSON, indent=4, sort_keys=True)

    def verify(self):
        pass

    #def getTZ(self, vm = None):
    #    tz = None
    #    if not vm:
    #        return self._system["timezone"]
    #    return vm.timezone

    def configTZ(self, vm, tzCfg):
        vm.tzCfg = tzCfg
         
    def configNet(self, vm, net):
        vm.networks = net
    
    def applyNet(self, vm, netcfg = None):
        vm.applyNet(self._pm, netcfg)

    def applyTZ(self, vm, tzCfg = None):
        vm.applyTZ(self._pm, tzCfg)

    def configAuth(self, vm, username, password):
        vm.auth = AuthConfig(username, password)

    def getVM(self, attr, value):
        #return [ vm for vm in self._VMs if eval("vm."+attr) == value ] #getattr(vm, attr)
        return [ vm for vm in self._VMs if getattr(vm, attr) == value ]

    @property
    def timezone(self):
        if self.tzCfg is None:
            # Then set it to default.  This may be a weird side effect
            self.tzCfg = TZConfig()
            
        return self.tzCfg.tz

    @property
    def tzCfg(self):
        return self._system.get("timezone", None)

    @tzCfg.setter
    def tzCfg(self, tzCfg):
        self._system["timezone"] = tzCfg

    @property
    def VMs(self):
        return self._VMs

    @property
    def product(self):
        return self._host.product

    @property
    def license(self):
        return self._host.license

    @property
    def dataStoreURL(self):
        return self._host.datastore.summary.url

    @property
    def hostIP(self):
        return self._host.ipaddr

    #@property
    #def processManager(self):
        #    return self._pm

    @property
    def dateTimeInfo(self):
        return self._host.dateTimeInfo

    @property
    def hostTZ(self):
        return self._host.dateTimeInfo.timeZone.name

    @property
    def hostName(self):
        return self._host.name

    @property
    def dateTime(self):
        return self._host.dateTime

    @property
    def bom(self):
        return self._bom

    def setHostDateTimeConfig(self, tz, ntp):
        self._host.UpdateDateTimeConfig(tz, ntp)

    def checkBuild(self, vm):
        return self._build == vm.getBuild(self._fm)

    def checkFiles(self, vm):
        return vm.checkFiles(self._fm)

    def stageFiles(self, vm):
        vm.stageFiles(self._fm)
                
    @property
    def license(self):
        return self._host.license
    
    @property
    def build(self):
        return self._build

    @property
    def gateway(self):
        gw = self._system.get("gateway", "")
        return gw

    @gateway.setter
    def gateway(self, gw):
        self._system["gateway"] = gw

    @property
    def netmask(self):
        return self._system.get("netmask", "")

    @netmask.setter
    def netmask(self, mask):
        self._system["netmask"] = mask

    @property
    def dns(self):
        #dns = []
        #dns.append(self._system.get("DNS_ALL_1", ""))
        #dns.append(self._system.get("DNS_ALL_2", ""))
        return self._system.get("dns", [])

    @dns.setter
    def dns(self, servers):
        # this should be a list
        self._system["dns"] = servers

    @property
    def ntp(self):
        #ntp = []
        #ntp.append(self._system.get("ESXI_NTPD_SERVER_1", ""))
        #ntp.append(self._system.get("ESXI_NTPD_SERVER_2", ""))
        #ntp.append(self._system.get("ESXI_NTPD_SERVER_3", ""))
        return self._system.get("ntp", [])

    @ntp.setter
    def ntp(self, servers):
        # this should be a list
        self._system["ntp"] = servers

    @property
    def system(self):
        return self._system

    def __repr__(self):
        return repr({ "system" : self._system, "VMs" : list(self._VMs.values()) })
    

class POCAdmin(object) :

    def __init__(self, username, password):
        self._user = username
        self._pwd = password
        self._poc = None
        
    def __enter__(self):
        class Config(POCConfig) :
        
            def __init__(self, username, password):
                self._si = SmartConnect(host='localhost',
                             user=username,
                             pwd=password,
                             #preferredApiVersions='vim.version.9',
                             port=443)

                super(Config, self).__init__(self._si)

                #self._VMs = []

                # Retrieve the host
                #self._host = HostConfig(self._si)
                # self._host.license = "25000-07H8J-58A49-03HUP-95L45"
                
                # Retrieve the processManager
                #self._pm = self._si.content.guestOperationsManager.processManager
                #self._fm = self._si.content.guestOperationsManager.fileManager

              
                # self._config = POCConfig(self._si)
                #self._loadConfig()
                self._hosts = None
                             
            def close(self):
                Disconnect(self._si)

            @property
            def si(self):
                return self._si

            #def _loadConfig(self):
                # import config from setupAppliance
                # self._config.glean()
                
    

                # merge the config with the VM info that might not exist in the config
                
                #for vm in self._VMs:
                    # vm.addNetCfg(net)
                    # self._config.addVM(vm)
                
            #def __repr__(self):
                #return repr(self._config)

            def _genHosts(self):
                # For all the VMs with IPs on VM Network create a hosts file to be deployed
                hosts = "hosts.poc"
                with open(hosts, 'w') as f:
                    f.write("#\n")
                    f.write("#Generated by POC setup\n")
                    f.write("#\n")
                    for vm in self.VMs:
                        hostname = vm.hostname
                        ips = vm.getIP("VM Network")
                        if hostname is not None and len(ips) > 0:
                            f.write("{0}\t{1}\n".format(hostname,ips[0]))
                    self._hosts = hosts
                    
            def deployHostsFile(self):
                if self._hosts is None:
                    self._genHosts()

                for vm in self.VMs:
                    try:
                        vm.deployHosts(self._hosts, self._fm)
                    except Exception as e:
                        print((e.message))

            def applyHosts(self, vm):
                for v in self.VMs:
                    hostname = v.hostname
                    ips = []
                    ncfg = v.getNet("VM Network")
                    if ncfg:
                        if not ncfg.dhcp:
                            ips = [ncfg.ipaddr]
                        else:
                            ips = v.getIP("VM Network")
                            
                    if hostname:
                        for ip in ips:
                            vm.addHost(hostname, ip, self._pm)


        self._poc = Config(self._user, self._pwd)
        return self._poc

    def __exit__(self, type, value, traceback):
        if self._poc is not None:
            self._poc.close()
            
        if type is not None: return False
        return self

    def __repr__(self):
        return repr(self._poc)
