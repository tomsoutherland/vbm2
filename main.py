#!/usr/bin/env python3

import re, sys, argparse, ipaddress, json, os, shlex, datetime, psutil, uuid
import xml.etree.ElementTree as ET
from configparser import RawConfigParser, ExtendedInterpolation
from subprocess import Popen, PIPE, STDOUT, call
from time import sleep
from glob import glob

# Global vars

#isodir=vbbasedir=vbdiskdir=vbheadless=vbheadlessargs=vrdeargs=vbmanage=socat=socatargs=''
#sleeptime=lockfoo=mac_over=natnetdns=vboxdata=lockfoo=uc=verbose=''
#uc = None
#verbose = False

def run_command(s, verbose=False):
    pipe = Popen(shlex.split(s), stdout=PIPE, stderr=STDOUT, encoding='utf-8')
    p = pipe.stdout.read()
    pipe.wait(20)
    if verbose:
        print(s, '\n', p)
    return pipe.returncode, p
def confirm_command(prompt=None, resp=False):
    if prompt is None:
        prompt = 'Confirm?'
    while True:
        ans = input(prompt)
        if not ans:
            return resp
        if ans not in ['y', 'Y', 'n', 'N']:
            print('please enter y or n.')
            continue
        if ans == 'y' or ans == 'Y':
            return True
        if ans == 'n' or ans == 'N':
            return False
class Unbound(object):
    def __init__(self):
        self.natnets = {}
        self.mac_dict = {}
        self.populate()
    run_command = staticmethod(run_command)
    def print_natnets(self):
        print('natnets', self.natnets)
    def is_ip_used(self, hostip):
        for m in self.mac_dict:
            if hostip in self.mac_dict[m].values():
                return True
        return False
    def resolv_conf(self):
        ns = []
        try:
            with open('/etc/resolv.conf', 'r') as resolvconf:
                for line in resolvconf.readlines():
                    match = re.search(r'^nameserver\s*(\d*\.\d*\.\d*\.\d*)', line)
                    if match:
                        ns.append(match.group(1))
        except:
            return []
        return ns
    def get_key_natnetdns(self, v):
        for nat, domain in natnetdns.items():
            if v == domain:
                return nat
        return None
    def init_lhosts(self):
        try:
            with open(os.path.join(vboxdata, "vbm-lhosts.xml").replace("\\","/"), 'r') as lhfoo:
                lhdata = json.load(lhfoo)
                lhfoo.close()
        except:
            lhdata = {}
        for k, v in mac_over.items():
            if re.search('DEADBEEF', k):
                p = v.split('.')
                hn = p.pop(0)
                dn = '.'.join(p)
                natnet = self.get_key_natnetdns(dn)
                if not k in lhdata:
                    print(natnetdns)
                    print(natnet)
                    self.unbound_ip(hn, k, natnet, None, None)
                    self.mac_dict[k].update({'netname': natnet})
                else:
                    self.mac_dict[k] = {}
                    if not lhdata[k].get('IP'):
                        self.unbound_ip(hn, k, natnet, None, None)
                        break
                    self.mac_dict[k].update({'netname': lhdata[k]['netname']})
                    self.mac_dict[k].update({'IP': lhdata[k]['IP']})
                    self.mac_dict[k].update({'name': hn})
        with open(os.path.join(vboxdata, "vbm-lhosts.xml").replace("\\","/"), 'w') as lhfoo:
            json.dump(self.mac_dict, lhfoo, indent=2)
            lhfoo.close()
    def populate(self):
        e, pipe = self.run_command(vbmanage + " list natnetworks", verbose)
        for line in pipe.splitlines():
            match = re.search(r'^NetworkName:\s+(\S*)', line)
            if match:
                n = match.group(1)
                self.natnets[n]={}
            match = re.search(r'^Network:\s+(\S*)', line)
            if match:
                self.natnets[n].update({'Network': match.group(1)})
            match = re.search(r'127.0.0.1=(\d*)', line)
            if match:
                self.natnets[n].update({'Loopback': match.group(1)})
        e, pipe = self.run_command(vbmanage + " list dhcpservers", verbose)
        for line in pipe.splitlines():
            match = re.search(r'NetworkName:\s+(\S.*)$', line)
            if match:
                netname = match.group(1)
            match = re.search(r' MAC (\S+)', line)
            if match:
                mac = re.sub('[.:-]', '', match.group(1).upper())
                self.mac_dict[mac]={}
                self.mac_dict[mac].update({'netname': netname})
            match = re.search(r'Fixed Address:\s+(\S+)', line)
            if match:
                self.mac_dict[mac].update({'IP': match.group(1)})
        for natnet in self.natnets.keys():
            tree = ET.parse(os.path.join(vboxdata, natnet + '-Dhcpd.leases').replace("\\","/"))
            root = tree.getroot()
            for lease in root.findall('Lease'):
                mac = ip = None
                if lease.get('state') == 'expired': continue
                mac = re.sub('[.:-]', '', lease.get('mac').upper())
                ip = lease.find('Address').get('value')
                if mac and ip:
                    if mac in self.mac_dict:
                        continue
                    else:
                        self.mac_dict[mac] = {}
                        self.mac_dict[mac].update({'IP': ip})
        e, pipe = self.run_command(vbmanage + " list -l vms", verbose)
        for line in pipe.splitlines():
            match = re.search(r'^Name:\s+(\S+)', line)
            if match: hname = match.group(1)
            match = re.search(r'MAC: (\S+),', line)
            if match:
                mac = match.group(1)
                if not mac in self.mac_dict:
                    self.mac_dict[mac] = {}
                if mac in mac_over:
                    self.mac_dict[mac].update({'name': mac_over[mac]})
                else:
                    self.mac_dict[mac].update({'name': hname})
        self.init_lhosts()
    def print_dicts(self):
        print('natnets', self.natnets, '\n\n', 'mac_dict', self.mac_dict, '\n\n', 'mac_over', mac_over)
        return
    def unbound_rm_ip(self, vm_name, vm_mac, vm_natnet, vm_nic, vm_uuid):
        s = vbmanage + ' dhcpserver modify --network=' + vm_natnet + ' --vm=' + vm_uuid + ' --nic=' + vm_nic +\
            ' --remove-config'
        self.run_command(s, verbose)
        self.mac_dict.pop(vm_mac, None)
        self.populate()
    def unbound_ip(self, vm_name, vm_mac, vm_natnet, vm_nic, vm_uuid):
        if vm_mac in self.mac_dict:
            if re.search('DEADBEEF', vm_mac): return
            if 'IP' in self.mac_dict[vm_mac]:
                ip = self.mac_dict[vm_mac]["IP"]
                if 'name' in self.mac_dict[vm_mac]:
                    hname = self.mac_dict[vm_mac]["name"]
                    s = vbmanage + ' dhcpserver modify --network=' + vm_natnet + ' --vm=' + vm_uuid + ' --nic=' + \
                        vm_nic + ' --set-opt=12 ' + hname + ' --fixed-address=' + ip
                    self.run_command(s, verbose)
                return
        else:
            self.mac_dict[vm_mac] = {}
            self.mac_dict[vm_mac].update({'name': vm_name})
            self.mac_dict[vm_mac].update({'netname': vm_natnet})
        if vm_natnet in self.natnets:
            dhcpnet = ipaddress.ip_network(self.natnets[vm_natnet]['Network'])
            for hostip in dhcpnet.hosts():
                break_flag = False
                hostip = str(hostip)
                if re.search('\.\d$', hostip): continue
                if self.is_ip_used(hostip): continue
                print(f"Found IP {hostip} for {vm_name}")
                self.mac_dict[vm_mac].update({'IP': hostip})
                if re.search('DEADBEEF', vm_mac): return
                s = vbmanage + ' dhcpserver modify --network=' + vm_natnet + ' --vm=' + vm_uuid + ' --nic=' + vm_nic +\
                        ' --set-opt=12 ' + vm_name + ' --fixed-address=' + hostip
                self.run_command(s, verbose)
                self.populate()
                return

    def unbound_control(self):
        verbose = False
        self.run_command(uc + " reload", verbose)
        for ns in self.resolv_conf():
            self.run_command(uc + " forward " + ns, verbose)
        for natnet in self.natnets.keys():
            if natnet in natnetdns:
                dnsdom = natnetdns[natnet]
            else:
                continue
            if not re.search('\S+\.$', dnsdom):
                dnsdom = dnsdom + '.'
            nsname = "ns-" + re.sub('[.: ]', '', natnet) + '.' + dnsdom
            self.run_command(uc + " local_zone " + dnsdom + " typetransparent", verbose)
            self.run_command(uc + " local_data " + dnsdom + " 10800 IN SOA " + nsname + \
                             " nobody.invalid. 1 3600 1200 604800 10800", verbose)
            self.run_command(uc + " local_data " + dnsdom + " IN NS " + nsname, verbose)
            ipnet = ipaddress.ip_network(self.natnets[natnet]['Network'])
            ns = (str(ipaddress.ip_address(int(ipnet.network_address) + int((self.natnets[natnet]['Loopback'])))))
            print(ns)
            self.run_command(uc + " local_data " + nsname + " IN A " + ns, verbose)
            s = uc + " local_data " + ipaddress.ip_address(ns).reverse_pointer + ". IN PTR " + nsname
            self.run_command(s, verbose)
            for m in self.mac_dict.keys():
                try:
                    if self.mac_dict[m]["netname"] != natnet: continue
                except:
                    continue
                host = self.mac_dict[m]['name'] + '.' + dnsdom
                if 'IP' in self.mac_dict[m]:
                    ip = self.mac_dict[m]['IP']
                    self.run_command(uc + ' local_data ' + host + ' IN A ' + ip, verbose)
                    s = uc + ' local_data ' + ipaddress.ip_address(ip).reverse_pointer + '. IN PTR ' + host
                    self.run_command(s, verbose)
            self.run_command(vbmanage + " dhcpserver modify --network=" + natnet + " --set-opt=6 " + ns, verbose)
            self.run_command(
                vbmanage + " dhcpserver modify --network=" + natnet + " --set-opt=15 " + dnsdom.rstrip('\.'), verbose)
            self.run_command(vbmanage + " dhcpserver restart --network=" + natnet, verbose)
        return
class VM(object):
    def __init__(self, name):
        self.name = name
        self.uuid = ''
        self.conf = {}
        self.VMParms = ["ostype", "memory", "cpus", "VMState", "VMStateChangeTime", "storagecontroller.*", "UUID",
                        "boot\d", "\S+\-\d+\-\d+", "nic.*", "uart.*", "macaddress\d",
                        "firmware", "graphicscontroller", "vram", "nestedpaging", "\S+ImageUUID\S+", "\S+IsEjected\S+"]
        self.populate()
    run_command = staticmethod(run_command)
    confirm_command = staticmethod(confirm_command)
    def get_mac_addr(self, nicn):
        try:
            mac = self.conf['macaddress' + nicn]
        except:
            mac = '0123456789AB'
        mac = ":".join(["%s" % (mac[i:i + 2]) for i in range(0, 12, 2)])
        nmac = ' '
        while not re.match("[0-9A-F]{2}([-:]?)[0-9A-F]{2}(\\1[0-9A-F]{2}){4}$", nmac.upper()):
            nmac = input("Enter MAC (" + mac + ") ")
            if nmac == "":
                nmac = mac
        nmac = re.sub('[.:-]', '', nmac).upper()
        if nmac == '0123456789AB':
            return 'auto'
        return nmac
    def toggle_nested_paging(self):
        if not confirm_command('Toggle nestedpaging?'):
            return
        if self.conf["nestedpaging"] == "on":
            print("Turning nested paging off")
            s = vbmanage + " modifyvm " + self.uuid + " --nestedpaging off"
        else:
            print("Turning nested paging on")
            s = vbmanage + " modifyvm " + self.uuid + " --nestedpaging on"
        e, pipe = run_command(s, verbose)
        if e:
            sys.exit("Failed to run command: " + s + '\n' + pipe)
        self.populate()
        return
    def remove_hba(self, hba):
        for k, v in self.conf.copy().items():
            if re.search(hba + '-ImageUUID', k):
                self.disk_detach(v, True)
        s = f"{vbmanage} storagectl {self.uuid} --name {hba} --remove"
        e, pipe = run_command(s, verbose)
        if e:
            sys.exit("Failed to run command: " + s + '\n' + pipe)
        self.populate()
        return
    def clone_vm(self, newvm):
        s = vbmanage + " clonevm " + self.uuid + " --basefolder=\"%s\""%vbbasedir + " --name=%s"%newvm + " --register"
        e, pipe = self.run_command(s, verbose)
        if e:
            sys.exit("Failed to run command: " + s + '\n' + pipe)
        return
    def display(self):
        print('Name  -> ', self.name)
        nicf = ['Attachment', 'Cable', 'Type']
        for k, v in self.conf.items():
            if v == 'none':
                continue
            print(k, ' -> ', v)
    def populate(self):
        self.conf = {}
        #self.conf["nestedpaging"] = ""
        s = vbmanage + " showvminfo --machinereadable " + self.name
        e, pipe = self.run_command(s, False)
        if e:
            sys.exit("Failed to run command: " + s + '\n' + pipe)
        for line in pipe.splitlines():
            if re.search('=', line):
                [k, v] = line.strip().replace('"','').split("=", 1)
                #print(k,v)
                #if v == 'disabled' or v == 'none':
                #    continue
                for r in self.VMParms:
                    if re.search(r, k):
                        if k == "UUID": self.uuid = v
                        self.conf.update({k: v})
        #exit(1)
    def check_console(self, port):
        for conn in psutil.net_connections('tcp4'):
            if conn.status == 'ESTABLISHED':
                if str(conn.raddr.port) == port:
                    return(str(conn.pid))
        return("0")
    def find_open_port(self, startport):
        conns = psutil.net_connections('tcp4')
        for i in range(startport, startport + 100, 1):
            inuse = 0
            for conn in conns:
                if conn.laddr.port == i:
                    inuse = 1
                    break
            if inuse == 0:
                return(i)
        return("0")
    def boot_vm(self, vrde):
        if uc:
            U = Unbound()
            for k, v in self.conf.items():
                match = re.search(r'NIC (\d*)', k)
                if match:
                    vm_nic = match.group(1)
                    match = re.search(r'MAC:(\S+), .* \'([\S\-]+)\',', v)
                    if match:
                        U.unbound_ip(self.name, match.group(1), match.group(2), vm_nic, self.uuid)
        if re.search(r'poweroff', self.conf["VMState"]):
            p = self.find_open_port(2021)
            if p == 0:
                sys.exit("Failed to find available TCP port\n")
            s = vbmanage + " modifyvm " + self.uuid + " --uartmode1 tcpserver " + str(p)
            e, pipe = run_command(s, verbose)
            if e:
                print("Failed to run: ", s, '\n', pipe)
                return
            s = vbmanage + " modifyvm " + self.uuid + " --uart1 0x3f8 4"
            e, pipe = run_command(s, verbose)
            if e:
                print("Failed to run: ", s, '\n', pipe)
                return
            print("booting " + self.name)
            if vrde:
                vargs = vrdeargs.split(' ')
            else:
                vargs = vbheadlessargs.split(' ')
            pipe = Popen([vbheadless] + vargs + ["-s", self.uuid], close_fds=True, shell=False)
            if pipe.returncode:
                print("Failed to run: " + [vbheadless] + vargs + ["-s", self.uuid])
                return
            if uc:
                print("Updating Unbound")
                U.unbound_control()
            sleep(sleeptime)
        self.populate()
        match = re.search(r'\,(\d+)', self.conf["uartmode1"])
        if match:
            p = match.group(1)
            inuse = self.check_console(p)
            if inuse != "0":
                sys.exit("Console in use by PID " + inuse + "\n")
            p = "tcp:127.0.0.1:" + p
            print("\033]0;%s\007" % (self.name), end=None)
            call(["socat", socatargs, p])
        else:
            sys.exit("No network port to connect.\n")
    def nmi(self):
        s = vbmanage + " debugvm " + self.uuid + " injectnmi"
        e, pipe = run_command(s, verbose)
        if e:
            print("Failed to run: ", s, '\n', pipe)
            return
        return
    def poweroff(self):
        s = vbmanage + " controlvm " + self.uuid + " poweroff"
        e, pipe = run_command(s, False)
        if e:
            print("Failed to run: ", s, '\n', pipe)
            return
        return
    def delete_vm(self):
        if not confirm_command(f'Delete {self.name} and attached disks?'):
            return
        if uc:
            U = Unbound()
            for k, v in self.conf.items():
                match = re.search(r'NIC (\d*)', k)
                if match:
                    vm_nic = match.group(1)
                match = re.search(r'MAC:(\S+), .* \'([\S\-]+)\',', v)
                if match:
                    U.unbound_rm_ip(self.name, match.group(1), match.group(2), vm_nic, self.uuid)
            U.unbound_control()
        s = vbmanage + " unregistervm " + self.uuid + " --delete"
        e, pipe = run_command(s, verbose)
        if e:
            print("Failed to run: ", s, '\n', pipe)
            return
        return
    def ejectdvd(self):
        for k, v in self.conf.copy().items():
            match = re.search(r'(^\S+)-IsEjected-(\S+$)', k)
            if match:
                if self.conf[match.group(1) + '-' + match.group(2)] == 'emptydrive':
                    print('DVD drive empty ' + match.group(1) + '-' + match.group(2))
                else:
                    dvd = self.conf[match.group(1) + '-ImageUUID-' + match.group(2)]
                    self.disk_detach(dvd, False)
                    return
        return
    def insertdvd(self, dvd):
        for k, v in self.conf.copy().items():
            match = re.search(r'(^\S+)-IsEjected-(\S+$)', k)
            if match:
                if self.conf[match.group(1) + '-' + match.group(2)] == 'emptydrive':
                    self.disk_attach(match.group(1), dvd, 'dvddrive')
                    return
                else:
                    print('DVD drive not empty: ' + match.group(1) + '-' + match.group(2))
        return
    def disk_attach(self, hba, foo, dtype):
        print(f'attaching {foo} to {hba} on {self.name}')
        maxports = {"SCSI": "16", "SATA": "30", "SAS": "255", "IDE": "2"}
        needscontroller = 1
        for k, v in self.conf.items():
            if v == hba:
                needscontroller = 0
                match = re.search(r'storagecontrollername(\d)', k)
                if match:
                    cpc = self.conf['storagecontrollerportcount' + match.group(1)]
                    if cpc != maxports[hba]:
                        print(f'changing port count from {cpc} to {maxports[hba]} for {hba}')
                        s = f"{vbmanage} storagectl {self.uuid} --name {hba} --portcount {maxports[hba]}"
                        e, pipe = run_command(s, False)
                        if e:
                            sys.exit("Failed to run command: " + s + '\n' + pipe)
                        self.populate()
            if re.search(foo, v):
                print("Already attached: " + k + " " + v)
                return
        if needscontroller:
            print("Adding " + hba + " to " + self.name)
            s = f"{vbmanage} storagectl {self.name} --add {hba.lower()} --name {hba} --portcount {maxports[hba]}"
            e, pipe = run_command(s, False)
            if e:
                sys.exit("Failed to run command: " + s + '\n' + pipe)
            self.populate()
        for k, v in self.conf.items():
            if re.search(hba, k) and v == 'emptydrive' and dtype == 'dvddrive':
                c, p, x = k.split('-')
                if c == "IDE":
                    s = f"{vbmanage} storageattach {self.uuid} --storagectl {c} --port {p} --device {x} " + \
                        f"--type {dtype} --medium \"{foo}\""
                else:
                    s = f"{vbmanage} storageattach {self.uuid} --storagectl {c} --port {p} " + \
                        f"--type {dtype} --medium \"{foo}\""
                e, pipe = run_command(s, False)
                if e:
                    sys.exit("Failed to run command: " + s + '\n' + pipe)
                self.populate()
                return
        for k, v in self.conf.items():
            if re.search(hba, k) and v == 'none':
                c, p, x = k.split('-')
                if c == "IDE":
                    s = f"{vbmanage} storageattach {self.uuid} --storagectl {c} --port {p} --device {x} " + \
                        f"--type {dtype} --medium \"{foo}\""
                else:
                    s = f"{vbmanage} storageattach {self.uuid} --storagectl {c} --port {p} " + \
                        f"--type {dtype} --medium \"{foo}\""
                e, pipe = run_command(s, False)
                if e:
                    sys.exit("Failed to run command: " + s + '\n' + pipe)
                self.populate()
                return
        sys.exit("Unable to attach disk")
    def disk_detach(self, foo, isdisk):
        print(f'detaching {foo} from {self.name}')
        if isdisk:
            m = "none"
        else:
            m = "emptydrive"
        foo = re.escape(foo)
        for K, v in self.conf.items():
            if re.search(foo, v):
                if re.search('UUID', K):
                    c, u, p, x = K.split('-')
                else:
                    c, p, x = K.split('-')
                if c == "IDE":
                    s = f"{vbmanage} storageattach {self.uuid} --storagectl {c} --port {p} --device {x} --medium {m}"
                else:
                    s = f"{vbmanage} storageattach {self.uuid} --storagectl {c} --port {p} --medium {m}"
                e, pipe = run_command(s, False)
                if e:
                    sys.exit("Failed to run command: " + s + '\n' + pipe)
                self.conf.pop(K, None)
                break
        return
    def set_vm_os(self, ostype):
        s = f"{vbmanage} modifyvm {self.uuid} --ostype {ostype}"
        e, pipe = run_command(s, False)
        if e:
            print("Failed to run: ", s, '\n', pipe)
            return
        return
    def set_vm_memory(self, mem):
        match = re.search(r'(^\d*)([MG])', mem)
        if not match:
            print("Error: Invalid memory: ", mem)
            return
        if match.group(2) == "G":
            mem = str(int(match.group(1)) * 1024)
        else:
            mem = match.group(1)
        s = f"{vbmanage} modifyvm {self.uuid} --memory {mem}"
        e, pipe = run_command(s, False)
        if e:
            print("Failed to run: ", s, '\n', pipe)
            return
        return
    def set_vm_cpus(self, cpus):
        s = f"{vbmanage} modifyvm {self.uuid} --cpus {str(cpus)}"
        e, pipe = run_command(s, False)
        if e:
            print("Failed to run: ", s, '\n', pipe)
            return
        return
class DVDs(object):
    def __init__(self):
        self.dvds = {}
        self.populate()
        self.sync_config()
    run_command = staticmethod(run_command)
    def populate(self):
        s = f"{vbmanage} list -l dvds"
        e, pipe = run_command(s, False)
        if e:
            sys.exit("Failed to run command: " + s + '\n' + pipe)
        for line in pipe.splitlines():
            match = re.search(r'^UUID:\s+(\S+)$', line)
            if match:
                uuid = match.group(1)
                self.dvds[uuid] = {}
                self.dvds[uuid]["In use by VMs"] = []
                continue
            match = re.search(r'(^\S[a-zA-Z0-9 ]+):\s*(\S.*)$', line)
            if match:
                if match.group(1) == "In use by VMs":
                    s = re.split(' ', match.group(2))
                    self.dvds[uuid]["In use by VMs"].append(s[0])
                else:
                    self.dvds[uuid].update({match.group(1): match.group(2)})
                continue
            match = re.search(r'^\s+(\S+) \(UUID', line)
            if match:
                self.dvds[uuid]["In use by VMs"].append(match.group(1))
                continue
        self.sorted_dict = {}
        self.sorted_keys = sorted(self.dvds, key=lambda x: (self.dvds[x]["Location"]))
        for k in self.sorted_keys:
            self.sorted_dict[k] = self.dvds[k]
        self.dvds = self.sorted_dict
        return
    def sync_config(self):
        self.isos = glob(os.path.join(isodir, "*.iso").replace("\\","/"))
        for K in self.dvds.copy().keys():
            if not os.path.isfile(self.dvds[K]["Location"]):
                print("Unregister", K, self.dvds[K]["Location"])
                self.dvds.pop(K, None)
                s = f"{vbmanage} closemedium dvd {K}"
                e, pipe = run_command(s, verbose)
                if e:
                    sys.exit("Failed to run command: " + s + '\n' + pipe)
                continue
            if self.dvds[K]["Location"] in self.isos:
                self.isos.remove(self.dvds[K]["Location"])
        for d in self.isos:
            print("Register", d)
            s = f"{vbmanage} modifymedium dvd \"{d}\" --type readonly --setlocation \"{d}\""
            e, pipe = run_command(s, verbose)
            if e:
                sys.exit("Failed to run command: " + s + '\n' + pipe)
        self.populate()

    def print_all(self):
        for K in self.dvds.keys():
            print('\n' + K)
            for k, v in self.dvds[K].items():
                print(k,v)
    def show_attachable_dvds(self, vm):
        for K in self.dvds.keys():
            if not vm in self.dvds[K]["In use by VMs"]:
                print(K, self.dvds[K]["Location"], self.dvds[K]["In use by VMs"])
class Disks(object):
    def __init__(self):
        self.disks = {}
        self.populate()
    run_command = staticmethod(run_command)
    confirm_command = staticmethod(confirm_command)
    def populate(self):
        self.disks = {}
        s = f"{vbmanage} list -l hdds"
        e, pipe = run_command(s, False)
        if e:
            sys.exit("Failed to run command: " + s + '\n' + pipe)
        for line in pipe.splitlines():
            match = re.search(r'^UUID:\s+(\S+)$', line)
            if match:
                uuid = match.group(1)
                self.disks[uuid] = {}
                self.disks[uuid]["In use by VMs"] = []
                continue
            match = re.search(r'(^\S[a-zA-Z0-9 ]+):\s*(\S.*)$', line)
            if match:
                if match.group(1) == "In use by VMs":
                    s = re.split(' ', match.group(2))
                    self.disks[uuid]["In use by VMs"].append(s[0])
                else:
                    self.disks[uuid].update({match.group(1): match.group(2)})
                continue
            match = re.search(r'^\s+(\S+) \(UUID', line)
            if match:
                self.disks[uuid]["In use by VMs"].append(match.group(1))
                continue
        return
    def print_all(self):
        for K in self.disks.keys():
            print('\n' + K)
            for k, v in self.disks[K].items():
                print(k,v)
    def show_attachable_disks(self, vm):
        for K in self.disks.keys():
            if (self.disks[K]["Type"] == "shareable" and not vm in self.disks[K]["In use by VMs"]) or \
                    len(self.disks[K]["In use by VMs"]) == 0:
                print(K, self.disks[K]["Location"], self.disks[K]["In use by VMs"])
    def purge_orphans(self):
        for K in self.disks.copy().keys():
            if len(self.disks[K]["In use by VMs"]) == 0:
                print("Purge", self.disks[K]["Location"])
                s = f"{vbmanage} closemedium disk {K} --delete"
                e, pipe = run_command(s, verbose)
                if e:
                    print("Error running command:", s, "\n", pipe)
                self.disks.pop(K, None)
        foos = glob(os.path.join(vbbasedir, "*/*.vdi").replace("\\","/"))
        for foo in foos:
            if os.path.isfile(foo):
                purge = 1
                for K in self.disks.copy().keys():
                    if self.disks[K]["Location"] == foo:
                        purge = 0
                        break
                if purge:
                    try:
                        print("Removed orphaned disk", foo)
                        os.remove(foo)
                    except OSError as e:
                        print("Encountered error removing:", foo, "\nOS Error: ", e.strerror)
def get_int(user_prompt):
    user_input = input(user_prompt)
    try:
        tmp = int(user_input)
    except:
        print(user_input, "is not a number.")
        return -1
    return tmp
def vm_select_os():
    oslist = {}
    i = 1
    print("\n=============== Select OS ==============\n")
    pipe = Popen([vbmanage, "list", "-s", "ostypes"], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
    for line in pipe.stdout:
        match = re.search(r'^ID:\s+(\S+)', line.rstrip())
        if match:
            oslist.update({i: match.group(1)})
            i += 1
    i = 0
    for k, v in oslist.items():
        print(f'{k:<3} {v:<20}', end="   ")
        i += 1
        if i == 4:
            i = 0
            print("")
    user_input = get_int("\nSelct OS: ")
    return oslist[user_input]
def init_config_vars():
    ppath = (os.path.dirname(os.path.realpath(__file__)))
    config = RawConfigParser(interpolation=ExtendedInterpolation())
    config.optionxform = lambda option: option
    try:
        config.read_file(open(os.path.join(ppath, 'vbm.ini').replace("\\","/"), 'rt', encoding='utf-8'))
    except:
        print('Unable to read configuration file, vbm.ini')
        return
    mac_over = {}
    natnetdns = {}
    global isodir
    global vbbasedir
    global vbdiskdir
    global vbdiskdir
    global vbheadless
    global vbheadlessargs
    global vrdeargs
    global vbmanage
    global socat
    global socatargs
    global sleeptime
    global lockfoo
    global vboxdata
    global uc
    uc=None
    for key, val in config.items('vbm'):
        if key == 'isodir': isodir = config['vbm']['isodir']
        if key == 'vbbasedir': vbbasedir = config['vbm']['vbbasedir']
        if key == 'vbdiskdir': vbdiskdir = config['vbm']['vbdiskdir']
        if key == 'vbheadless': vbheadless = config['vbm']['vbheadless']
        if key == 'vbheadlessargs': vbheadlessargs = config['vbm']['vbheadlessargs']
        if key == 'vrdeargs': vrdeargs = config['vbm']['vrdeargs']
        if key == 'vbmanage': vbmanage = config['vbm']['vbmanage']
        if key == 'socat': socat = config['vbm']['socat']
        if key == 'socatargs': socatargs = config['vbm']['socatargs']
        if key == 'sleeptime': sleeptime = int(config['vbm']['sleeptime'])
        if key == 'lockfoo': lockfoo = config['vbm']['lockfoo']
        if key == 'vboxdata': vboxdata = config['vbm']['vboxdata']
        if key == 'uc': uc = config['vbm']['uc']
    for key, val in config.items('name_overrides'):
        mac_over.update({key.upper(): val})
    for key, val in config.items('logical_hosts'):
        mac_over.update({key.upper(): val})
    for key, val in config.items('natnetdns'):
        natnetdns.update({key: val})
    return 0
def ask_confirm(prompt):
    user_input = '-'
    while user_input != 'Y' or user_input != 'N':
        user_input = input(prompt).upper()
        if user_input == 'Y':
            return True
        elif user_input == 'N':
            return False
        else:
            print("\nPlease respond (Y or N)\n")
def list_vms(verbose):
    vms = {}
    l = 0
    s = vbmanage + " list -s -l vms"
    e, p = run_command(s, verbose)
    if e:
        print("Error running:", s)
        return e
    for vm in p.splitlines():
        match = re.search(r'^Name:\s+([a-zA-Z0-9\-]+)$', vm)
        if match:
            vm_name = match.group(1)
            vms[vm_name] = {}
            if l < len(vm_name): l = len(vm_name)
        match = re.search(r"State:\s+(\S.*\(.........................)", vm)
        if match:
            vms[vm_name].update({'State': match.group(1) + ')'})
        match = re.search(r"Guest OS:\s+(\S.*)$", vm)
        if match:
            vms[vm_name].update({'OS': match.group(1)})
    for vm in list(vms):
        if "State" in vms[vm]:
            print('{:<{l}}'.format(vm, l=l), vms[vm]['State'], vms[vm]['OS'])
        else:
            del vms[vm]
def vbox_sync_config():
        foodict = {}
        vbdict = {}
        pipe = Popen([vbmanage, "list", "-s", "vms"], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
        for line in pipe.stdout:
            match = re.search(r'\"(.*)\"\s{(.*)}', line.rstrip())
            if match:
                vbdict.update({match.group(2): match.group(1)})
        foos = glob(os.path.join(vbbasedir, "*/*.vbox").replace("\\","/"))
        for foo in foos:
            f = open(foo)
            for line in f:
                match = re.search(r'Machine uuid="{(\S+)}" name="([A-Za-z0-9 \-]+)"', line)
                if match:
                    foodict.update({match.group(1): foo})
                    f.close
                    break
        for k, v in vbdict.copy().items():
            if v == "<inaccessible>":
                print("Unregistering ", k, v)
                Popen([vbmanage, "unregistervm", k], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
                del vbdict[k]
        for k, v in foodict.items():
            if not k in vbdict:
                print("Registering ", k, v)
                pipe = Popen([vbmanage, "registervm", v], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
                print(pipe.stdout.read())
        return
def vm_select_nictype():
    nictypes = {1: "none", 2: "null", 3: "nat", 4: "bridged", 5: "intnet", 6: "hostonly", 7: "generic", 8: "natnetwork"}
    i = 0
    for k, v in nictypes.items():
        print(f'{k:<2} {v:<10}', end="   ")
        i += 1
        if i == 4:
            i = 0
            print("")
    user_input = get_int("\nSelect NIC Type: ")
    return nictypes[user_input]
def create_and_attach_disks(n_disks, disk_size, hba, vm_list):
    VMs = {}
    for v in vm_list:
        Vm = VM(v)
        VMs.update({v:Vm})
    if len(vm_list) > 1:
        shared = 1
        ddir = vbdiskdir
    else:
        shared = 0
        ddir = os.path.join(vbbasedir, v).replace("\\","/")
    dsize = 0
    match = re.search(r"(\d*)G", disk_size)
    if match:
        dsize = int(match.group(1)) * 1024
    match = re.search(r"(\d*)M", disk_size)
    if match:
        dsize = int(match.group(1))
    if not dsize: sys.exit("Invalid disk size: " + disk_size)
    while n_disks > 0:
        diskname = str(uuid.uuid4())
        if shared:
            foo = os.path.join(ddir, 'shared_' + diskname + '.vdi')
            s = f"{vbmanage} createmedium disk --filename \"{foo}\" --size {str(dsize)} --variant Fixed"
            e, pipe = run_command(s, verbose)
            if e:
                sys.exit("Failed to run command: " + s + '\n' + pipe)
            s = f"{vbmanage} modifymedium disk \"{foo}\" --type shareable"
            e, pipe = run_command(s, verbose)
            if e:
                sys.exit("Failed to run command: " + s + '\n' + pipe)
        else:
            foo = os.path.join(ddir, v + '_' + diskname + '.vdi')
            s = f"{vbmanage} createmedium disk --filename \"{foo}\" --size {str(dsize)} --variant Standard"
            e, pipe = run_command(s, verbose)
            if e:
                sys.exit("Failed to run command: " + s + '\n' + pipe)
        for vm_name, Vm in VMs.items():
            Vm.disk_attach(hba, foo, 'hdd')
        n_disks -= 1
def vm_select_nicnet(iftype):
    nicnets = {}
    nicips = {}
    i = 1
    pipe = Popen([vbmanage, "list", "-s", iftype], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
    for line in pipe.stdout:
        match = re.search(r'(^\S+):\s+(\S+)', line.rstrip())
        if match:
            if match.group(1) == "Name" or match.group(1) == "NetworkName":
                v = match.group(2)
                v = re.sub(r':.*', '', v)
                nicnets.update({i: v})
            elif match.group(1) == "IPAddress" or match.group(1) == "IP":
                nicips.update({i: match.group(2).rstrip()})
                i += 1
    for k, v in nicnets.items():
        y = nicips[k]
        print(f'{k:<3} {v:<10} {y:<15}')
    user_input = get_int("\nSelct Interface: ")
    return nicnets[user_input]
def vm_set_border(Vm):
    border = []
    bmenu = ['none', 'floppy', 'dvd', 'disk', 'net']
    j = 0
    while len(border) < 4:
        i = 0
        while i < len(bmenu):
            print("(", i, ")", bmenu[i])
            i += 1
        user_input = get_int("Enter Boot Device " + str(j) + " : ")
        border.append(bmenu[user_input])
        j += 1
    print("\nSetting Boot Order to ", border)
    j = 0
    while j < 4:
        s = f"{vbmanage} modifyvm {Vm.uuid} --boot{str(j + 1)} {border[j]}"
        e, pipe = run_command(s, verbose)
        if e:
            print("Failed to run command:", s, "\n", pipe)
        j += 1
    return
def edit_vm(vm):
    Vm = VM(vm)
    cs = {1: "IDE", 2: "SATA", 3: "SCSI", 4: "SAS"}
    user_input = ''
    while user_input != "Q":
        Vm.populate()
        Vm.display()
        print("\n"
              "(O) OS  (N) NICs  (C) CPUs  (M) Memory  (D) Delete Storage Controller\n"
              "(B) Boot Order  (G) Video  (F) Firmware Type  (P) Force NMI      (Q) Return to Previous Menu")
        user_input = input("\nCommand Me: ").upper()
        if user_input == "D":
            user_input = get_int("Delete  (1) IDE  (2) SATA  (3) SCSI  (4) SAS ")
            if user_input and user_input < 5 and ask_confirm('Delete Controller ' + cs[user_input] + ' ? '):
                Vm.remove_hba(cs[user_input])
        elif user_input == "B":
            vm_set_border(Vm)
        elif user_input == "M":
            user_input = input("Memory [ Xm | Xg ]?: ").upper()
            Vm.set_vm_memory(user_input)
        elif user_input == "C":
            user_input = get_int("CPUs?: ")
            Vm.set_vm_cpus(user_input)
        elif user_input == "O":
            Vm.set_vm_os(vm_select_os())
        elif user_input == "N":
            N = input("NIC Number? ")
            nicmodels = {1: 'Am79C970A', 2: 'Am79C973', 3: 'Am79C960', 4: '82540EM', 5: '82543GC', 6: '82545EM',
                         7: 'virtio'}
            nicmodel = get_int("NIC Model " + str(nicmodels) + " ? ")
            nicm = nicmodels[nicmodel]
            nictype = vm_select_nictype()
            mac = Vm.get_mac_addr(N)
            if nictype == "bridged":
                nicnet = vm_select_nicnet("bridgedifs")
                s = f"{vbmanage} modifyvm {Vm.uuid} --nic{N} {nictype} --bridgeadapter{N} {nicnet} --nictype{N} " + \
                    f"{nicm} --macaddress{N} {mac}"
            elif nictype == "hostonly":
                nicnet = vm_select_nicnet("hostonlyifs")
                s = f"{vbmanage} modifyvm {Vm.uuid} --nic{N} {nictype} --hostonlyadapter{N} {nicnet} --nictype{N} " + \
                    f"{nicm} --macaddress{N} {mac}"
            elif nictype == "natnetwork":
                nicnet = vm_select_nicnet("natnets")
                s = f"{vbmanage} modifyvm {Vm.uuid} --nic{N} {nictype} --nat-network{N} {nicnet} --nictype{N} " + \
                    f"{nicm} --macaddress{N} {mac}"
            elif nictype == "nat":
                nicnet = vm_select_nicnet("natnets")
                s = f"{vbmanage} modifyvm {Vm.uuid} --nic{N} {nictype} --natnet{N} {nicnet} --nictype{N} " + \
                    f"{nicm} --macaddress{N} {mac}"
            elif nictype == "none":
                s = f"{vbmanage} modifyvm {Vm.uuid} --nic{N} {nictype} --macaddress{N} {mac}"
            e, pipe = run_command(s, verbose)
            if e:
                print("Error running command:", s, '\n', pipe)
        elif user_input == "F":
            fopts = {1: "bios", 2: "efi", 3: "efi32", 4: "efi64"}
            for k, v in fopts.items():
                print(str(k), v, end="  ")
            user_input = get_int("\n\nSelect Firmware Type: ")
            if fopts[user_input]:
                s = f"{vbmanage} modifyvm {Vm.uuid} --firmware {fopts[user_input]}"
                e, pipe = run_command(s, verbose)
                if e:
                    print("Error running command:", s, "\n", pipe)
        elif user_input == "G":
            vopts = {1: "none", 2: "vboxvga", 3: "vmsvga", 4: "vboxsvga"}
            for k, v in vopts.items():
                print(str(k), v, end="  ")
            user_input = get_int("\n\nSelect Graphics Type: ")
            if vopts[user_input]:
                s = f"{vbmanage} modifyvm {Vm.uuid} --graphicscontroller {vopts[user_input]}"
                e, pipe = run_command(s, verbose)
                if e:
                    print("Error running command:", s, "\n", pipe)
            user_input = get_int("\n\nSelect Graphics Memory (MB): ")
            if user_input != -1:
                s = f"{vbmanage} modifyvm {Vm.uuid} --vram {str(user_input)}"
                e, pipe = run_command(s, verbose)
                if e:
                    print("Error running command:", s, "\n", pipe)
        elif user_input == "P":
            Vm.nmi()

def create_vm(vm_name):
    ostype = vm_select_os()
    s = f"{vbmanage} createvm --name {vm_name} --ostype {ostype} --basefolder \"{vbbasedir}\" --register --default"
    e, pipe = run_command(s, verbose)
    if e:
        print("Error running command:", s, "\n", pipe)
    return
def main():
    global verbose
    verbose=False
    init_config_vars()
    parser = argparse.ArgumentParser(description='Manage your VirtualBox VMs.')
    parser.add_argument('-l', action='store_true', help='List the VirtualBox VMs.')
    parser.add_argument('-s', type=str, help='Show configuration of VM', metavar='VM')
    parser.add_argument('-p', type=str, help='Power Off VM', metavar='VM')
    parser.add_argument('-n', type=str, help='Toggle Nested Paging', metavar='VM')
    parser.add_argument('-e', type=str, help='Edit VM', metavar='VM')
    parser.add_argument('-d', type=str, help='Delete VM', metavar='VM')
    parser.add_argument('-r', action='store_true', help='Sync on disk config with VirtualBox')
    parser.add_argument('-u', action='store_true', help='Update unbound DNS')
    parser.add_argument('-v', action='store_true', help='Verbose mode showing command results')
    parser.add_argument('--nmi', type=str, help='Causes an NMI to be injected into the VM.', metavar='VM')
    parser.add_argument('--create', type=str, help='Create new VM', metavar="VM")
    parser.add_argument('--clone', nargs=2, help='Clone VM to CLONE', metavar=('VM', 'CLONE'))
    parser.add_argument('--adisks', type=str, help='List attachable disks for VM', metavar='VM')
    parser.add_argument('--advds', type=str, help='List attachable dvds for VM', metavar='VM')
    parser.add_argument('--orphans', action='store_true', help='Delete unattached disks (orphans)')

    boot = parser.add_argument_group('Boot a VM')
    boot.add_argument('-b', type=str, help='Boot VM or connect to VM console if already booted', metavar='VM')
    boot.add_argument('-g', action='store_true', default=False, help='Enable VRDE (' + vrdeargs + ')')

    cdrom = parser.add_argument_group('Insert or Eject a DVD')
    cdrom.add_argument('--eject', type=str, help='Eject DVD from VM', metavar='VM')
    cdrom.add_argument('--insert', type=str, help='Insert --dvd XX into VM', metavar='VM --dvd XX')

    disks = parser.add_argument_group('Create and Attach Disks')
    disks.add_argument('--disks', type=int, help='Create D Disks', metavar="D")
    disks.add_argument('--size', type=str, help='Disk Size in Gigabytes (g) or Megabytes (m)', metavar='[Sg|Sm]')
    v = disks.add_argument('--vms', type=str, nargs='+', help='List of VMs', metavar=('VMa', 'VMb'))
    c = disks.add_argument('--hba', type=str.lower, help='HBA Type (ide sata sas scsi)', choices=['ide', 'sata', 'sas', 'scsi'], metavar='TYPE')

    adisks = parser.add_argument_group('Attach DVD or Disk')
    d = adisks.add_argument('--disk', type=str, help='Disk UUID or Name to detach or attach', metavar="DISK")
    e = adisks.add_argument('--dvd', type=str, help='DVD UUID or Name to eject or insert', metavar="XX")
    adisks.add_argument('--attach', action='store_true', help='Attach disk or dvd')
    adisks._group_actions.append(v)
    adisks._group_actions.append(c)

    ddisks = parser.add_argument_group('Eject DVD or Detach Disk')
    ddisks._group_actions.append(d)
    ddisks._group_actions.append(e)
    ddisks.add_argument('--detach', action='store_true', help='Detach disk or dvd')
    ddisks._group_actions.append(v)

    results = parser.parse_args()

    if results.v:
        verbose = True

    if results.l:
        list_vms(results.v)
    elif results.create:
        create_vm(results.create)
    elif results.e:
        edit_vm(results.e)
    elif results.eject:
        Vm = VM(results.eject)
        Vm.ejectdvd()
    elif results.insert:
        Vm = VM(results.insert)
        Vm.insertdvd(results.dvd)
    elif results.nmi:
        Vm = VM(results.nmi)
        Vm.nmi()
    elif results.s:
        Vm = VM(results.s)
        Vm.display()
    elif results.b:
        Vm = VM(results.b)
        if results.g:
            Vm.boot_vm(True)
        else:
            Vm.boot_vm(False)
    elif results.n:
        Vm = VM(results.n)
        Vm.toggle_nested_paging()
    elif results.p:
        Vm = VM(results.p)
        Vm.poweroff()
    elif results.e:
        Vm = VM(results.e)
        edit_vm(Vm)
    elif results.d:
        Vm = VM(results.d)
        Vm.delete_vm()
    elif results.r:
        vbox_sync_config()
    elif results.u:
        if uc:
            U = Unbound()
            U.unbound_control()
            U.print_natnets()
        else:
            ppath = (dirname(realpath(__file__)))
            print('Check configuration: ', os.path.join(ppath, 'vbm.ini')).replace("\\","/")
            print('unbound is not configured.')
    elif results.clone:
        Vm = VM(results.clone[0])
        Vm.clone_vm(results.clone[1])
    elif results.disks and results.size and results.vms and results.hba:
        create_and_attach_disks(results.disks, results.size.upper(), results.hba.upper(), results.vms)
    elif results.disk and results.vms and results.detach:
        for vm in results.vms:
            Vm = VM(vm)
            Vm.disk_detach(results.disk, True)
    elif results.dvd and results.vms and results.detach:
        for vm in results.vms:
            Vm = VM(vm)
            Vm.disk_detach(results.dvd, False)
    elif results.disk and results.vms and results.attach and results.hba:
        for vm in results.vms:
            Vm = VM(vm)
            Vm.disk_attach(results.hba.upper(), results.disk, "hdd")
    elif results.dvd and results.vms and results.attach and results.hba:
        for vm in results.vms:
            Vm = VM(vm)
            Vm.disk_attach(results.hba.upper(), results.dvd, "dvddrive")
    elif results.adisks:
        D = Disks()
        D.show_attachable_disks(results.adisks)
    elif results.advds:
        D = DVDs()
        D.show_attachable_dvds(results.advds)
    elif results.orphans:
        D = Disks()
        D.purge_orphans()
    else:
        parser.print_usage()

if __name__ == '__main__':
    main()
