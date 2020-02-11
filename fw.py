#!/usr/bin/python3

import argparse
import os
import requests
import shlex
import shutil
import subprocess
import sys 


def Msg(msg="",type="OK"):
    #define colors
    red='\033[91m'
    green='\033[92m'
    blue='\033[94m'
    yellow='\033[93m'
    white='\033[97m'
    cyan='\033[96m'
    endc='\033[0m'
    
    
    if type == "ERROR":
        print(f"[{red}Error{endc}]: {msg}")
    elif type == "RUN":
        print(f"{blue} ==> {endc} {msg}")
    elif type == "WARN":
        print(f"[{yellow}Error{endc}]: {msg}")
    elif type == "OK":
        print(f"[{green} OK {endc}]: {msg}")
    else:
        print(f"{white}{msg}{endc}")

def CheckPublicIP():
    urllist = [ 'http://ip-api.com/',
                'https://ipinfo.io/',
                'https://api.myip.com/',
                'https://ipleak.net/json/']
    for url in urllist:
        try:
            
            r = requests.get(url)
            if r.status_code == 200:
                return r.text
        except Exception as e:
            print(e)
            
        

def GetLocalIP(interface='eth0'):
    '''Gets local ip address 

    Parameters
    ----------d fs
    interface : str
        interface to get ip address of 

    Returns
    ------- 
    str
        ip address of interface 
    '''

    cmd = f"ip addr show {interface} | grep 'inet ' | cut -f2 | awk '{ print $2}'"
    try: 
        cp =  subprocess.check_output([cmd],shell=True,encoding='UTF-8')
        return cp.split('/')[0]
    except Exception as e:
        Msg("Falied to get local ip address","ERROR")
        Msg(e,"ERROR")
        return 0

def SetDefaultRules():
    localip = GetLocalIP()
    defaultrules = '''-F
                    -X
                    -t nat -F
                    -t nat -X
                    -t mangle -F
                    -t mangle -X
                    -A INPUT -s {}/24 -i eth0 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
                    -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
                    -P INPUT   DROP
                    -P FORWARD DROP
                    -P OUTPUT  DROP
                    -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
                    -A INPUT -i lo -j ACCEPT
                    -A OUTPUT -o eth0 -p tcp -m tcp --match multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
                    -A OUTPUT -o lo -j ACCEPT
                    -A OUTPUT -p icmp -j ACCEPT
                    -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
                    -A INPUT -j DROP
                    -A FORWARD -j DROP
                    -A OUTPUT -j DROP'''.format(localip)
    
    for rule in defaultrules.splitlines():
        if not RunRule(rule.strip()):
            Msg("Default Rules Not Set","ERROR")
            return False
           
    Msg("Default Rules Set")
    return True
   
def PrintRules():
    IPT = '/usr/sbin/iptables '
    cmds = ['-nvL','-nvL -t nat']
    for cmd in cmds:
        try:
            Msg(subprocess.check_output([IPT + cmd],shell=True).decode('utf-8'),"OUT")
        except subprocess.CalledProcessError as e:            
            Msg("Error Getting Rules: {}".format(e),"ERROR")
            return False

def RunRule(cmd,IPT = '/usr/sbin/iptables '):
    ''' Runs iptables rule specified by cmd

    Parameters
    ----------
    cmd: str
        iptables command to run
    IPT: str
        path to iptables binary

    Return
    ------
        bool
            True if successful, false if error
    '''
    try:
        cmd = IPT + cmd
        subprocess.run([cmd],shell=True,check=True)
        return True

    except subprocess.CalledProcessError as e:            
        Msg("Error Setting Rule: {}".format(cmd),"ERROR")
        return False

def Add(ip,interface='eth0'):
    '''Helper Function to make adding rule easier'''
    IptablesRules(ip,action="I",interface=interface)

def Remove(ip,interface='eth0'):
    '''Helper Function to make adding rule easier'''
    IptablesRules(ip,action="D",interface=interface)


def IptablesRules(ip,action="I",interface='eth0'):
    '''Takes a list of ip:port combinations, parses them and runs 
       the appropriate iptables Rules. 

       Ex: >:443 = allow tcp port 443 inbound
       Ex: 192.168.1.1 192.168.1.2 = allow to/from 192.168.1.1 & 192.168.1.2 
    
    Parameters
    ----------
    ip : list
        list containing IP:port combinations to add
    action : str
        Iptables Action [I = Insert], D = Delete, A = ADD
    interface : str
        Network interface to apply rule to
    
    Returns
    -------
        bool
            True if Successful, False if error. 
    
    '''
    direction = 'b'
    
    for item in ip:
        if item[0] in [">" , "<"]:
            direction = item[0]
            item = item[1:]
        
        ips = item.split(":",1)
        if len(ips) > 2: 
            Msg("unknown string {}".format(ips),"ERROR")
        elif len(ips) == 1:
            #Handle only ips
            if direction in [ ">",'b']:
                cmd = "-{} INPUT -i {} -p tcp -s {} -j ACCEPT".format(action,interface,ips[0])
                RunRule(cmd)
            if direction in [ "<",'b']:
                cmd = "-{} OUTPUT -o {} -p tcp -d {} -j ACCEPT".format(action,interface,ips[0])
                RunRule(cmd)
                        
        elif len(ips) == 2:
            #Handle multiple ports :PORT,PORT or IP:PORT,PORT
            if ips[0] != "" and ips[1] != "":
                for port in ips[1].split(','):
                    if direction in [ ">",'b']:
                        cmd = "-{} INPUT -i {} -p tcp -s {} --dport {} -j ACCEPT".format(action,interface,ips[0],port)
                        RunRule(cmd)
                    if direction in [ "<" ]:
                        cmd = "-{} OUTPUT -o {} -p tcp -d {} --dport {} -j ACCEPT".format(action,interface,ips[0],port)
                        RunRule(cmd)

            # Handle port only :<RHP>
            elif ips[0] == "" and ips[1] != "":
                for port in ips[1].split(','):
                    if direction in [ ">",'b']:
                        cmd = "-{} INPUT -i {} -p tcp --dport {} -j ACCEPT".format(action,interface,port)
                        RunRule(cmd)
                    if direction in [ "<" ]:
                        cmd = "-{} OUTPUT -o {} -p tcp --dport {} -j ACCEPT".format(action,interface,port)
                        RunRule(cmd)
            else: 
                Msg("Unkown Specification","ERROR")                
        else: 
            Msg("Unknown Value","ERROR")
            return False

        return True

def FlushRules():
    '''Flushes iptables Rules and Sets all to ACCEPT
    
    Returns
    -------
    bool 
        True if Successful, False if error. 
    '''

    rules = '''-P INPUT ACCEPT
               -P FORWARD ACCEPT
               -P OUTPUT ACCEPT
               -F
               -X
               -t nat -F
               -t nat -X
               -t mangle -F
               -t mangle -X'''

    for rule in rules.splitlines():
        if not RunRule(rule.strip()):
            Msg("Error Flushing Rules","ERROR")
            return False
           
    Msg("Rules Flushed.")
    return True

def SetTorRules(virtual_address,trans_port,dns_port,control_port=None):
    '''Sets iptables rules needed for tor transparent proxy
    [TODO]: Use Control Port to determine bridge IP address and explicitly allow outbound. 

    Parameters
    ----------
    virtual_address : str
        String <ip/cidr> containing the virtual address for the tor connection (VirtualAddrNetworkIPv4 in torrc)
    trans_port : str
        String containing TransPort from torrc
    dns_port : str
        String containing TOR DNS_port from torrc

    Returns
    -------
    bool 
        True if successful, False if not 
    '''

    not_tor="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    tor_uid  =subprocess.run(['id','-u','debian-tor'],capture_output=True,encoding='utf-8').stdout.strip()
    
    tor_rules=f'''-P INPUT ACCEPT
            -P FORWARD ACCEPT
            -P OUTPUT ACCEPT
            -F
            -X
            -t nat -F
            -t nat -X
            -t nat -A OUTPUT -d {virtual_address} -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports {trans_port}
            -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports {dns_port}
            -t nat -A OUTPUT -m owner --uid-owner {tor_uid} -j RETURN
            -t nat -A OUTPUT -o lo -j RETURN
            -t nat -A OUTPUT -d {not_tor} -j RETURN
            -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports {trans_port}
            -A INPUT -m state --state ESTABLISHED -j ACCEPT
            -A INPUT -i lo -j ACCEPT
            -A INPUT -i eth0 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
            -A INPUT -j DROP
            -A FORWARD -j DROP
            -A OUTPUT -m conntrack --ctstate INVALID -j DROP
            -A OUTPUT -m state --state INVALID -j DROP
            -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
            -A OUTPUT -m owner --uid-owner {tor_uid} -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT
            -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT
            -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport {trans_port} --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
            -A OUTPUT -o eth0 -p tcp -m tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
            -A OUTPUT -j DROP
            -P INPUT DROP
            -P FORWARD DROP
            -P OUTPUT DROP'''
    for rule in tor_rules.splitlines():
        if not RunRule(rule.strip()):
            Msg("Error Setting TOR Rules","ERROR")
            return False
           
    Msg("TOR Iptables Rules Set")
    return True

def StartTor(torrc=None):
    ''' Configures system as a transparent TOR proxy. 

    Parameter
    ---------
    torrc : str
        custom torrc file to use

    Returns
    -------
    bool 
        True if successful, False if Error
    '''

    Msg("Stopping Tor Service","RUN")
    subprocess.run(['systemctl','stop','tor.service'],capture_output=True)
    
    torrc_file = "/etc/tor/torrc"
    
    Msg("Starting Transparent Proxy","RUN")
    try:
        Msg("Backing up torrc to /tmp/torrc_orig","RUN")
        shutil.copyfile(torrc_file,'/tmp/torrc_orig')
    except Exception as e:
        Msg("Couldn't backing up torrc ... exiting","ERROR")
        Msg("\t{e}","ERROR")
        return False
    
    if torrc:
        try:
            Msg("Copying custom torrc to /etc/tor/torrc","RUN")
            shutil.copyfile(torrc,torrc_file)
        except Exception as e:
            Msg("Couldn't copy custom torrc","ERROR")
            Msg("\t{e}","ERROR")
            return False
    else:
        trans_port="9040"
        dns_port="5353"
        virtual_address="10.192.0.0/10"

        torrc =f'''VirtualAddrNetworkIPv4 {virtual_address}
        AutomapHostsOnResolve 1
        TransPort {trans_port} IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
        SocksPort 9050
        DNSPort {dns_port}
        '''
        try:
            Msg("Writing tor options")
            with open(torrc_file,'a') as tfile:
                tfile.write(torrc)
        except Exception as e:
            Msg("Couldn't write options ... exiting","ERROR")
            Msg("\t{e}","ERROR")
            return False
    
    
    
    Msg("Configure system's DNS resolver to use Tor's DNSPort","RUN")
    shutil.copyfile('/etc/resolv.conf','/tmp/resolv.conf.backup')
    with open('/etc/resolv.conf','w') as ofile:
        ofile.write("nameserver 127.0.0.1")
    
   
    Msg("Disable IPv6 with sysctl","RUN")
    subprocess.run(['sysctl','-w','net.ipv6.conf.all.disable_ipv6=1'],check=True,capture_output=True)
    subprocess.run(['sysctl','-w', 'net.ipv6.conf.default.disable_ipv6=1'],check=True,capture_output=True)            
    
    cp = subprocess.run(['systemctl','start','tor.service'],capture_output=True,check=True)
    if not cp.returncode:
        Msg( "Tor service started")
    else: 
        Msg("Error Starting TOR service",'ERROR')
        return False
    # setup_iptables tor_proxy
    Msg("Setting Up iptables for TOR","RUN")
    if not SetTorRules(virtual_address,trans_port,dns_port):
        Msg("Error Configuring TOR iptables")
        
    
    #check Tor Status status 
    Msg("Checking current status of Tor service","RUN")
    cp = subprocess.run(['systemctl','is-active','tor.service'],capture_output=True,check=True)
    if not cp.returncode:
        Msg("Tor Service is running","OK")
        CheckPublicIP()
        Msg("Transparent Proxy activated, your system is under Tor")
        return True
    else:
        Msg("Tor Service is not running","ERROR")
        return False
    
    
    return False

def StopTor():        
    '''Stops TOR service and resets things to previous settings

    Returns
    -------
    bool
        True if successful, False if failure
    '''

    Msg("Stopping TOR Service","RUN")
    cp = subprocess.run(['systemctl','stop','tor.service'],check=True,capture_output=True)
    Msg("TOR Service Stopped")
    Msg("Restoring Default iptables Rules","RUN")
    SetDefaultRules()


    try:
        Msg("Restoring torrc from /tmp/torrc_orig","RUN")
        shutil.move('/tmp/torrc_orig', '/etc/tor/torrc')
    except:
        Msg("Couldn't restore original torrc","ERROR")

    try:
        Msg("Restoring system's DNS resolver","RUN")
        shutil.copyfile('/tmp/resolv.conf.backup','/etc/resolv.conf')
    except Exception as e:
        Msg("Can't Restore resolv.conf","ERROR")
        Msg("\t{e}","ERROR")

    Msg("Enabling IPv6 with sysctl","RUN")
    subprocess.run(['sysctl','-w','net.ipv6.conf.all.disable_ipv6=0'],check=True,capture_output=True)
    subprocess.run(['sysctl','-w', 'net.ipv6.conf.default.disable_ipv6=0'],check=True,capture_output=True)            

    Msg("Transparent Proxy stopped")
    return True
    
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-A','--add', nargs='+',help="Allow IP IP:PORT :PORT through firewall, ")
    parser.add_argument('-D','--delete', nargs='+')
    parser.add_argument('-F','--flush',action='store_true',help='Flush and Accept All')
    parser.add_argument('-i', '--interface',help='Specify inteface [eth0]',default = 'eth0')
    parser.add_argument('-P','-p','--print',action='store_true',help='Print Firewall Rules')
    parser.add_argument('-R','--reset',action='store_true', help = 'reset default rules')
    parser.add_argument('-C','--check',action='store_true', help='Check public IP')
    parser.add_argument('-T','--starttor',action='store_true', help='Start Kalitorify')
    parser.add_argument('-t','--torrc', default=None, help='Custom torrc file')
    parser.add_argument('-X','--stoptor',action='store_true', help='Stop Kalitorify')
    args = parser.parse_args()
    #sudo check 
    if os.geteuid() != 0:
        subprocess.call(['sudo', 'python3', *sys.argv])
        sys.exit()
    else:
            pass

    if args.reset:
        SetDefaultRules()
    if args.add:
        IptablesRules(args.add,interface=args.interface)
    if args.delete:
        IptablesRules(args.delete,'D',interface=args.interface)
    if args.flush:
        FlushRules()
    if args.check:
        print(CheckPublicIP())
    if args.print:
        PrintRules()
    if args.starttor:
        StartTor(args.torrc)
    if args.stoptor:
        StopTor()
    


        



