#!/usr/bin/python3

import argparse
import os
import requests
import shlex
import shutil
import subprocess
import sys 

DEBUG = False

class bcolors:
    red='\033[91m'
    green='\033[92m'
    blue='\033[94m'
    yellow='\033[93m'
    white='\033[97m'
    cyan='\033[96m'
    endc='\033[0m' 

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
        except:
            pass
        

def GetLocalIP():
    cmd = "ip addr show eth0 | grep 'inet ' | cut -f2 | awk '{ print $2}'"
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
    if DEBUG:
        cmd = IPT + cmd
        print("DEBUG: {}".format(cmd))
    else:
        try:
            cmd = IPT + cmd
            subprocess.run([cmd],shell=True,check=True)
            return True

        except subprocess.CalledProcessError as e:            
            Msg("Error Setting Rule: {}".format(cmd),"ERROR")
            return False

def IptablesRules(ip,action="I",interface='eth0'):
    # 192.168.1.1 192.168.1.1:80,443 :443
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

def FlushRules():
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
            Msg("Error Flushin Rules","ERROR")
            return False
           
    Msg("Rules Flushed.")
    return True


def SetForTor(action='start'):
    
    trans_port="9040"
    dns_port="5353"
    virtual_address="10.192.0.0/10"

    # LAN destinations that shouldn't be routed through Tor
    non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    
    torrc_file = '/etc/tor/torrc'
    torrc =f'''VirtualAddrNetworkIPv4 {virtual_address}
    AutomapHostsOnResolve 1
    TransPort {trans_port} IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
    SocksPort 9050
    DNSPort {dns_port}
    '''
    if action == 'start':
        try:
            Msg("Copying torrc to /tmp/torrc_orig","RUN")
            shutil.copyfile(torrc_file,'/tmp/torrc_orig')
        except Exception as e:
            Msg("Couldn't backing up torrc ... exiting","ERROR")
            Msg("\t{e}","ERROR")
            return False
        try:
            Msg("Writing tor options")
            with open(torrc_file,'a') as tfile:
                tfile.write(torrc)
        except Exception as e:
            Msg("Couldn't write options ... exiting","ERROR")
            Msg("\t{e}","ERROR")

        Msg("Tor Setup complete")
        return True
    elif action == 'stop':
        try:
            Msg("Restoring torrc from /tmp/torrc_orig","RUN")
            shutil.move('/tmp/torrc_orig', torrc_file)
        except:
            Msg("Couldn't restore original torrc","ERROR")

        Msg("Tor Restoration complete")
        return True
    else:
        return False

'''
def SetForTor(action='start'):
    if action=='start':
        cmd = ["sudo","kalitorify","-t"]
    elif action == 'stop':
        cmd = ["sudo","kalitorify","-c"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        while True:
            out = p.stdout.read(1)
            if out == '' and p.poll() != None:
                break
            if out != '':
                sys.stdout.write(out.decode('utf-8'))
                sys.stdout.flush()    
        return True
    except Exception as e:
        print("ERROR setting up kalitorify, reseting default rules.")
        print(e)
        SetDefaultRules()
        return False
'''

if __name__ == '__main__':
    #Check if sudo 
    parser = argparse.ArgumentParser()
    parser.add_argument('-A','--add', nargs='+',help="Allow IP IP:PORT :PORT through firewall, ")
    parser.add_argument('-D','--delete', nargs='+')
    parser.add_argument('-F','--flush',action='store_true',help='Flush and Accept All')
    parser.add_argument('-i', '--interface',help='Specify inteface [eth0]',default = 'eth0')
    parser.add_argument('-P','--print',action='store_true',help='Print Firewall Rules')
    parser.add_argument('-R','--reset',action='store_true', help = 'reset default rules')
    parser.add_argument('-C','--check',action='store_true', help='Check public IP')
    parser.add_argument('-T','--starttor',action='store_true', help='Start Kalitorify')
    parser.add_argument('-X','--stoptor',action='store_true', help='Stop Kalitorify')
    args = parser.parse_args()
    if os.geteuid() != 0:
        subprocess.call(['sudo', 'python3', *sys.argv])
        sys.exit()
    else:
            pass

    if args.add:
        IptablesRules(args.add,interface=args.interface)
    if args.delete:
        IptablesRules(args.delete,'D',interface=args.interface)
    if args.print:
        PrintRules()
    if args.reset:
        SetDefaultRules()
    if args.flush:
        FlushRules()
    if args.check:
        print(CheckPublicIP())
    if args.starttor:
        SetForTor('start')
    if args.stoptor:
        SetForTor('stop')
    


        



