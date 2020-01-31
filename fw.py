#!/usr/bin/python3

import argparse
import os
import shlex
import subprocess
import sys 


def CheckSudo():
    ret = 0
    if os.geteuid() != 0:
        msg = "[sudo] password for %u:"
        ret = subprocess.check_call("sudo -v -p '%s'" % msg, shell=True)
    return ret

def GetLocalIP():
    cmd = "ip addr show eth0 | grep 'inet ' | cut -f2 | awk '{ print $2}'"
    try: 
        cp =  subprocess.check_output([cmd],shell=True,encoding='UTF-8')
        return cp.split('/')[0]
    except Exception as e:
        print("Falied to get local ip address")
        print(e)
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
            print("Default Rules Not Set")
            return False
           
    print("Default Rules Set")
    return True
   
def PrintRules():
    IPT = 'sudo /usr/sbin/iptables '
    cmds = ['-nvL','-nvL -t nat']
    for cmd in cmds:
        try:
            print(subprocess.check_output([IPT + cmd],shell=True).decode('utf-8'))
            
        except subprocess.CalledProcessError as e:            
            print("Error Getting Rules: {}".format(e))
            return False

def RunRule(cmd,IPT = 'sudo /usr/sbin/iptables '):
    
    try:
        cmd = IPT + cmd
        cp = subprocess.check_call([cmd],shell=True)
        return True

    except subprocess.CalledProcessError as e:            
        print("Error Setting Rule: {}".format(cmd))
        return False

def IptablesRules(ip,action="I",interface='eth0'):
    # 192.168.1.1 192.168.1.1:80,443 :443

    for item in ip:
        ips = item.split(":",1)
        if len(ips) > 2: 
            print("ERROR: unknown string {}".format(ips))
        elif len(ips) == 1:
            #Handle only ips
            outcmd = "-{} OUTPUT -o {} -p tcp -d {} -j ACCEPT".format(action,interface,ips[0])
            incmd = "-{} INPUT -i {} -p tcp -s {} -j ACCEPT".format(action,interface,ips[0])
            print(outcmd)
            print(incmd)
        elif len(ips) == 2:
        #Handle multiple ports :PORT,PORT or IP:PORT,PORT
        #TODO: Specify Direction???
            if ips[0] != "" and ips[1] != "":
                for port in ips[1].split(','):
                    cmd = "-{} OUTPUT -o {} -p tcp -d {} --dport {} -j ACCEPT".format(action,interface,ips[0],port)
                    print(cmd)
                # Handle port only :<RHP>
            elif ips[0] == "" and ips[1] != "":
                for port in ips[1].split(','):
                    cmd = "-{} OUTPUT -o {} -p tcp --dport {} -j ACCEPT".format(action,interface,port)
                    print(cmd)
            else: 
                print("ERROR: Unkown Specification")                
        else: 
            print("ERROR: Unknown Value")
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
            print("Error Flushin Rules")
            return False
           
    print("Rules Flushed.")
    return True

def SetForTor(action='start'):
    if action=='start':
        cmd = ["sudo","kalitorify","-t"]
    elif action == 'stop':
        cmd = ["sudo","kalitorify","-c"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 
        ## But do not wait till netstat finish, start displaying output immediately ##
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


if __name__ == '__main__':
    #Check if sudo 
    parser = argparse.ArgumentParser()
    parser.add_argument('-A','--add', nargs='+',help="Allow IP IP:PORT :PORT through firewall, ")
    parser.add_argument('-B','--block', nargs='+')
    parser.add_argument('-D','--delete', nargs='+')
    parser.add_argument('-F','--flush',action='store_true',help='Flush and Accept All')
    parser.add_argument('-P','--print',action='store_true',help='Print Firewall Rules')
    parser.add_argument('-R','--reset',action='store_true', help = 'reset default rules')
    parser.add_argument('-T','--starttor',action='store_true', help='Start Kalitorify')
    parser.add_argument('-X','--stoptor',action='store_true', help='Stop Kalitorify')
    args = parser.parse_args()
    if CheckSudo() != 0:
        print("Run with root")
        sys.exit()
    else:
        pass

    if args.add:
        IptablesRules(args.add)
    if args.delete:
        IptablesRules(args.delete,'D')
    if args.block:
        #IptablesRules(args.delete,'block')
        pass
    if args.print:
        PrintRules()
    if args.reset:
        SetDefaultRules()
    if args.flush:
        FlushRules()
    if args.starttor:
        SetForTor('start')
    if args.stoptor:
        SetForTor('stop')
    


        



