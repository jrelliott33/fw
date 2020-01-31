#!/usr/bin/python3

import argparse
import os
import shlex
import subprocess
import sys 

IPT = 'sudo /usr/sbin/iptables'

def check_sudo():
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

def SetDefaultRules(localip):
    defaultrules = '''-F
                    -X
                    -t nat -F
                    -t nat -X
                    -t mangle -F
                    -t mangle -X
                    -P INPUT   DROP
                    -P FORWARD DROP
                    -P OUTPUT  DROP
                    -A INPUT -s {}/24 -i eth0 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
                    -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
                    -A INPUT -i lo -j ACCEPT
                    -A OUTPUT -o eth0 -p tcp -m tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
                    -A OUTPUT -o eth0 -p tcp -m tcp --match multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
                    -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
                    -A OUTPUT -o lo -j ACCEPT
                    -A OUTPUT -p icmp -j ACCEPT
                    -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
                    -A INPUT -j DROP
                    -A FORWARD -j DROP
                    -A OUTPUT -j DROP'''.format(localip)
    print (len(defaultrules.splitlines()))
    for rule in defaultrules.splitlines():
        cmd = IPT + " " + rule.strip()
        try:
            print(cmd)
            cp = subprocess.run([cmd],shell=True,
                                      check=True)
            
        except Exception as e: 
            print("Error Setting Default Rules")
            return False
       
    print("Default Rules Set")
    return True

def AddRule(ip):
    pass

def DeleteRule(ip):
    pass

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
        cmd = IPT + " " + rule.strip()
        try: 
            print(cmd)
            cp = subprocess.run([cmd],shell=True,check=True)
        except Exception as e:
            print("Error Flushing Rules")
            return False
        
    print("Rules Flushed.")
    return True


def SetForTor(ip,cmd):
    pass



if __name__ == '__main__':
    #Check if sudo 
    parser = argparse.ArgumentParser()
    parser.add_argument('-A','--add', nargs='+')
    parser.add_argument('-D','--delete', nargs='+')
    parser.add_argument('-B','--block', nargs='+')
    parser.add_argument('-R','--reset',action='store_true', help = 'reset default rules')
    parser.add_argument('-F','--flush',action='store_true',help='Flush and Accept All')
    parser.add_argument('-T','--tor-start',action='store_true', help='Start Kalitorify')
    parser.add_argument('-X','--tor-stop',action='store_true', help='Stop Kalitorify')
    args = parser.parse_args()

    if check_sudo() != 0:
        print("Run with root")
        sys.exit()
    else:
        try :
            localip = GetLocalIP()
        except:
            sys.exit()

    print(localip)
    if args.add:
        AddRule(localip)
    if args.delete:
        DeleteRule(localip)
    if args.block:
        BlockRule(localip)
    if args.reset:
        SetDefaultRules(localip)
    if args.flush:
        FlushRules()
    


        



