from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from paramiko.ssh_exception import SSHException
from netmiko.ssh_exception import AuthenticationException
from getpass import getpass
import os
import re
import time
import csv



with open('show_commands.txt', 'r') as f:
    show_commands = f.read().splitlines()

with open('ip_addresses.txt', 'r') as f:
    ip_addresses = f.read().splitlines()

# print(ip_addresses)

INTERFACE_RE = r'(Eth\w+\d+\/\d+|Te\w+\d+\/\d+\/\d+\.\d+|Te\w+\d+\/\d+\/\d+|Gi\d\/\d\/\d+\.\d+|Gig\w+\d+\/\d+\/\d+\.\d+|Gig\w+\d+\/\d+\/\d+|Gig\w+\.\d+|Gig\w+|Lo\d+|Loop\w+|Ten\w+\.\d+|Ten\w+|Tun\w+|Vlan\d+)'
IPADDRESS_RE = r'.*\s+(\d+\.\d+\.\d+\.\d+)\s+.*'
IPADDRESS_RE1 = r'.*\s+(\d+\.\d+\.\d+\.\d+).*'
HOSTNAME_RE = r'^hostname\s+(.+)'
SITE_CODE_RE = r'(^\w{1,3}).+'
LOCAL_AS_RE = r'.+\s+bgp\s+(\d+)'
REMOTE_AS_IP_RE = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d+\s+(\d+)\s+.+'
SUBNET_RE = r'\s\*>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\s+'
SUBNET_RE1 = r'\s\*>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
IP_INT_BR_RE = r'(Eth\w+\d+\/\d+|Te\w+\d+\/\d+\/\d+\.\d+|Te\w+\d+\/\d+\/\d+|Gi\d\/\d\/\d+\.\d+|Gig\w+\d+\/\d+\/\d+\.\d+|Gig\w+\d+\/\d+\/\d+|Gig\w+\.\d+|Gig\w+|Lo\d+|Loop\w+|Ten\w+\.\d+|Ten\w+|Tun\w+|Vlan\d+)\s+(\d+\.\d+\.\d+\.\d+).*'


def create_device_details(ip):
    return{
       'device_type': 'cisco_ios',
       'ip': ip,
       'username': 'amit',
       'password': 'cisco',
    }

def find_L22_ip_in_output(output=None):
    test1 = re.search('Loopback22',output)
    # print(test1)
    if test1 == None:
        test2 = re.search('Lo22',output)
        # print(test2)
        if test2 == None:
            test3 = re.search('Loopback0',output)
            # print(test3)
            if test3 == None:
                test4 = re.search('Loopback1',output)
                # print(test4)
    
    if test1 != None:
        for line in output.split('\n'):
            if 'Loopback22' in line:
                x = re.match(IP_INT_BR_RE,line)
                L22ip = x.group(2)
                # print(L22ip)
    elif test2 != None:
        for line in output.split('\n'):
            if 'Lo22' in line:
                x = re.match(IP_INT_BR_RE,line)
                L22ip = x.group(2)
                # print(L22ip)
    elif test3 != None:
        for line in output.split('\n'):
            if 'Loopback0' in line:
                x = re.match(IP_INT_BR_RE,line)
                L22ip = x.group(2)
                # print(L22ip)
    elif test4 != None:
        for line in output.split('\n'):
            if 'Loopback1' in line:
                x = re.match(IP_INT_BR_RE,line)
                L22ip = x.group(2)
                # print(L22ip)
    else:
        L22ip = 'Could not determine'
    return L22ip

def find_hostname_in_output(output=None):
    for line in output.split("\n"):
        k = re.match(HOSTNAME_RE, line)
        if k:
            hostname = k.group(1)
            return hostname

def find_local_as_in_output(output=None):
    for line in output.split("\n"):
        k = re.match(LOCAL_AS_RE, line)
        if k:
            local_as = k.group(1)
            return local_as   

def find_site_code_in_hostname(hostname=None):
    k = re.match(SITE_CODE_RE, hostname)
    if k:
        site_code = k.group(1)
        return site_code

def play_with_device_session(net_connect=None, commands=None):
    output = '0' + '\n'
    if type(commands) == str:
        output += net_connect.send_command(commands, delay_factor=.2)
        return output
    else:
        for command in commands:
            cmd = command.strip('\n')
            output += '\n' + net_connect.send_command(cmd, delay_factor=.2)
        return output

def as_public_private(hub_as):
    if int(hub_as) in range(64512, 65536):
        return None
    else:
        return(hub_as)

def find_peer_ip_and_as_in_output(local_as=None):
    cmd = "sh ip bgp summ | ex enteries|mem|BGP|soft|Neigh|" + str(local_as) 
    output = play_with_device_session(net_connect=net_connect, commands=cmd)
    for line in output.split("\n"):
        k = re.match(REMOTE_AS_IP_RE, line)
        if k:
            remote_ip = k.group(1)
            remote_as1 = k.group(2)
            remote_as = as_public_private(remote_as1)
            if remote_as == None:
                continue
            return [remote_ip, remote_as]

def find_peer_ip_and_as_in_output2(net_connect=None, local_as=None):
    output = play_with_device_session(net_connect=net_connect, commands='sh ip bgp summ | ex enteries|mem|BGP|soft|Neigh')
    ip_as = []
    for line in output.split('\n'):
        if local_as in line:
            k = re.match(REMOTE_AS_IP_RE, line)
            if k:
                remote_ip = k.group(1)
                remote_as = k.group(2)
                ip_as = [remote_ip, remote_as]
    if len(ip_as) == 0:
        ip_as = ["Check BGP", "none"]
        return ip_as
    else:
        return ip_as

def find_the_advertised_subnets(net_connect=None, cmd=None):
    output = play_with_device_session(net_connect=net_connect, commands=cmd)
    ADV_SUB_LIST = []

    for line in output.split("\n"):
        x = re.search(SUBNET_RE1, line)
        if x:
            ADV_SUB_LIST.append(x.group(1))
            # print(x.group(1))
        elif x == None:
            x = re.search(SUBNET_RE, line)
            if x:
                ADV_SUB_LIST.append(x.group(1))
                # print(x.group(1))
            else:
                continue
    q = len(ADV_SUB_LIST)
    for _ in range(q+1, 12):
        ADV_SUB_LIST.append('none')
    return ADV_SUB_LIST

def get_length(file_path):
    with open(file_path, "r", newline='') as csv_file:
        reader = csv.reader(csv_file)
        reader_list = list(reader)
        return len(reader_list)

def append_data(file_path, ip, site_code='none', router_name='none', L22ip='none', peer_ip='none', peer_as='none', 
                pool_1='none', pool_2='none', pool_3='none', pool_4='none', pool_5='none', pool_6='none', 
                pool_7='none', pool_8='none', pool_9='none', pool_10='none', pool_11='none'):
    fieldnames = ['S. N0.','LOGIN-IP','SITE-CODE','ROUTER-NAME','ROUTER-LOOP22-IP','PEER-IP','PEER-AS',
        'PUBLIC-POOL-1','PUBLIC-POOL-2','PUBLIC-POOL-3','PUBLIC-POOL-4','PUBLIC-POOL-5','PUBLIC-POOL-6',
        'PUBLIC-POOL-7','PUBLIC-POOL-8','PUBLIC-POOL-9','PUBLIC-POOL-10','PUBLIC-POOL-11']
    next_id = get_length(file_path)
    if next_id == 0:
        with open(file_path, "a", newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow({'S. N0.':next_id+1,
                             'LOGIN-IP':ip,
                             'SITE-CODE':site_code,
                             'ROUTER-NAME':router_name,
                             'ROUTER-LOOP22-IP':L22ip,
                             'PEER-IP':peer_ip,
                             'PEER-AS':peer_as,
                             'PUBLIC-POOL-1':pool_1,
                             'PUBLIC-POOL-2':pool_2,
                             'PUBLIC-POOL-3':pool_3,
                             'PUBLIC-POOL-4':pool_4,
                             'PUBLIC-POOL-5':pool_5,
                             'PUBLIC-POOL-6':pool_6,
                             'PUBLIC-POOL-7':pool_7,
                             'PUBLIC-POOL-8':pool_8,
                             'PUBLIC-POOL-9':pool_9,
                             'PUBLIC-POOL-10':pool_10,
                             'PUBLIC-POOL-11':pool_11,
                            })
    else:
        with open(file_path, "a", newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writerow({'S. N0.':next_id,
                             'LOGIN-IP':ip,
                             'SITE-CODE':site_code,
                             'ROUTER-NAME':router_name,
                             'ROUTER-LOOP22-IP':L22ip,
                             'PEER-IP':peer_ip,
                             'PEER-AS':peer_as,
                             'PUBLIC-POOL-1':pool_1,
                             'PUBLIC-POOL-2':pool_2,
                             'PUBLIC-POOL-3':pool_3,
                             'PUBLIC-POOL-4':pool_4,
                             'PUBLIC-POOL-5':pool_5,
                             'PUBLIC-POOL-6':pool_6,
                             'PUBLIC-POOL-7':pool_7,
                             'PUBLIC-POOL-8':pool_8,
                             'PUBLIC-POOL-9':pool_9,
                             'PUBLIC-POOL-10':pool_10,
                             'PUBLIC-POOL-11':pool_11,
                            })


def main():

    for ip in ip_addresses:
        devices = create_device_details(ip)
        try:
            net_connect = ConnectHandler(**devices, auth_timeout=60)
        except(NetMikoTimeoutException):
            print ('Timeout to device with ip: ' + ip)
            continue
        except (EOFError):
            print ("End of file while attempting device with ip:" + ip)
            continue
        except (SSHException):
            print ('SSH Issue. Are you sure SSH is enabled? on device with ip: ' + ip)
            continue
        except Exception as unknown_error:
            print ('Some other error: ' + str(unknown_error) + 'while accessing device with ip: ' + ip)
            continue
        
        # time.sleep(.2)
        hostprompt = net_connect.find_prompt()
        op1 = play_with_device_session(net_connect=net_connect,commands=show_commands)
        # print(op1)
        L22ip = find_L22_ip_in_output(output=op1)
        hostname1 = hostprompt.strip('#')
        site_code = find_site_code_in_hostname(hostname=hostname1)
        local_as = find_local_as_in_output(output=op1)
        peer_ip_as_list = find_peer_ip_and_as_in_output(local_as=local_as)
        if peer_ip_as_list == None:
            peer_ip_as_list = find_peer_ip_and_as_in_output2(net_connect=net_connect, local_as=local_as)
        peer_ip = peer_ip_as_list[0]
        peer_as = peer_ip_as_list[1]
        cmd1 = 'sh ip bgp neigh '+ str(peer_ip) + ' advertised-routes | in 32768'
        subnets = find_the_advertised_subnets(net_connect=net_connect, cmd=cmd1)
        append_data('brbgpdata.csv', ip,site_code=site_code.upper(),router_name=hostname1,L22ip=L22ip,peer_ip=peer_ip,peer_as=peer_as,
        pool_1=subnets[0], pool_2=subnets[1], pool_3=subnets[2], pool_4=subnets[3], pool_5=subnets[4], 
        pool_6=subnets[5], pool_7=subnets[6], pool_8=subnets[7], pool_9=subnets[8], pool_10=subnets[9], pool_11=subnets[10])

if __name__ == "__main__":
    main()
