"""
Generates DP cli commands to add
network classes and blocklist rules
from a list of IP subnet/hosts
================
example:

input:
145.13.164.171
145.13.163.0/24

cli class:
classes modify network add blk_list_1 1 -a 145.13.164.171 -s 32
classes modify network add blk_list_1 3 -a 145.13.163.0 -s 24

cli blok list rule:
dp block-allow-lists blocklist table create blk_list_1 -sn blk_list_1 -dn any_ipv4 -a drop
=================

This program has for stages:
each stage uses an input file and an output file 
the output file is used the next stage as input
(see each function comments for more details)

IF THE SUBNET LIST ARE ALREADY IN A VALIDATED LIST YOU CAN START AT STAGE 3

Stages
1) remove_duplicates - clean the data source for leading/trailling spaces and remove duplicate lines
2) validate_subnet - validates each subnet from the list
3) generate cli command for network classes from valid subnet list
4) generate cli command for block list rules from the newwork classes created in step 3

"""

import sys
import os
import ipaddress
import argparse
from requests import Session
import requests
import config as cfg


subnet_list = 'subnet_list.txt'  # stage 1 outpout file and stage 2 input file 
valid_subnets = 'valid_subnets.txt'  # stage 2 outpout file and stage 3 input file
cli_class_cmd = 'cli_class_cmd.txt' # stage 3 outpout file and stage 4 input file
cli_blk_rule = 'cli_blk_rule.txt' # stage 4 output file
output_log = 'output.log'
chunk_size=250

class Vision:

    def __init__(self, ip, username, password):
        self.ip = ip
        self.login_data = {"username": username, "password": password}
        
        
        
        self.base_url = "https://" + ip
        self.sess = Session()
        self.sess.headers.update({"Content-Type": "application/json"})
        self.login()

    def login(self):
        print("Login to Vision...")
        login_url = self.base_url + '/mgmt/system/user/login'
        try:
            r = self.sess.post(url=login_url, json=self.login_data, verify=False)
            r.raise_for_status()
            response = r.json()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
                requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as err:
            raise SystemExit(err)

        if response['status'] == 'ok':
            self.sess.headers.update({"JSESSIONID": response['jsessionid']})
            #print("Auth Cookie is:  " + response) #'jsessionid'])
            #print(response) #'jsessionid'])
        else:
            exit(1)

    def LockUnlockDP(self,action,dp):
        #lock/unlock DP
        self.DPlock_path = f"/mgmt/system/config/tree/device/byip/{dp}/"
        send_url = self.base_url + self.DPlock_path + action
        r = self.sess.post(url=send_url, verify=False)
        banner()
        print (action.capitalize(),"DP\n#Request headers:",r.request.headers)
        print("URL:",send_url)
        print("Status code:", r.status_code)
        print("return code",r.status_code,r._content)
        banner()
    
    def AddNetClass(self,net_class,dp):
        #net_class is a dict with
            # key (used in the URL) = network_class_name/index"
            # value (used as json payload) = another dict with values (see below)
                # { 'class_name/x : {'rsBWMNetworkAddress': '198.51.154.24', 'rsBWMNetworkMask': '32'} }
        self.DPclass_path = f"/mgmt/device/byip/{dp}/config/rsBWMNetworkTable/"
        for net_name, json_data in net_class.items():
            print("Add network class...")
            send_url = self.base_url + self.DPclass_path + net_name
            print("URL:",send_url)
            print("Class name and index:",net_name)
            print("JSON payload:" , json_data)        
            r = self.sess.post(url=send_url, json=json_data, verify=False)
            print("return code",r.status_code,r._content)
            banner("-")
        banner()

    def AddBlkPolicy(self,bl_policy,dp):
        #bl_policy is a dict with"
            # key (used in the URL) = policy_name"
            # value (used as json payload) = another dict with values (see below)
                # {'policy_name' : {'rsNewBlockListSrcNetwork': 'p2_1', 'rsNewBlockListDstNetwork': 'any'} }
        self.DPBlkPol_path = f"/mgmt/device/byip/{dp}/config/rsNewBlockListTable/"
        for policy_name, json_data in bl_policy.items():
            print("Add Blocklist policy...")
            print(f"Policy name: {policy_name}, JSON payload: {json_data}")
            send_url = self.base_url + self.DPBlkPol_path + policy_name
            print("URL:",send_url)
            r = self.sess.post(url=send_url, json=json_data, verify=False)
            print("return code",r.status_code,r._content)
            # print(r.content)
            # if r.status_code != '200':
            #     print("return code",r.status_code,"\n",r._content)
            banner("-")
        banner()

    def UpdatePoliciesAllDP(self):
        print("Update policy...")
        #json_payload={"deviceIpAddresses":["172.27.200.169"]} data is a list of IPs
        key='deviceIpAddresses'
        value=cfg.DefensePro_MGMT_IP
        json_payload = {key:value} # a Dict with value =>a LIST of IP
        sig_list_url = self.base_url + '/mgmt/device/multi/config/updatepolicies'
        print(sig_list_url)
        r = self.sess.post(url=sig_list_url, json=json_payload, verify=False)
        print(r.content)
        banner()

    def UpdatePolicies(self,dp):
        print("Update policy...")
        sig_list_url = self.base_url + f'/mgmt/device/byip/{dp}/config/updatepolicies'
        print(sig_list_url)
        r = self.sess.post(url=sig_list_url, verify=False)
        print("return code",r.status_code,r._content)
        banner()

def banner(char="="):
    print(char * 80)

def extract_values_from_dict(input_dict):
    extracted_dict = {}

    for key, value in input_dict.items():
        # Split the value string into individual components
        components = value.split(',')

        # Create a new dictionary from the components
        extracted_values = {item.split(':')[0]: item.split(':')[1] for item in components}

        # Add the new dictionary to the extracted_dict using the original key
        extracted_dict[key] = extracted_values

    return extracted_dict

# STAGE 1
def remove_duplicates(input_file_path, output_file_path):
    """
    The input file must contain 1 column with
    the list of subnets/hots to add
    a.a.a.a/x -> specific subnet
    b.b.b.b  -> /32 subnet
    clean lines of the file and remove duplicates
    """
    # Set to store unique lines
    unique_lines = set()
    duplicate_count = 0
    total_lines = 0

    # Open the input file for reading
    with open(input_file_path, 'r') as input_file:
        # Read each line from the file
        lines = input_file.readlines()

        # Iterate over the lines
        for line in lines:
            # Increment the total line count
            total_lines += 1

            # Strip leading and trailing whitespaces
            cleaned_line = line.strip()

            # Check if the line is not in the set (i.e., it's unique)
            if cleaned_line not in unique_lines:
                # Add the line to the set
                unique_lines.add(cleaned_line)
            else:
                # Increment the duplicate count
                duplicate_count += 1


    # Open the output file for writing
    with open(output_file_path, 'w') as output_file:
        # Write the unique lines to the output file
        output_file.write("\n".join(unique_lines))
        

    print("Stage1: Processing",input_file_path,"to remove duplicate lines and spaces.")
    print(f"Found {duplicate_count} duplicate lines out of {total_lines} total lines.")
    print("Stage1: Results are in ",output_file_path,".")
    banner()

# STAGE2
def validate_subnets(input_file, output_file):
    print("Stage2: Processing",input_file,"to remove invalid subnets.")
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        count=0
        for line_number, line in enumerate(infile, start=1):
            subnet = line.strip()  # Remove leading and trailing whitespaces
            count +=1
            if '/' in subnet:
                ip_address, subnet_mask = subnet.split('/')
                try:
                    ip = ipaddress.IPv4Address(ip_address)
                    net = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=True)
                    outfile.write(f"{subnet}\n")
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                    print(f"{input_file} has an invalid subnet (line {line_number}): {subnet}")
            else:
                try:
                    ip = ipaddress.IPv4Address(subnet)
                    outfile.write(f"{subnet}/32\n")
                except ipaddress.AddressValueError:
                    print(f"{input_file} has invalid host (line {line_number}): {subnet}")
    print(f"Stage2: processed {count} lines. Valid subnets saved to {output_file}.")
    banner()


# STAGE3
def gen_cli_class_cmd(input_file_path, output_file_path,class_name,chunk=chunk_size):
    """
    Process a text file with IP subnets,
    split the lines into chunks, and write the output to a text file.

    Parameters:
    - input_file_path (str): Path to the input file.
    - output_file_path (str): Path to the output text file.
    - chunk_size (int): Number of lines to include in each chunk.
    Default is 250.
    User is asked to enter class_name and an index (X) is added for each 250 subnets
    blk_list_1
    blk_list_2
    output: classes modify network add 'class_name_X' 'row_number' -a 'ip_subnet' -s 'ip_mask'
    """
    net_class_api={}
    
    print("Stage3: generate network class commands")
    with open(input_file_path, 'r') as input_file:
        lines = input_file.readlines()
        with open(output_file_path, 'w') as output_file:
            for i in range(0, len(lines), chunk):
                for j, line in enumerate(lines[i:i+chunk], 1):
                    split_lines = line.split('/')
                    output_file.write(f'classes modify network add {class_name}_{i//chunk + 1} {j} -a {split_lines[0]} -s {split_lines[1]}')  
                    key = f'{class_name}_{i//chunk + 1}/{j}'
                    value = f'rsBWMNetworkAddress:{split_lines[0]},rsBWMNetworkMask:{split_lines[1].strip()}' 
                    net_class_api.update({key:value})
                    if (j == 1 and i == 0 ) : print("Network class and index:",key,"\n...") 
            print("Network class and index:",key)
    print(f"Output file '{output_file_path}' has been created.\nIt contains netwrok classes to be added.")
    banner()
    return extract_values_from_dict(net_class_api)

# STAGE4
def gen_cli_block_rule(input_file,output_file,policy_name):
    """
    Generate block list rule
    Parameters:
    - input_file_path (str): cli class definition
    - output_file_path (str): 1 block list rule per network class 
    block list rule has 
    src: network class
    dst: any 
    direction: one way
    ports: any
    protocol: any
    """
    policy_api={}
    #payload = "rsNewBlockListSrcNetwork:n6,rsNewBlockListDstNetwork:any,rsNewBlockListAction:1"
    print("Stage4: generate block list policy rules")
    blk_id = set()
    with open(input_file, 'r') as file:
        for line in file:
            columns = line.split()
            blk_id.add(columns[4])
            #print(sorted(blk_id))
        # Convert the set to a sorted list
        sorted_blk = sorted(blk_id)
        with open(output_file, 'w') as output:
            for bk in sorted_blk:
                name = policy_name+ bk[-2:]
                print('Policy:',name)
                output.write(f'dp block-allow-lists blocklist table create {name} -sn {bk} -dn any_ipv4 -a drop\n')
                policy_api.update({name:f'rsNewBlockListSrcNetwork:{bk},rsNewBlockListDstNetwork:any'})
    print(f"Output file '{output_file}' has been created.\nIt contains blocklist policies to be added.")
    banner()
    return extract_values_from_dict(policy_api)


def main():

    description = """
    From an input tile with a list of subnets we generate cli
    commands to create Network Class and Blocklist rule on DP.
    Use "-p or (--push)" option to send the commands to the DP.
    (and update policies)
    """
    parser = argparse.ArgumentParser(description = description,formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument('-i', '--input', type=str, help='Input file with list of networks.')
    parser.add_argument('-n', '--network', type=str, help='Name of the Network class.')
    parser.add_argument('-b', '--blocklist', type=str, help='Name of Blocklist policy.')
    parser.add_argument('-p', '--push', action="store_true", help='Push config to device and update policy.')


    # Parse the command-line arguments
    args = parser.parse_args()
    
    input_file = args.input
    network_name = args.network
    policy_name = args.blocklist
  
    # Your program logic here
    print(f'Input file: {input_file}')
    print(f'Network class name : {network_name}')
    print(f'Policy name: {policy_name}')    
    banner()

    
    if not (args.input and args.network and args.blocklist):
        parser.print_help()
        parser.error("All three arguments (input, network, blocklist) are required.")

    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
        
    else:
        # STAGE 1 - comment to bypass this stage
        remove_duplicates(input_file, subnet_list)

        # STAGE 2 - comment to bypass this stage
        validate_subnets(subnet_list, valid_subnets)

        # STAGE 3
        net_class  = gen_cli_class_cmd(valid_subnets,cli_class_cmd,network_name)
        
        # STAGE 4
        blk_policy = gen_cli_block_rule(cli_class_cmd,cli_blk_rule,policy_name)

        if args.push:
            print("Flag -p or --push is present. Sending config to Vision...")
            print("For a large number of subnets it may take 1-2 minutes...")
            #print("\nDetails are located in ",output_log)
            original_stdout = sys.stdout
            with open(output_log, 'w') as f:
                # Redirect stdout to the file
                sys.stdout = f
                sys.stderr = f
                v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
                for dp in cfg.DefensePro_MGMT_IP:
                    v.LockUnlockDP('lock',dp)
                    v.AddNetClass(net_class,dp)
                    v.AddBlkPolicy(blk_policy,dp)
                    v.UpdatePolicies(dp)
                    v.LockUnlockDP('unlock',dp)
            sys.stdout = original_stdout
            print("\nScript execution finished.\nDetails are located in ",output_log)
        else:
            print("Flag -p or --push is not present. Config is not pushed to device.")
    
        
if __name__ == '__main__':
    main()
