"""
Generates DP cli commands to add network classes and blocklist rules from a list of IP subnet/hosts
Pushed config to DP

Config file needed is config.py
    # Sample config.py file
    VISION_IP = "x.x.x.x"          # APSolute Vision IP or FQDN
    VISION_USER = "my_user"        # APSolute Vision username
    VISION_PASS = "my_password"    # APSolute Vision password
    DefensePro_MGMT_IP = ["172.16.1.1", "10.1.1.1"]  # DefensePro IP list in this format

================
This program has for stages:

Stages:
1) remove_duplicates - clean the data source for leading/trailling spaces and remove duplicate lines
2) validate_subnet - validates each subnet from the list
3) generate cli command for network classes from valid subnet list
4) generate cli command for block list rules from the newwork classes created in step 3
5) if -p flag is used config is sent to DP

Program uses following arguments:

-i or --input: File containing subnets.
One subnet/line with an IP (for a host) or a subnet (/32 is accepted).
Invalid subnets will be displayed and not processed. Example: 1.1.1.1/24, 1.1.1.3/30 (not valid). Duplicate lines will be removed. Valid subnets will be saved to valid_subnets.txt.

-n or --name: Name of the network class to create.
The script will append _1, _2, etc., for each network class created.
Each class will have a maximum of 250 subnets.

-b or --blocklist: Name of the blocklist to create.
The script will append _1, _2, etc., for each blocklist rule created. Blocklist rule will be configured with default settings:
    Source network: from the script
    Destination network: any
    Protocol: any
    Port: any
Example command: python de_cfg.py -i input_file.txt -n network_class_name -b blocklist_name

Save CLI Commands to Files

The above 3 arguments are ****mandatory**** ; the script will save the CLI commands into two files:

cli_class_cmd.txt - network class commands (example):
    classes modify network add net_1 1 -a 1.51.154.21 -s 32
    classes modify network add net_1 2 -a 198.51.154.2 -s 32
    ...
    classes modify network add net_1 250 -a 19.1.14.0 -s 24

cli_blk_rule.txt - block list rule to create (example):
    dp block-allow-lists blocklist table create b1_1 -sn net1_1 -dn any_ipv4 -a drop

Push Configuration to DP (Optional)

If you also use the -p or --push argument,
the configuration will be pushed to DefensePro with Vision API calls.
Details of Vision commands will be saved to output.log.

Example command:
python dp_cfg.py -i input_file.txt -n network_class_name -b blocklist_name -p
"""

import datetime
import sys
import os
import ipaddress
import argparse
from requests import Session
import requests
import config as cfg
import socket
import json
from contextlib import redirect_stdout, redirect_stderr
import urllib3
import re

urllib3.disable_warnings()


timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
subnet_list = 'subnet_list.txt'  # stage 1 outpout file and stage 2 input file 
valid_subnets = 'valid_subnets.txt'  # stage 2 outpout file and stage 3 input file
cli_class_cmd = 'cli_class_cmd.txt' # stage 3 outpout file and stage 4 input file
cli_blk_rule = 'cli_blk_rule.txt' # stage 4 output file
output_log = 'output.log'
chunk_size=3

class Vision:

    def __init__(self, ip, username, password):
        self.ip = ip
        self.login_data = {"username": username, "password": password}
        self.base_url = "https://" + ip
        self.byip_cfg_path = "/mgmt/device/byip"
        self.sess = Session()
        self.sess.headers.update({"Content-Type": "application/json"})
        self.login()

    def login(self):
        print("Login to Vision...")
        login_url = self.base_url + '/mgmt/system/user/login'

        try:       
            socket.gethostbyname(cfg.VISION_IP)
        except socket.gaierror as e:
            print(f"Name resolution error: {e}."+ F"\nPlease check 'config.py'")
            exit(1)          
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
            print(response) #'jsessionid'])
            banner()
            return(True)
        else:
            exit(1)

    def LockUnlockDP(self,action,dp):
        #lock/unlock DP
        self.DPlock_path = f"/mgmt/system/config/tree/device/byip/{dp}/"
        send_url = self.base_url + self.DPlock_path + action
        r = self.sess.post(url=send_url, verify=False)
        banner()
        print (action.capitalize(),"DP:",dp)
        print("URL:",send_url)
        print("Status code",r.status_code,r._content)
        banner()
        return(r.status_code)
    
    def AddNetClass(self,net_class,dp):
        #net_class is a dict with
            # key (used in the URL) = network_class_name/index"
            # value (used as json payload) = another dict with values (see below)
                # { 'class_name/x : {'rsBWMNetworkAddress': '198.51.154.24', 'rsBWMNetworkMask': '32'} }
        self.DPclass_path = self.byip_cfg_path + f"/{dp}/config/rsBWMNetworkTable/"
        for net_name, json_data in net_class.items():
            print("DP: ",dp,"- Add network class...")
            send_url = self.base_url + self.DPclass_path + net_name
            print("URL:",send_url)
            print("Class name and index:",net_name)
            print("JSON payload:" , json_data)        
            r = self.sess.post(url=send_url, json=json_data, verify=False)
            print("return code",r.status_code,r._content)
            banner("-")
        banner()
        return(r.status_code)

    def AddBlkPolicy(self,bl_policy,dp):
        #bl_policy is a dict with"
            # key (used in the URL) = policy_name"
            # value (used as json payload) = another dict with values (see below)
                # {'policy_name' : {'rsNewBlockListSrcNetwork': 'p2_1', 'rsNewBlockListDstNetwork': 'any'} }
        self.DPBlkPol_path = self.byip_cfg_path + f"/{dp}/config/rsNewBlockListTable/"
        for policy_name, json_data in bl_policy.items():
            print("DP: ",dp,"- Add Blocklist policy...")
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
        return(r.status_code)

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
        print("DP: ",dp,"- Update policy...")
        sig_list_url = self.base_url + self.byip_cfg_path + f"/{dp}/config/updatepolicies"
        print(sig_list_url)
        r = self.sess.post(url=sig_list_url, verify=False)
        print("return code",r.status_code,r.content)
        banner()
        
    def delEntry(self,dp,table,name):
        # [ {"rsNewBlockListName": "block3_1", "rsNewBlockListSrcNetwork": "False_1"},
        # {"rsNewBlockListName": "block3_2", "rsNewBlockListSrcNetwork": "False_2"} ]
        if name == "bl":
            bl_names = [item["rsNewBlockListName"] for item in table]
            for bl in bl_names:
                sig_list_url = self.base_url + self.byip_cfg_path + f"/{dp}/config/rsNewBlockListTable/"+bl
                r = self.sess.delete(url=sig_list_url, verify=False)
                print(self.sess.delete.__name__ + "->" + sig_list_url)
                print("return code",r.status_code,".",r.content)
                banner()
        elif "class":
            # {'rsBWMNetworkName': 'any', 'rsBWMNetworkSubIndex': '0'}
            # ex: net_id = [mylist_3/1,mylist_3/2]
            net_id = [(item['rsBWMNetworkName'] + "/" + item['rsBWMNetworkSubIndex']) for item in table]
            for net in net_id:
                sig_list_url = self.base_url + self.byip_cfg_path + f"/{dp}/config/rsBWMNetworkTable/"+net
                r = self.sess.delete(url=sig_list_url, verify=False)
                print(self.sess.delete.__name__ + "->" + sig_list_url)
                print("return code",r.status_code,".",r.content)
                banner()

    #get blocklist or network class table
    def getTable(self,dp,table,search=None):
        # function will return a dict for blocklist table="bl" or network class table="class"
        # dict key =  table name ; dict values = another dict with key = BL rule names and value = source network names
        # block list
        # {'rsNewBlockListTable': [{'rsNewBlockListName': 'l', 'rsNewBlockListSrcNetwork': 'last4'}, 
        #                          {'rsNewBlockListName': 'n1_1', 'rsNewBlockListSrcNetwork': 'n1_1'}]}
        #network class
        # {"rsBWMNetworkTable": [{'rsBWMNetworkName': 'any', 'rsBWMNetworkSubIndex': '0'}, 
        #                       {'rsBWMNetworkName': '1r_3', 'rsBWMNetworkSubIndex': '2'}]}
        if table == "bl":
            tbl_dict='rsNewBlockListTable'
            tbl_item="rsNewBlockListName"
            print("DP: ",dp,"- Get Block List rules and src_network...")
            sig_list_url = self.base_url + self.byip_cfg_path + \
                            f"/{dp}/config/rsNewBlockListTable?props=rsNewBlockListName,rsNewBlockListSrcNetwork"
        elif table == "class":
            tbl_dict="rsBWMNetworkTable"
            tbl_item="rsBWMNetworkName"            
            print("DP: ",dp,"- Get NetClasses...")
            sig_list_url = self.base_url + self.byip_cfg_path + \
                     f"/{dp}/config/rsBWMNetworkTable?props=rsBWMNetworkName,rsBWMNetworkSubIndex,rsBWMNetworkAddress,rsBWMNetworkMask"
        else:
            print("Table name required")
            exit(1)    
        print(sig_list_url)
        r = self.sess.get(url=sig_list_url, verify=False)
        list_items = json.loads(r.content)
        print("return code",r.status_code)
        banner()
        if search:
            list_name = [item for item in list_items.get(tbl_dict,"[]") \
                            if item[tbl_item].startswith(search)]
            return list_name
        else:
            list_name = [item for item in list_items.get(tbl_dict,"[]") ]
            return list_name

    #CYBERCONTROLLER ONLY
    def delTable(self,dp,table,key_name):
        if key_name == 'rsNewBlockListName' :
            print("DP: ",dp,"- Delete Blocklist rules...")
        elif key_name == 'rsBWMNetworkTable' :
            print("DP: ",dp,"- Delete Network classes...")
        print(f'JSON payload: {table}')
        sig_list_url = self.base_url + f'/mgmt/device/byip/{dp}/config/deletetablerows'
        print(sig_list_url)
        json_payload = table
        r = self.sess.delete(url=sig_list_url, json=json_payload ,verify=False)
        print("return code",r.status_code,r.content)
        banner()        

def extract_suffix(name):
    # Define a regular expression pattern to match "_xxx" at the end of a string
    # xxx = numbers
    pattern = re.compile(r'_\d+$')
    return pattern.search(name).group(0)

def question(question):
    # Example usage
    # user_agrees = ask_yes_no_question("Do you want to proceed?")
    # if user_agrees:
    #     print("Great! Proceeding...")
    # else:
    #     print("Okay, stopping.")
    while True:
        user_input = input(f"{question} (yes/no): ").strip().lower()
        
        if user_input == 'yes':
            return True
        elif user_input == 'no':
            return False
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

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
    print(f"Output file '{output_file_path}' has been created.\nIt contains network classes to be added.")
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
                name = policy_name+ extract_suffix(bk)
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
    
    parser.add_argument('-a', '--auto',action="store_true", help='Used for automation. No user prompt.')
    parser.add_argument('-i', '--input', type=str, help='Input file with list of networks.')
    parser.add_argument('-n', '--network', help='Name of the Network class. If not used it will have same name as blocklist.')
    parser.add_argument('-b', '--blocklist', type=str, help='Blocklist policy that STARTS with this name.')
    parser.add_argument('-p', '--push', action="store_true", help='Push config to device and update policy.Requires -i and -b.')
    parser.add_argument('-sbl', '--showBL', action="store_true", help='Show (all-> if -b not used) blocklist names and source network.')
    parser.add_argument('-snet', '--showNet', action="store_true", help='Show (all-> if -n not used) Network Classes names and index.')
    parser.add_argument('-dbl', '--delBL', action="store_true", help='Delete Blocklist rule starting with a value. Requires -b')
    parser.add_argument('-dnet', '--delNet', action="store_true", help='Delete Network Class(es) starting with a value. Requires -n')

    # Parse the command-line arguments
    args = parser.parse_args()
    
    input_file = args.input
    policy_name = args.blocklist
    network_name = args.network if args.network else args.blocklist
    
    v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
    
    if args.showBL:
        for dp in cfg.DefensePro_MGMT_IP:
            if args.blocklist:
                result=v.getTable(dp,"bl",policy_name)
            else:
                result=v.getTable(dp,"bl")
            if (result):
                if policy_name:
                    print("DP:",dp,"Blocklist rules STARTING with: <",policy_name,">\n",json.dumps(result,indent=1))
                else:
                    print("DP:",dp,"All blocklist rules.\n",json.dumps(result,indent=1))
            else:
                print("DP:",dp,"Blocklist rules starting with: <",policy_name,"> not in place.")
    elif args.showNet:
        for dp in cfg.DefensePro_MGMT_IP:
            if args.network:
                result=v.getTable(dp,"class",network_name)
            else:
                result=v.getTable(dp,"class")
            if (result):
                if network_name:
                    print("DP:",dp,"Network Classes STARTING with : <",network_name,">\n",json.dumps(result,indent=1))
                else:
                    print("DP:",dp,"All Network classes.\n",json.dumps(result,indent=1))
            else:
                print("DP:",dp,"Network classes: <",network_name,"> - not in place.")    
    elif args.delBL:
        print("Flag -dbl is present. Deleting BL rule...")
        if args.blocklist is  None:
            print("Please specify blocklist to delete with <<-b>> ")
        else:
            for dp in cfg.DefensePro_MGMT_IP:
                if v.LockUnlockDP('lock',dp) != 200:
                    print("Unable to lock DP: ",dp)
                    continue
                result=v.getTable(dp,"bl",policy_name)
                if not result:
                    print("DP:",dp,"Blocklist rules starting with: <",policy_name,"> - not in place.")
                else:
                    print(json.dumps(result,indent=2))
                    if args.auto:
                            v.delEntry(dp,result,"bl")
                            v.UpdatePolicies(dp)
                            v.LockUnlockDP('unlock',dp)
                            print("\nScript execution finished.\n")
                    elif question("Delete ???"):
                        with open(output_log, 'w') as output_file:
                            with redirect_stdout(output_file), redirect_stderr(output_file):
                                v.delEntry(dp,result,"bl")
                                v.UpdatePolicies(dp)
                                v.LockUnlockDP('unlock',dp)
                        print("\nScript execution finished.\nDetails are located in ",output_log)
    elif args.delNet:
        print("Flag -dnet is present. Deleting Network class(es)...")
        if args.network is  None:
            print("Please specify Network class to delete  with <<-n>> ")
        else:
            for dp in cfg.DefensePro_MGMT_IP:
                if v.LockUnlockDP('lock',dp) != 200:
                    print("Unable to lock DP: ",dp)
                    continue
                result=v.getTable(dp,"class",network_name)
                if not (result):
                    print("DP:",dp,"Network classes starting with: <",network_name,"> - not in place.")
                else:
                    print(json.dumps(result,indent=2))
                    if args.auto:
                            v.delEntry(dp,result,"class")
                            v.UpdatePolicies(dp)
                            v.LockUnlockDP('unlock',dp)
                            print("\nScript execution finished.\n")
                    elif question("Delete???"):
                        with open(output_log, 'w') as output_file:
                            with redirect_stdout(output_file), redirect_stderr(output_file):
                                v.delEntry(dp,result,"class")
                                v.UpdatePolicies(dp)
                                v.LockUnlockDP('unlock',dp)
                            print("\nScript execution finished.\nDetails are located in ",output_log)
    elif not (args.blocklist):
        parser.print_help()
        banner()
        parser.error("Argument (blocklist) is required. Argument (input) is required to add new rules.")
    else:        
        if not (args.input):
            banner()
            parser.error("Arguments(input,blocklist) are required.")
        elif not os.path.exists(input_file):
            print(f"Error: Input file '{input_file}' not found.")
            sys.exit(1)
        else:
                print(f'Input file: {input_file}')
                print(f'Network class name : {network_name}')
                print(f'Policy name: {policy_name}')    
                banner()

                # STAGE 1 - clean file, remove duplicates
                remove_duplicates(input_file, subnet_list)

                # STAGE 2 - validate subnet lists
                validate_subnets(subnet_list, valid_subnets)

                # STAGE 3 - generate cli commands for network class                 
                net_class  = gen_cli_class_cmd(valid_subnets,cli_class_cmd,network_name)

                # STAGE 4 - generate cli commands for blocklist policy
                blk_policy = gen_cli_block_rule(cli_class_cmd,cli_blk_rule,policy_name)
                
                if args.push:
                    print("Flag -p or --push is present. Sending config to Vision...")
                    print("Creating 1500 classes on 2 DP takes more than 4 minutes ...")
                    print("To see the progress open a 2nd terminal and run 'tail -f output.log'")
                    #print("\nDetails are located in ",output_log)
                    with open(output_log, 'w') as output_file:
                        #with redirect_stdout(output_file), redirect_stderr(output_file):                    
                        for dp in cfg.DefensePro_MGMT_IP:
                            if v.LockUnlockDP('lock',dp) != 200:
                                print("Unable to lock DP: ",dp)
                                continue
                            else:
                                v.AddNetClass(net_class,dp)
                                v.AddBlkPolicy(blk_policy,dp)
                                v.UpdatePolicies(dp)
                                v.LockUnlockDP('unlock',dp)
                    print("\nScript execution finished.\nDetails are located in ",output_log)
                else:
                    print("Flag -p or --push is not present. Config is not pushed to device.")

if __name__ == '__main__':
    main()
