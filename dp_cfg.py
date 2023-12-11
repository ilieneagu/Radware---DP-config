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
3) Returns a dictionnary with network classes from valid subnet list
4) Returns a dictionnary with block list rules from network classes created in step 3


Program uses following arguments:

-i or --input: File containing subnets.
One subnet/line with an IP (for a host) or a subnet (/32 is accepted).
Invalid subnets will be displayed and not processed. Example: 1.1.1.1/24, 1.1.1.3/30 (not valid). Duplicate lines will be removed. Valid subnets will be saved to valid_subnets.txt.

-n or --name: Name of the network class to create.
The script will append _1, _2, etc., for each network class created.
Each class will have a maximum of 250 subnets.

-b or --blocklist: Name of the blocklist to create.
If "-n" is not used network classes will have same prefix as blocklist rule

The script will append _1, _2, etc., for each blocklist rule created.
Blocklist rule will be configured with default settings:
    Source network: from the script
    Destination network: any
    Protocol: any
    Port: any
Example command:
    python de_cfg.py -i input_file.txt -n network_class_name -b blocklist_name

if -p flag is used the config will be sent to DP

Other arguments:
-dnet "name" : deletes network classes stating whith "name"
    (name_1, name_2,etc)
    (requires -n)
-dbl "name" : deletes blocklist rule and network classes stating whith "name"
    (name_1, name_2,etc)
    (requires -b)

"""

import ipaddress
import socket
import json
import datetime
import re
import sys
import argparse
import requests
import urllib3
from requests import Session
import config as cfg

SUBNET_LIST = 'subnet_list.txt'  # stage 1 outpout file and stage 2 input file 
VALID_SUBNETS = 'VALID_SUBNETS.TXT' # STAGE 2 OUTPOUT FILE AND STAGE 3 INPUT FILE
CHUNK_SIZE = 250

urllib3.disable_warnings()


class Vision:
    """Class representing Vision/Cybercontroller obj"""

    def __init__(self, ip, username, password):
        self.ip = ip
        self.login_data = {"username": username, "password": password}
        self.base_url = "https://" + ip
        self.byip_cfg_path = "/mgmt/device/byip"
        self.sess = Session()
        self.sess.headers.update({"Content-Type": "application/json"})
        self.login()

    def login(self):
        """Login to Vision"""
        print("Login to Vision...")
        login_url = self.base_url + '/mgmt/system/user/login'

        try:
            socket.gethostbyname(cfg.VISION_IP)
        except socket.gaierror as e:
            print(f"Name resolution error: {e}."+ "\nPlease check 'config.py'")
            sys.exit(1)
        try:
            r = self.sess.post(url=login_url, json=self.login_data, verify=False)
            r.raise_for_status()
            response = r.json()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, 
                requests.exceptions.SSLError,requests.exceptions.Timeout,
                requests.exceptions.ConnectTimeout,requests.exceptions.ReadTimeout) as err:
            raise SystemExit(err) from err
        if response['status'] == 'ok':
            self.sess.headers.update({"JSESSIONID": response['jsessionid']})
            print(response) #'jsessionid'])
            banner()
            return True
        return None

    def lock_unlock_dp(self,action,dp):
        """Lock or unlock DP unit"""

        dp_lock_path = f"/mgmt/system/config/tree/device/byip/{dp}/"
        send_url = self.base_url + dp_lock_path + action
        r = self.sess.post(url=send_url, verify=False)
        banner()
        print (action.capitalize(),"DP:",dp)
        print("URL:",send_url)
        print("Status code",r.status_code,r.content)
        banner()
        return(r.status_code)
    
    def add_net_class(self,net_class,dp):
        """net_class is a dict with
            # key (used in the URL) = network_class_name/index"
            # value (used as json payload) = another dict with values (see below)
                # { 'class_name/x : {'rsBWMNetworkAddress': '198.51.154.24', 'rsBWMNetworkMask': '32'} }
        """
        dp_class_path = self.byip_cfg_path + f"/{dp}/config/rsBWMNetworkTable/"
        for net_name, json_data in net_class.items():
            print("DP: ",dp,"- Add network class...")
            send_url = self.base_url + dp_class_path + net_name
            print("URL:",send_url)
            print("Class name and index:",net_name)
            print("JSON payload:" , json_data)        
            r = self.sess.post(url=send_url, json=json_data, verify=False)
            print(self.sess.post.__name__ ,"=>return code",r.status_code,r._content)
            banner("-")
        banner()

    def add_blk_policy(self,bl_policy,dp):
        """ bl_policy is a dict with"
            # key (used in the URL) = policy_name"
            # value (used as json payload) = another dict with values (see below)
                # {'policy_name' : {'rsNewBlockListSrcNetwork': 'p2_1', 'rsNewBlockListDstNetwork': 'any'} }
        """
        dp_blk_pol_path = self.byip_cfg_path + f"/{dp}/config/rsNewBlockListTable/"
        for policy_name, json_data in bl_policy.items():
            print("DP: ",dp,"- Add Blocklist policy...")
            print(f"Policy name: {policy_name}, JSON payload: {json_data}")
            send_url = self.base_url + dp_blk_pol_path + policy_name
            print("URL:",send_url)
            r = self.sess.post(url=send_url, json=json_data, verify=False)
            print(self.sess.post.__name__  ,"=>return code",r.status_code,r.content)
            banner("-")
        banner()

    def update_policies(self,dp):
        """Update policies for a DP"""
        
        print("DP: ",dp,"- Update policy...")
        sig_list_url = self.base_url + self.byip_cfg_path + f"/{dp}/config/updatepolicies"
        print(sig_list_url)
        r = self.sess.post(url=sig_list_url, verify=False)
        print("return code",r.status_code,r.content)
        banner()

    def del_entry(self,dp,table,name):
        """ Bloklist
        # [ {"rsNewBlockListName": "block3_1", "rsNewBlockListSrcNetwork": "False_1"},
        # {"rsNewBlockListName": "block3_2", "rsNewBlockListSrcNetwork": "False_2"} ]
        # Network Class
        # # {'rsBWMNetworkName': 'any', 'rsBWMNetworkSubIndex': '0'}
        """

        if name == "block_list":
            bl_names = [item["rsNewBlockListName"] for item in table]
            for bl in bl_names:
                sig_list_url = self.base_url + \
                    self.byip_cfg_path + f"/{dp}/config/rsNewBlockListTable/"+bl
                r = self.sess.delete(url=sig_list_url, verify=False)
                print(self.sess.delete.__name__ + "-> " + sig_list_url)
                print("return code",r.status_code,".",r.content)
                banner()
        else:
            # ex: net_id = [mylist_3/1,mylist_3/2]
            net_id = [(item['rsBWMNetworkName'] + "/" + \
                        item['rsBWMNetworkSubIndex']) for item in table]
            for net in net_id:
                sig_list_url = self.base_url + \
                                self.byip_cfg_path + f"/{dp}/config/rsBWMNetworkTable/"+net
                r = self.sess.delete(url=sig_list_url, verify=False)
                print(self.sess.delete.__name__ + "-> " + sig_list_url)
                print("return code",r.status_code,".",r.content)
                banner()

    def get_table(self,dp,table,pol_name,show_full_table=0):
        """  get blocklist or network class table
        function will return a dict for blocklist
        table="block_list" or network class table="net_class"
        # dict key =  table name ;
        # dict values = another dict with key = BL rule names and value = source network names
        # 
        # block list
        # {'rsNewBlockListTable':[{'rsNewBlockListName': 'l', 'rsNewBlockListSrcNetwork': 'last4'},
        #                      {'rsNewBlockListName': 'n1_1', 'rsNewBlockListSrcNetwork': 'n1_1'}]}
        #network class
        # {"rsBWMNetworkTable": [{'rsBWMNetworkName': 'any', 'rsBWMNetworkSubIndex': '0'}, 
        #                       {'rsBWMNetworkName': '1r_3', 'rsBWMNetworkSubIndex': '2'}]}
        """

        if table == "block_list":
            tbl_dict='rsNewBlockListTable'
            tbl_item="rsNewBlockListName"
            print("DP: ",dp,"- Get Block List rules and src_network...")
            sig_list_url = self.base_url + self.byip_cfg_path + \
             f"/{dp}/config/rsNewBlockListTable?props=rsNewBlockListName,rsNewBlockListSrcNetwork"
        elif table == "net_class":
            tbl_dict="rsBWMNetworkTable"
            tbl_item="rsBWMNetworkName"            
            print("DP: ",dp,"- Get NetClasses...")
            sig_list_url = self.base_url + self.byip_cfg_path + \
                     f"/{dp}/config/rsBWMNetworkTable?props=rsBWMNetworkName,rsBWMNetworkSubIndex,rsBWMNetworkAddress,rsBWMNetworkMask"
        else:
            print("Table name required")
            sys.exit(1)    
        print(sig_list_url)
        r = self.sess.get(url=sig_list_url, verify=False)
        print(self.sess.get.__name__ ,"=>return code",r.status_code)
        list_items = json.loads(r.content)
        if show_full_table:
            banner("*")
            print("FULL ",tbl_dict,"TABLE:\n",list_items)
            banner("*")
       
        #
        # banner()
        list_name = [item for item in list_items.get(tbl_dict,"[]") \
                        if find_value(item[tbl_item],pol_name)]
        if len(list_name) :
           return list_name
        else:
            return 0


def banner(char="="):
    """ Simple banner 100 column long"""

    print(char * 100)


def get_time():
    """Time format"""

    end_time = datetime.datetime.now()
    return end_time.strftime("%Y-%m-%d %H:%M:%S")


def extract_suffix(name):
    """ Define a regular expression pattern to return "_xxx" at the end of a string
    # xxx = numbers
    """
    pattern = re.compile(r'(\w+)(_\d+$)')
    return pattern.search(name).group(2)


def find_value(find_txt,value):
    """ Define a regular expression pattern
    #  to match policy name that starts with "value" and 
    #  has "_xxx" at the end of a string
    #  xxx = numbers
    """
    pattern = r'^'+ value + r'(_\d+$)'
    matches= re.search(pattern,find_txt,re.IGNORECASE)
    if matches:
        #print(matches)
        return True
    return False

def custom_sort(item):
    """ Extract the number part after the underscore and convert it to an integer
    # Ex: 'rere_1','rere_2','rere_3'
    """

    return int(item.rsplit('_',1)[1])


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
    with open(input_file_path,mode='r',encoding='utf-8') as input_file:
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
    with open(output_file_path, mode='w',encoding='utf-8') as output_file:
        # Write the unique lines to the output file
        output_file.write("\n".join(unique_lines))

    print("Stage1: Processing",input_file_path,"to remove duplicate lines and spaces.")
    print(f"Found {duplicate_count} duplicate lines out of {total_lines} total lines.")
    print("Stage1: Results are in ",output_file_path,".")
    banner()


# STAGE2
def validate_subnets(input_file, output_file):
    """Validate subnets method"""

    print("Stage2: Processing",input_file,"to remove invalid subnets.")
    with open(input_file, mode='r',encoding='utf-8') as infile, \
        open(output_file, mode='w',encoding='utf-8') as outfile:
        count=0
        for line_number, line in enumerate(infile, start=1):
            subnet = line.strip()  # Remove leading and trailing whitespaces
            count +=1
            if '/' in subnet:
                ip_address, subnet_mask = subnet.split('/')
                try:
                    ipaddress.IPv4Address(ip_address)
                    ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=True)
                    outfile.write(f"{subnet}\n")
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                    print(f"{input_file} has an invalid subnet (line {line_number}): {subnet}")
            else:
                try:
                    ipaddress.IPv4Address(subnet)
                    outfile.write(f"{subnet}/32\n")
                except ipaddress.AddressValueError:
                    print(f"{input_file} has invalid host (line {line_number}): {subnet}")
    print(f"Stage2: processed {count} lines. Valid subnets saved to {output_file}.")
    banner()


# STAGE3
def gen_class_api(input_file_path,class_name,chunk=CHUNK_SIZE):
    """
    Process a text file with IP subnets,
    split the lines into chunks based on chunk size
    Returns a dictionnary with network classes

    Parameters:
    - input_file_path (str): Path to the input file.
    - network class dict
    - chunk_size (int): Number of lines to include in each chunk.
    Default is 250.

    """
    net_class_api={}
    key=""
    with open(input_file_path, mode='r',encoding='utf-8') as input_file:
        lines = input_file.readlines()
        for i in range(0, len(lines), chunk):
            for j, line in enumerate(lines[i:i+chunk], 1):
                split_lines = line.split('/')
                key = f'{class_name}_{i//chunk + 1}/{j}'
                value = {'rsBWMNetworkAddress':f'{split_lines[0]}',\
                        'rsBWMNetworkMask':f'{split_lines[1].strip()}'}
                net_class_api.update({key:value})
    # returns a dictionnary with network classes
    # {'net_1':'rsBWMNetworkAddress': '18.51.154.216', 'rsBWMNetworkMask': '32'})
    return net_class_api


# STAGE4
def gen_bl_api(net_class,policy_name):
    """
    Return a dictionnary with BL rule
    Parameters:
    - network class dict
    - policy name for the blocklist rule
    The rule will have default settings: 
        src: network class
        dst: any 
        direction: one way
        ports: any
        protocol: any
    """
    #  input is network class dict
    # {'net_1':'rsBWMNetworkAddress': '18.51.154.216', 'rsBWMNetworkMask': '32'})
    policy_api={}
    src_net = set()
    # extract net-class names from net class dictionnary
    class_name = set([k for k in net_class.keys()])

    # extract source net from class_name set (remove /1,/2,etc)
    # add it to source network set and thus no duplicates
    for item in class_name:
        data=item.split("/")
        src_net.add(data[0])

    # sort source network by number after rightmost "_"
    # see function "custom sort"
    # net_1,net_2 etc
    src_net_sort = sorted(src_net,key=custom_sort)

    # create policy name from source net name
    # from src_1,src_2,etc
    # to policy name : policyname_1,_2 etc
    for item in (src_net_sort):
        pol_name =policy_name+ extract_suffix(item) # add suffix to policy name
        #build json payload
        r={f'{pol_name}':{'rsNewBlockListSrcNetwork': f'{item}', 'rsNewBlockListDstNetwork': 'any'}}
        policy_api.update(r)
    # return a dict 
    # key = policy name
    # value = JSON payload to add the BL rule
    # {'policy-name_1': {'rsNewBlockListSrcNetwork': 'net2_1', 'rsNewBlockListDstNetwork': 'any'}}
    return policy_api


def main():
    """Main program"""
    description = """
    From an input file with a list of subnets, the script
    creates Network Class(es) and Blocklist rule(s) on DP
    using Vision API.
    Use "-p or (--push)" option to send the commands to the DP.

    Use -dbl to delete block list policy ; requires -b
        Policy name FORMAT: "policy-name_xx" (xx - numbers)
    THIS OPTION WILL ALSO DELETE NETWORK CLASSES WITH THE SAME PREFIX !

    Use -dnet to delete speific network classes ; requires -n
        Network class FORMAT: "network-name_xx" (xx - numbers)
    
    example: python dp_cfg.py  -b pk_bl   -dbl
        delete all blocklist policies
        and network classes with 
        prefix PK_BL (case insensitive)
            pk_bl_1,pk_bl_2,pk_bl_3,etc
    
    example: 
    python dp_cfg.py  -n pk  -dnet
        delete all network classes with name 
        pk_1,pk_2,pk_3,etc
    
    see arguments below
    """
    parser = argparse.ArgumentParser \
        (description =  description,formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument \
        ('-i', '--input', type=str, help='Input file with list of networks.')
    parser.add_argument \
        ('-n', '--network', help='Network class name. If not used, it will have same name as BL.')
    parser.add_argument \
        ('-b', '--blocklist', type=str, help='Blocklist policy that STARTS with this name.')
    parser.add_argument \
        ('-p', '--push', action="store_true", help='Push config to device.Requires -i and -b.')
    parser.add_argument \
        ('-dbl', '--delBL', action="store_true", help='Delete Blocklist rule. Requires -b')
    parser.add_argument \
        ('-dnet', '--delNet', action="store_true", help='Delete Network Class(es). Requires -n')

    # Parse the command-line arguments
    args = parser.parse_args()
    input_file = args.input
    policy_name = args.blocklist
    network_name = args.network if args.network else args.blocklist
    print("Script started at:", get_time())
    if args.delBL:
        if not policy_name:
            print("Missing blocklist policy name")
            sys.exit(1)
        v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
        print("Flag -dbl is present. Flag -dnet is ignored...")
        for dp in cfg.DefensePro_MGMT_IP:
            if v.lock_unlock_dp('lock',dp) != 200:
                print("Unable to lock DP: ",dp)
                continue
            result=v.get_table(dp,"block_list",policy_name,0)
            if result:
                print("Deleting Blocklist and Network class(es) with same prefix...")
                print("item to delete\n:",json.dumps(result,indent=1))
                v.del_entry(dp,result,"block_list")
                #delete network class with the same name if exists
                result2=v.get_table(dp,"net_class",policy_name)
                if result2:
                    print("item to delete\n:",json.dumps(result2,indent=1))
                    v.del_entry(dp,result2,"net_class")
                else:
                    print("No network classes starting with ",policy_name)
                    v.get_table(dp,"net_class",policy_name,1)
                    banner("*")
                v.update_policies(dp)
            else:
                banner("*")
                print("Blocklist policy:"+ policy_name +"_xxx not found.")
                banner("*")
                v.get_table(dp,"block_list",policy_name,1)
            v.lock_unlock_dp('unlock',dp)
        print("\nScript execution finished.\n")
    elif args.delNet:
        print("Flag -dnet is present. Deleting Network class(es)...")
        if not network_name:
            print("Missing network class name")
            sys.exit(1)
        v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
        for dp in cfg.DefensePro_MGMT_IP:
            if v.lock_unlock_dp('lock',dp) != 200:
                print("Unable to lock DP: ",dp)
                continue
            result=v.get_table(dp,"net_class",network_name)
            if result:
                print("item to delete\n:",json.dumps(result,indent=1))
                v.del_entry(dp,result,"net_class")
                v.update_policies(dp)
            else:
                banner("*")
                print("Network class:" + network_name + "_xxx not found.")
                banner("*")
                result=v.get_table(dp,"net_class",network_name,1)
            v.lock_unlock_dp('unlock',dp)
        print("\nScript execution finished.\n")
    else:
        print(f'Input file: {input_file}')
        print(f'Network class name : {network_name}')
        print(f'Policy name: {policy_name}')
        banner()
        if not policy_name:
            print("Missing blocklist policy name")
            sys.exit(1)
        v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
        # STAGE 1 - clean file, remove duplicates
        remove_duplicates(input_file, SUBNET_LIST)

        # STAGE 2 - validate subnet lists
        validate_subnets(SUBNET_LIST, VALID_SUBNETS)

        # STAGE 3 - generate network class dict
        net_class  = gen_class_api(VALID_SUBNETS,network_name)

        # STAGE 4 - blocklist policy dict
        blk_policy = gen_bl_api(net_class,policy_name)
        if args.push:
            print("Flag -p or --push is present. Sending config to Vision...")
            print("Creating 1500 classes on 2 DP takes more than 2 minutes ...")
            for dp in cfg.DefensePro_MGMT_IP:
                if v.lock_unlock_dp('lock',dp) != 200:
                    print("Unable to lock DP: ",dp)
                    continue
                v.add_net_class(net_class,dp)
                v.add_blk_policy(blk_policy,dp)
                v.update_policies(dp)
                v.lock_unlock_dp('unlock',dp)
            print("\nScript execution finished.\n")
        else:
            print("Flag -p or --push is not present. Config is not pushed to device.")
    print("Script completed at:", get_time())
if __name__ == '__main__':
    main()
