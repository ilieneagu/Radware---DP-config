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
Invalid subnets will be displayed and not processed. Example: 1.1.1.1/24, 1.1.1.3/30 (not valid).
Duplicate lines will be removed. Valid subnets will be saved to valid_subnets.txt.

Each Network class will have a maximum of 250 subnets.

-b or --blocklist: Name of the blocklist to create.
The script will append _1, _2, etc., for each blocklist rule created.
The script will create network classes with the same name as BL policy name

Blocklist rule will be configured with default settings:
    Source network: from the script
    Destination network: any
    Protocol: any
    Port: any
Example command:
    python de_cfg.py -i input_file.txt -b blocklist_name => create Net_class and BL policy
    python de_cfg.py -b blocklist_name -dbl              => remove BL policy and Net_class

"""
import time
import ipaddress
import socket
import json
import datetime
import re
import sys
import os
import argparse
import requests
import urllib3
from requests import Session
import config as cfg

SUBNET_LIST = 'subnet_list.txt'  # stage 1 outpout file and stage 2 input file 
VALID_SUBNETS = 'VALID_SUBNETS.TXT' # STAGE 2 OUTPOUT FILE AND STAGE 3 INPUT FILE
CHUNK_SIZE = 250

class Vision:
    """Class representing Vision obj"""
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
        print("Status code",r.status_code,r.text.replace('\n',''))
        banner()
        if r.status_code == 200:
            return True
        return False

    def add_net_class(self,net_class,dp):
        """
        net_class is a dict with
        key (used in the URL) = network_class_name/index"
        value (used as json payload) = another dict with values (see below)
        { 'class_name/x : {'rsBWMNetworkAddress': '198.51.154.24', 'rsBWMNetworkMask': '32'} }
        """
        dp_class_path = self.byip_cfg_path + f"/{dp}/config/rsBWMNetworkTable/"
        for net_name, json_data in net_class.items():
            print("DP: ",dp,"- Add network class...")
            send_url = self.base_url + dp_class_path + net_name
            print("URL:",send_url)
            print("Class name and index:",net_name)
            print("JSON payload:" , json_data)        
            r = self.sess.post(url=send_url, json=json_data, verify=False)
            print(self.sess.post.__name__ ,"=>return code",r.status_code,r.text)
            banner("-")
        banner()

    def add_blk_policy(self,bl_policy,dp):
        """ bl_policy is a dict with"
        # key (used in the URL) = policy_name"
        # value (used as json payload) = another dict with values (see below)
        # {'policy_name' : {'rsNewBlockListSrcNetwork': 'p2_1', 'rsNewBlockListDstNetwork': 'any'}}
        """
        dp_blk_pol_path = self.byip_cfg_path + f"/{dp}/config/rsNewBlockListTable/"
        for policy_name, json_data in bl_policy.items():
            print("DP: ",dp,"- Add Blocklist policy...")
            print(f"Policy name: {policy_name}, JSON payload: {json_data}")
            send_url = self.base_url + dp_blk_pol_path + policy_name
            print("URL:",send_url)
            r = self.sess.post(url=send_url, json=json_data, verify=False)
            print(self.sess.post.__name__  ,"=>return code",r.status_code,r.text)
            banner("-")
        banner()

    def update_policies(self,dp):
        """Update policies for a DP"""
        print("DP: ",dp,"- Update policy...")
        sig_list_url = self.base_url + self.byip_cfg_path + f"/{dp}/config/updatepolicies"
        print(sig_list_url)
        r = self.sess.post(url=sig_list_url, verify=False)
        print("return code",r.status_code,r.text.replace('\n',''))
        banner()

    def del_entry(self,dp,table,name):
        """
        Bloklist
        [ {"rsNewBlockListName": "block3_1", "rsNewBlockListSrcNetwork": "False_1"},
        {"rsNewBlockListName": "block3_2", "rsNewBlockListSrcNetwork": "False_2"} ]
        Network Class
        [{'rsBWMNetworkName': 'any', 'rsBWMNetworkSubIndex': '0'}]
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
            net_id = [(item['rsBWMNetworkName'] + "/" +\
                        item['rsBWMNetworkSubIndex']) for item in table]
            for net in net_id:
                sig_list_url = self.base_url + \
                                self.byip_cfg_path + f"/{dp}/config/rsBWMNetworkTable/"+net
                r = self.sess.delete(url=sig_list_url, verify=False)
                print(self.sess.delete.__name__ + "-> " + sig_list_url)
                print("return code",r.status_code,".",r.content.decode("utf-8"))
                banner()

    def get_table(self,dp,table,pol_name,show_full_table=0):
        """
        get blocklist or network class table
        function will return a dict for blocklist
        table="block_list" or network class table="net_class"
        dict key =  table name ;
        dict values = another dict with key = BL rule names and value = source network names
        block list:
        {'rsNewBlockListTable':[{'rsNewBlockListName': 'l', 'rsNewBlockListSrcNetwork': 'last4'},
                              {'rsNewBlockListName': 'n1_1', 'rsNewBlockListSrcNetwork': 'n1_1'}]}
        network class:
         {"rsBWMNetworkTable": [{'rsBWMNetworkName': 'any', 'rsBWMNetworkSubIndex': '0'}, 
                               {'rsBWMNetworkName': '1r_3', 'rsBWMNetworkSubIndex': '2'}]}
        """
        if table == "block_list":
            tbl_dict='rsNewBlockListTable'
            tbl_item="rsNewBlockListName"
            print("DP: ",dp,"- Get Block List rules and src_network...")
            sig_list_url = self.base_url + self.byip_cfg_path + \
             f"/{dp}/config/rsNewBlockListTable?props="+\
                "rsNewBlockListName,rsNewBlockListSrcNetwork,rsNewBlockListDstNetwork"
        elif table == "net_class":
            tbl_dict="rsBWMNetworkTable"
            tbl_item="rsBWMNetworkName"
            print("DP: ",dp,"- Get NetClasses...")
            sig_list_url = self.base_url + self.byip_cfg_path + \
               f"/{dp}/config/rsBWMNetworkTable?props="+\
                "rsBWMNetworkName,rsBWMNetworkSubIndex,rsBWMNetworkAddress,rsBWMNetworkMask"
        print(sig_list_url)
        r = self.sess.get(url=sig_list_url, verify=False)
        print(self.sess.get.__name__ ,"=>return code",r.status_code)
        list_items = json.loads(r.content)
        if show_full_table == 1:
            banner("*")
            print("FULL ",tbl_dict,"TABLE:\n",list_items)
            banner("*")
        elif show_full_table == 2:
            list_name = list(item for item in list_items.get(tbl_dict,"[]"))
            return list_name
        else:
            #Find table with required policy_name
            list_name = [item for item in list_items.get(tbl_dict,"[]") \
                        if find_value(item[tbl_item],pol_name)]
            if len(list_name):
                return list_name
        return False

def find_dicts_with_value(key1, key2, value, dict_list):
    """
    Find values whithin a list of dict
    key1,2 : dict key to look for 
    value to search : search for value with _xxx suffix
    (see find_value method)
    dict_list: list of dict (blocklist or net class)
    dict example:
    [
    {'rsNewBlockListName': 'i99_1', 'rsNewBlockListSrcNetwork': 'ip0_1',
                                 'rsNewBlockListDstNetwork': 'ipp2_1'},
    {'rsNewBlockListName': 'ip1_1', 'rsNewBlockListSrcNetwork': 'ip1_1',
                                     'rsNewBlockListDstNetwork': 'any'}
    ]    
    """
    matching_dict1 = [d for d in dict_list if key1 in d and find_value(d[key1],value)]
    matching_dict2 = [d for d in dict_list if key2 in d and find_value(d[key2],value)]
    return matching_dict1+matching_dict2

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
        return True
    return False

def suffix_sort(item):
    """ Extract the number part after the underscore and convert it to an integer
    # Ex: 'rere_1','rere_2','rere_3'
    """
    return int(item.rsplit('_',1)[1])

def check_single_entry_and_match(data):
    """ Check if the list has only one entry """
    if len(data) == 1:
        entry = data[0]
        # Check if 'rsNewBlockListName' is equal to 'rsNewBlockListSrcNetwork'
        if entry.get('rsNewBlockListName') == entry.get('rsNewBlockListSrcNetwork'):
            return True
    return False

def net_class_to_delete(blk_list,net_list):
    """
    Check data for used SRC or DST network name from a list of network names 
    exept if block list name = net-list name
    blk_list = [{'rsNewBlockListName': 'bad_1', 'rsNewBlockListSrcNetwork': 'bad_1', 
            'rsNewBlockListDstNetwork': 'any'}, {'rsNewBlockListName': 'bad_12', 
            'rsNewBlockListSrcNetwork': 'bad_2', 'rsNewBlockListDstNetwork': 'any'}]
    returns a list of net names that are not used of in blocklist
    """
    net_class=net_list[:]
    for value in net_list:
        for item in (blk_list):
            #print(item)
            if value == item.get("rsNewBlockListSrcNetwork") or \
                  value == item.get("rsNewBlockListDstNetwork"):
                if value != item.get("rsNewBlockListName"):
                    net_class.remove(value)
    return net_class

def list_net_class(blk_tbl):
    """
    Return a list with SRC and DST network names from this dict list except when network = any
    [{'rsNewBlockListName': 'ipiep_1', 'rsNewBlockListSrcNetwork': 'ipip_1',
      'rsNewBlockListDstNetwork': 'ipip_2'}, {'rsNewBlockListName': 'iepip_2', 
      'rsNewBlockListSrcNetwork': 'ipip_2', 'rsNewBlockListDstNetwork': 'any_ipv4'}]
    """
    net_class_list=[]
    for _ in blk_tbl:
        if _.get('rsNewBlockListSrcNetwork') != "any" and \
              _.get('rsNewBlockListSrcNetwork') != "any_ipv4":
            net_class_list.append(_.get('rsNewBlockListSrcNetwork'))
        if _.get('rsNewBlockListDstNetwork') != "any" and \
            _.get('rsNewBlockListDstNetwork') != "any_ipv4":
            net_class_list.append(_.get('rsNewBlockListDstNetwork'))
    return net_class_list

def get_net_class(class_list,net_tbl):
    """
    extract Net class from a netclass table based on a list
      of net classes names
    """
    result=[]
    for i in net_tbl:
        for _ in class_list:
            if _ == i.get('rsBWMNetworkName'):
                #print(i.get('rsBWMNetworkName'),i.get('rsBWMNetworkSubIndex'))
                result += [{'rsBWMNetworkName':i.get('rsBWMNetworkName'),\
                            'rsBWMNetworkSubIndex':i.get('rsBWMNetworkSubIndex')}]
    return result

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
    try :
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
    except FileNotFoundError:
        print("File not found:",input_file_path)
        sys.exit(1)

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
def gen_class_dict(input_file_path,class_name,chunk=CHUNK_SIZE):
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
    net_class_tbl={}
    key=""
    with open(input_file_path, mode='r',encoding='utf-8') as input_file:
        lines = input_file.readlines()
        for i in range(0, len(lines), chunk):
            for j, line in enumerate(lines[i:i+chunk], 1):
                split_lines = line.split('/')
                key = f'{class_name}_{i//chunk + 1}/{j}'
                value = {'rsBWMNetworkAddress':f'{split_lines[0]}',\
                        'rsBWMNetworkMask':f'{split_lines[1].strip()}'}
                net_class_tbl.update({key:value})
    # returns a dictionnary with network classes
    # {'net_1':'rsBWMNetworkAddress': '18.51.154.216', 'rsBWMNetworkMask': '32'}
    return net_class_tbl


# STAGE4
def gen_bl_dict(net_class,policy_name):
    """
    Return a dictionnary with BL rule:
    input: a network class dict
    The rule will have default settings: 
        src: network class
        dst: any 
        direction: one way
        ports: any
        protocol: any
    """
    # input is network class dict
    # {'net_cls_1/1': {'rsBWMNetworkAddress': '1.51.154.21', 'rsBWMNetworkMask': '32'}}
    policy_tbl={}
    src_net = set()
    # extract net_class_name from class dict and remove index (/1, /2, etc)
    # add it to source network SET to elimitate duplicates
    for item in net_class.keys():
        src_net.add(item.split("/")[0])
    # sort source network by number after rightmost "_"
    # see function "custom sort"
    # net_1,net_2 etc
    src_net_sort = sorted(src_net,key=suffix_sort)
    # create policy name from source net name
    # from src_1,src_2,etc
    # to policy name : policyname_1,_2 etc
    for item in (src_net_sort):
        pol_name = policy_name + extract_suffix(item) # add suffix to policy name
        #build json payload
        r={f'{pol_name}':{'rsNewBlockListSrcNetwork': f'{item}', 'rsNewBlockListDstNetwork': 'any'}}
        policy_tbl.update(r)
    # return a dict
    # key = policy name
    # value = JSON payload to add the BL rule
    # {'policy-name_1': {'rsNewBlockListSrcNetwork': 'net2_1', 'rsNewBlockListDstNetwork': 'any'}}
    return policy_tbl

def validate_input(input_file,policy_name):
    """
    Validate input before processing request
    """
    if not policy_name:
        print("Missing blocklist policy name... (-b <<policy_name>>)\n")
        return False
    if not input_file:
        print("Missing input file...")
        return False
    if not os.path.exists(input_file):
        print(f"The file {input_file} does not exist.")
        return False
    return True

def main():
    """Main program"""
    description = """
    From an input file with a list of subnets, the script
    creates Network Class(es) and Blocklist rule(s) on DP
    using Vision API.

    Use -dbl <policy_name_prefix> to delete block list policy; requires -b

    Script will look for policies with name: "policy_name_xx" (xx - numbers)
    THIS OPTION WILL ALSO DELETE NETWORK CLASSES 
    STARTING WITH THE SAME PREFIX !

    example: python dp_cfg.py  -b pk_bl   -dbl
        delete all blocklist policies
        and network classes with 
        prefix PK_BL (case insensitive)
            pk_bl_1,pk_bl_2,pk_bl_3,etc
        
    see arguments below
    """
    parser = argparse.ArgumentParser \
        (description =  description,formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument \
        ('-i', '--input', type=str, help='Input file with list of networks.')
    parser.add_argument \
        ('-b', '--blocklist', type=str, help='Blocklist policy that STARTS with this name.')
    parser.add_argument \
      ('-dbl', '--delBL', action="store_true", help='Delete BL rule and its net class.Requires -b')

    # Parse the command-line arguments
    args = parser.parse_args()
    print(args)
    input_file = args.input
    policy_name = args.blocklist
    network_name = args.blocklist
    print("Script started at:", get_time())

    start_time=time.time()
   
    if not validate_input(input_file,policy_name):
        parser.print_help()
        sys.exit(1)

    urllib3.disable_warnings()
    v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)

    if args.delBL:
        print("Flag -dbl is present.")
        for dp in cfg.DefensePro_MGMT_IP:
            if not v.lock_unlock_dp('lock',dp):
                print("Unable to lock DP: ",dp)
                continue
            bl_table=v.get_table(dp,"block_list",policy_name,0)
            bl_full= v.get_table(dp,"block_list",policy_name,2)
            net_table= v.get_table(dp,"net_class",network_name,0)
            if bl_table:
                print("Deleting Blocklist and Network class(es) with same prefix...")
                print("item to delete\n:",json.dumps(bl_table,indent=1))
                v.del_entry(dp,bl_table,"block_list")
                print("Delete Network classes...")
                v.del_entry(dp,net_table,"net_class")
                v.update_policies(dp)
            else:
                banner("*")
                if bl_full:
                    print("Blocklist policy:"+ policy_name +"_xxx not found.")
                    banner("*")
                    print(json.dumps(bl_full,indent=2))
                else:
                    print("No blocklist policies defined")
            v.lock_unlock_dp('unlock',dp)
        print("\nScript execution finished.\n")
    else:
        print(f'Input file: {input_file}')
        print(f'Network class name : {network_name}')
        print(f'Policy name: {policy_name}')
        banner()

        # STAGE 1 - clean file, remove duplicates
        remove_duplicates(input_file, SUBNET_LIST)

        # STAGE 2 - validate subnet lists
        validate_subnets(SUBNET_LIST, VALID_SUBNETS)

        # STAGE 3 - generate network class dict
        net_class  = gen_class_dict(VALID_SUBNETS,network_name)

        # STAGE 4 - blocklist policy dict
        blk_policy = gen_bl_dict(net_class,policy_name)
        print("Flag -p or --push is present. Sending config to Vision...")
        for dp in cfg.DefensePro_MGMT_IP:
            if not v.lock_unlock_dp('lock',dp):
                print("Unable to lock DP: ",dp)
                continue
            v.add_net_class(net_class,dp)
            v.add_blk_policy(blk_policy,dp)
            v.update_policies(dp)
            v.lock_unlock_dp('unlock',dp)
        print("\nScript execution finished.\n")
    print("Script completed at:", get_time())
    end_time=time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds ({ float(elapsed_time) / 60:.2f} min)")

if __name__ == '__main__':
    main()
