# Radware - DP config
Configuration of DefensePro(DP) devices with Vision API calls

This program allows configuration of DP device with network classes and block list policies from a list of subnets.
After reading subnets from the file, CLI commands will be generated; the configuration can also be pushed to the DP.

## Prerequisites:
Tested with Python 3.9.
Please see requirements.txt for required packages

You can install the required dependencies using the following command:\
`python -m pip install -r requirements.txt` 

## How to Run the Script

1.  **Modify `config.py`**
    
You need to modify `config.py` for your environment. Update the following parameters:

`VISION_IP = "x.x.x.x"          # APSolute Vision IP or FQDN`\
`VISION_USER = "my_user"        # APSolute Vision username`\
`VISION_PASS = "my_password"    # APSolute Vision password`\
`DefensePro_MGMT_IP = ["172.16.1.1", "10.1.1.1"]  # DefensePro IP list in this format`
    
2.  **Run `de_cfg.py` with the following arguments:**
    
    -   `-i` or `--input`: File containing subnets. One subnet/line with an IP (for a host) or a subnet (/32 is accepted). Invalid subnets will be displayed and not processed. Example: `1.1.1.1/24`, `1.1.1.3/30` (not valid). Duplicate lines will be removed. Valid subnets will be saved to **`valid_subnets.txt`**.
        
    -   `-n` or `--name`: Name of the network class to create. The script will append `_1`, `_2`, etc., for each network class created.\ Each class will have a maximum of 250 subnets.
        
    -   `-b` or `--blocklist`: Name of the blocklist to create. The script will append `_1`, `_2`, etc., for each blocklist rule created. Blocklist rule will be configured with default settings:        
        -   Source network: from the script
        -   Destination network: any
        -   Protocol: any
        -   Port: any
    
Example command:
`python de_cfg.py -i input_file.txt -n network_class_name -b blocklist_name` 
    
3.  **Save CLI Commands to Files**
    
    The above 3 arguments are **<ins>mandatory</ins>** ; the script will save the CLI commands into two files:
    
    -   **`cli_class_cmd.txt`** - network class commands (example):
        
        `classes modify network add net_1 1 -a 1.51.154.21 -s 32 \
        classes modify network add net_1 2 -a 198.51.154.2 -s 32 \
        ...
        classes modify network add net_1 250 -a 19.1.14.0 -s 24` 
        
    -   **`cli_blk_rule.txt`** - block list rule to create (example):
        
        `dp block-allow-lists blocklist table create b1_1 -sn net1_1 -dn any_ipv4 -a drop` 
        
4.  **Push Configuration to DP (Optional)**
    
    If you also use the `-p` or `--push` argument, the configuration will be pushed to DefensePro with Vision API calls.
    Details of Vision commands will be saved to **`output.log`**.
    
    Example command:    
    `python dp_cfg.py -i input_file.txt -n network_class_name -b blocklist_name -p`
