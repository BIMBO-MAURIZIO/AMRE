import subprocess
import sys
import os



###################################################################################################################################
#method in order to create firewall rules using blacklisted ips
def ip_block_rules(mal_ip_list, OS):
    #checks if there is at list 1 ip in the list
    if mal_ip_list:
        mal_ip_string_filtered = ""
        file_path = "firewall/firewall_rules.ps1"
        #reads ips from file stripping \n characters
        with open('other/whitelisted_ip.txt', 'r') as whitelisted_ip_file:
            whitelisted_ips = whitelisted_ip_file.read().splitlines()
        
        for mal_ip in mal_ip_list:
            if mal_ip not in whitelisted_ips:
                mal_ip_string_filtered = mal_ip_string_filtered + mal_ip + ","

        mal_ip_string_filtered = mal_ip_string_filtered[:-1]

        if OS == 'windows':     
            p = subprocess.run(["powershell.exe", "-File", file_path, mal_ip_string_filtered])
            #if return code differ from 0 it means thatthe script comes to an error  
            if p.returncode != 0:
                sys.exit("failed to set ip-blocking firewall rules")
            else:
                print("")
                print("firewall rules added successfully")
                print("")

        elif OS == 'linux':
            give_permissions = subprocess.run(["chmod", "+x", "firewall/firewall_rules.sh"])
            if give_permissions.returncode != 0:
                sys.exit("not possible to give permissions to the script")
            p = subprocess.run(["firewall/firewall_rules.sh", mal_ip_string_filtered])
            if p.returncode != 0:
                sys.exit("failed to set ip-blocking firewall rules")
            else:
                print("")
                print("firewall rules added successfully")
                print("")
        else:
            print("")
            print("the malicious ip list is empty")
            print("")
    return


###################################################################################################################################
# method in order to convert firewall rules in the middleware syntax
def to_another_syntax(OS, blacklisted_ip):
    rules = open('firewall/rules.txt', 'w')
    if OS == 'windows':
        rules = open('firewall/rules.txt', 'w')
        rules.writelines(["*filter\n", ":INPUT ACCEPT [0:0]\n", ":FORWARD ACCEPT [0:0]\n", ":OUTPUT ACCEPT [0:0]\n"])
        for ip in blacklisted_ip:
            fp = "-A INPUT -s "
            sp = "/32 -j DROP"
            policy = fp + str(ip) + sp + "\n"
            rules.write(policy)
        for ip in blacklisted_ip:
            fp = "-A OUTPUT -s "
            sp = "/32 -j DROP"
            policy = fp + str(ip) + sp + "\n"
            rules.write(policy)
        rules.write("COMMIT\n")
        rules.write("\n")
        rules.writelines(["*nat\n", ":PREROUTING ACCEPT [0:0]\n", ":INPUT ACCEPT [0:0]\n", ":OUTPUT ACCEPT [0:0]\n", ":POSTROUTING ACCEPT [0:0]\n", "COMMIT\n"])
        wd = os.getcwd()
        rules.close()
        docker_cmd = subprocess.run("docker run --rm -ti -v \""+ wd +"\":/mnt wert310/fws -m cli firewall/rules_conversion.fws > firewall/compiled.txt", capture_output=True)
        if docker_cmd.returncode != 0:
                sys.exit("problems in the rule syntax conversion procedure")
        output = docker_cmd.stdout.decode()
        dec_ref = open("decompiled.txt", "w")
        dec_ref.write(output)
        dec_ref.close()
        
    elif OS == "linux":
        write_policies = subprocess.run(["iptables-save", "-f", "firewall/rules.txt"])
        if write_policies.returncode != 0:
                sys.exit("it wasn't possible to write policies on rules.txt file")
        wd = os.getcwd()
        docker_cmd = subprocess.run("docker run --rm -ti -v \""+ wd +"\":/mnt wert310/fws -m cli firewall/rules_conversion.fws > firewall/decompiled.txt", shell=True)
        if docker_cmd.returncode != 0:
                sys.exit("problems in the rule syntax conversion procedure")
    
    return


###################################################################################################################################
# method in order to create yara rules from a dict containing pairs of hashes-filesizes
def yara_rules_building(hash_filesize_dict):
    for my_hash in hash_filesize_dict:
        filesize = hash_filesize_dict.get(my_hash)
        filename_no_ext = "dumped_file_hash_" + my_hash[:5] 
        filename = filename_no_ext + ".yar"
        filepath = "yara_rules/" + filename
        f = open(filepath, "w")
        frl = "import \"hash\"\n"
        sl = "rule "+filename_no_ext+" {\n"
        tl = "\tmeta:\n"
        fol = "\t\tauthor = \"AMRE\"\n"
        fil = "\tcondition:\n"
        hash_condition = "\t\tfilesize == " + str(filesize) + " and " + "hash.sha256(0, filesize) == \"" + my_hash + "\"\n"
        sel = "}\n"
    
        f.writelines([frl, sl, tl, fol, fil, hash_condition, sel])
        f.close()



###################################################################################################################################
# method in order to autmatically manage registry operations performed by the malware
def registry_operations(reg_op_dict, control_flag):
    reg_operations_filepath = "registry/reg_operations.txt"
    if control_flag == 0:
        f = open(reg_operations_filepath, "w", encoding="utf-8")
    else:
        f = open(reg_operations_filepath, "a", encoding="utf-8")
    if(len(reg_op_dict) != 0):
        if control_flag == 0:
            f.write("\n")
            f.write("-------------------------REGISTRY OPERATIONS FOR THE ORIGINALLY SUBMITTED SAMPLE-------------------------\n")
        elif control_flag == 1:
            f.write("\n")
            f.write("-------------------------REGISTRY OPERATIONS FOR OTHER SAMPLES BELONGING TO THE SAME FAMILY OF THE ONE SUBMITTED-------------------------\n")
    else:
        return
    for el in reg_op_dict:
        reg_div = el.split("\t")
        op = reg_div[0].strip()
        reg = reg_div[1]
        values_list = reg_op_dict[el]
        score = values_list[0]
        name = values_list[1]
        #branch taken by the original sample
        if op == "Key created" and control_flag == 0:
            #key created by malware sample ar deleted only if their score is higher than 6
            if score >= 6:
                #modify the key name in order to be a valid argument for the powershell script
                known_reg = 1
                if("\\REGISTRY\\MACHINE" in reg):
                    arg = reg.replace("\\REGISTRY\\MACHINE", "registry::HKLM")
                elif("\\REGISTRY\\USER" in reg):
                    arg = reg.replace("\\REGISTRY\\USER", "registry::HKU")
                else:
                    known_reg = 0
                if known_reg == 1:
                    p = subprocess.run(["powershell.exe", "-Command", "Remove-Item", "-Path " + arg, "-Force"])
                    #if return code differ from 0 it means that the script comes to an error
                    if p.returncode != 0:
                        sys.exit("failed to delete registry key")
                    else:
                        f.write("registry key " + reg + " deleted successfully\n")
                else:
                    print("not supported register found, refer to the dev:")
                    print(reg)

        #branch taken by malware coming from data augmentation
        elif op == "Key created" and control_flag == 1:
            f.write("\n")
            f.write("key created: " + reg + "\n")
            f.write("description: " + name + "\n")
            f.write("score: " + str(score) + "\n")
        elif op == "Key opened" or op == "Key value queried":
            f.write("\n")
            f.write("key opened: " + reg + "\n")
            f.write("description: " + name + "\n")
            f.write("score: " + str(score) + "\n")
        elif "Set value" in op:
            f.write("\n")
            f.write("Set value: " + reg + "\n")
            f.write("description: " + name + "\n")
            f.write("score: " + str(score) + "\n")
        elif "Key deleted" in op:
            f.write("\n")
            f.write("key deleted: " + reg + "\n")
            f.write("description: " + name + "\n")
            f.write("score: " + str(score) + "\n")
        else:
            print("new type of operation found : " + op)

    f.close()
    if control_flag == 1:
        print("")
        print("registry file successfully written")
        print("")


###################################################################################################################################
# method in order to match TTPs from a file with those used by malware
def TTPs(ttps_dict, my_ttps):
    print("")
    print("---List of the TTPs that samples of the same family of the submitted malware usually exploit---")
    print("")
    for el in my_ttps:
        if el in ttps_dict:
            desc = ttps_dict.get(el)
            print(el + " - " + desc)


###################################################################################################################################
# method in order to prompt to the analyst the most dengerous events from Triage report
def dangerous_events(DE_dict):
    print("")
    print("---Dangerous events triggered by the malware or by samples of its same family---")
    print("")
    for key,value in DE_dict.items():
	    print("event description: " +  key + ' - score: ' + str(value))
   


