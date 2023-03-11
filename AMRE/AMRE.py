import time
import requests
import json
import getopt
import sys
from datetime import date

#custom imports
import search_engine
import parse_engine
import remediation_engine

# coding=utf-8

#user parameters
api_key = "insert-here-your-api-key"


#global parameters
root_api_url = "https://tria.ge/api/v0"
sample_api_url = root_api_url + "/samples"
headers = {'Authorization' : 'Bearer '+ api_key}


#method in order to post a sample for the analysis on triage sandbox and return the sample_id
def submit_sample(file_path):
    
    #multipart/form-data POST - send the sample
    files = {'file' : open(file_path, 'rb'), '_json' : (None, '{"kind":"file", "interactive":false}')}
    
    response = requests.post(sample_api_url, headers = headers, files = files)

    if response.status_code == 200 :
        #print(json.dumps(response.json(), indent=4))
        print("sample successfully submitted")
        #analyze the response
        j_resp = response.json()
        sample_id = j_resp['id']
    else:
        print(response.raise_for_status())
        sys.exit("comunication error")

    return str(sample_id)


#method in order to request and return the overview of a sample with a specific sample_id
def get_sample_overview(sample_id):
    mySample_api_url = sample_api_url + "/" + sample_id # questo dovrà essere sostituito automaticamente quando si fa il post
    overview_api_url = mySample_api_url + "/overview.json"
    response = requests.get(overview_api_url, headers = headers)
    if response.status_code == 200 :
        j_resp = response.json()

    else:
        print(response.raise_for_status())
        #sys.exit("comunication error")

    return j_resp
    


#method in order to return some useful overview's info
def extract_overview_info(overview):
    tasks = parse_engine.tasks_from_overview(overview)
    family_list = parse_engine.family_from_overview(overview)
    campaign = parse_engine.campaign_from_overview(overview)
    filename = parse_engine.filename_from_overview(overview)#

    #if parser return None it means that the key used to parse doesn't exist
    if tasks is None:
        sys.exit('key to parse tasks not existing')

    return tasks, family_list, campaign, filename



#method to write overview to a file
def print_overview(overview, sample_id, family_list):
    #empty list is false, non empty is true
    if not family_list:
        filename = sample_id + "_" + "unknown-fam" + "_Overview.txt"       
    else:
        filename = sample_id + "_" + family_list[0] + "_Overview.txt"
    f = open(filename,"w")
    f.write(json.dumps(overview, indent=4))
    f.close()
    print("overview wrote to the file")

    return


#method in order to retrieve the dynamic report of all tasks executed on the sample with specified sample_id
def get_dynamic_report(tasks, sample_id):
    
    mySample_api_url = sample_api_url + "/" + sample_id
    report_list = []

    #cycle on all possible tasks
    for i in range(len(tasks)):
        task_id = tasks[i] 
        report_api_url = mySample_api_url + "/" + task_id + "/report_triage.json"
        response = requests.get(report_api_url, headers = headers)
        if response.status_code == 200 :
            report_list.append(response.json())   
        else:
            print(response.raise_for_status())
            sys.exit("comunication error")
    
    return report_list


#method to write dynamic reports to a file
def print_dynamic_report(report_list, sample_id, family_list):
    for i in range(len(report_list)):
        i_report = report_list[i]
        if not family_list:
            filename = sample_id + "_" + "unknown-fam" + "_" + "behavioural" + str(i+1) + "_Dynamic_report_" + ".txt"
        else:
            filename = sample_id + "_" + family_list[0]  + "_" + "behavioural" + str(i+1) + "_Dynamic_report_" + ".txt"
        f = open(filename,"w")
        f.write(json.dumps(i_report, indent=4))
        f.close()
        print("dinamic report " + str(i+1) + " wrote to the file")


#method in order to check if the report is ready or not
def check_status(sample_id):
    my_sample_api_url = sample_api_url + "/" + sample_id
    response = requests.get(my_sample_api_url, headers = headers)
    status = parse_engine.status_from_sampleQuery(response.json())

    return status


def main():
    argumentList = sys.argv[1:] 
    options = "hp:d:f"
    long_options = ["Help", "Path =", "Days =", "Firewall"]
    path = ""
    days = 1
    firewall_flag = 0

    try:
        arguments, options = getopt.getopt(argumentList, options, long_options)

        for currentArgument, currentValue in arguments:
            if currentArgument in ["-p"]:
                path = currentValue
            elif currentArgument in ["-d"]:
                days = int(currentValue)  
            elif currentArgument in ["-f"]:
                firewall_flag= 1
            elif currentArgument in ["-h"]:
                print("usage -p(mandatory) <global path of the file> -d(optional) <days to go bach in malware augumentation> -f(optional) new firewall sintax")
        
    except getopt.error as err:
        print(str(err))
    
    sample_id = submit_sample(path) 

    #waits for the task to complete
    time.sleep(180)

    #checks if the task is effectively completed, other  ways sleeps for other 30 secs
    while(check_status(sample_id) != 'reported'):
        if(check_status(sample_id) == 'failed'):
            sys.exit("triage processing of the sample is failed")
        else:
            print("waiting for the report for addictional 30 seconds")
            time.sleep(30)

    #request and write to file overview
    my_overview = get_sample_overview(sample_id)
    print_overview(my_overview, sample_id, family_list)

    #retrive some info from the malware
    tasks, family_list, campaign, filename = extract_overview_info(my_overview)
    tags = parse_engine.tags_from_overview(my_overview)
    os = parse_engine.OS_from_overview(my_overview)

    #request and write to file dynamic reports
    my_dynamic_report = get_dynamic_report(tasks, sample_id)
    print_dynamic_report(my_dynamic_report,sample_id, family_list)

    
    ip_blacklist = []
    reg_orig = {}
    reg_ma = {}
    TTPs_list = []
    DE_dict = {}
    #check if family list is None and if the list is empty
    if family_list != None and family_list:
        #malware augumentation
        malware_id_aug_list = parse_engine.ids_from_SampleList(search_engine.search_for_rep_rec(family_list, search_engine.days_back(days), str(date.today()), campaign, tags), filename)
        
        if len(malware_id_aug_list) > 99:
            malware_id_aug_list = malware_id_aug_list[:99]
        #add also the original sample to the list
        malware_id_aug_list.append(sample_id)


        for mal_id in malware_id_aug_list:
            overview = get_sample_overview(mal_id)
            
            #IPS
            #retrieve all ips from the overview with mal_id
            malicious_ip = parse_engine.ip_from_overview(overview)
            #remove repetitions from the ip list
            for ip in malicious_ip:
                if ip not in ip_blacklist:
                    ip_blacklist.append(ip)

            #DOMAINS
            #retrieve the list of all the domains from the overview with mal_id
            malicious_domain = parse_engine.domains_from_overview(overview)
            dom_ips = search_engine.ips_from_domain(malicious_domain)
            ip_blacklist = parse_engine.merge_lists(ip_blacklist, dom_ips)

            tasks, family_list, campaign, filename = extract_overview_info(overview)
            dynamic_report = get_dynamic_report(tasks, mal_id)
            for rep in dynamic_report:
                #YARA RULES
                hash_dict = parse_engine.hash_from_dynRep(rep)
                remediation_engine.yara_rules_building(hash_dict)
                
                #REGISTRY
                if(os == "windows"):
                    if mal_id == sample_id:
                        reg_orig = parse_engine.registry_from_dynRep(rep, reg_orig)
                    else:
                        reg_ma = parse_engine.registry_from_dynRep(rep, reg_ma)

                #TTPs
                TTPs_list = parse_engine.TTPs_from_dynRep(rep, TTPs_list)

                #DANGEROUS EVENTS
                DE_dict = parse_engine.dEvents_from_dynRep(rep, DE_dict)
    


    else: 
        #samples that have no known family -> no malware augmentation
        #IPS
        malicious_ip = parse_engine.ip_from_overview(my_overview)
        for ip in malicious_ip:
            if ip not in ip_blacklist:
                ip_blacklist.append(ip)

        #DOMAINS
        malicious_domain = parse_engine.domains_from_overview(my_overview)
        dom_ips = search_engine.ips_from_domain(malicious_domain)
        ip_blacklist = parse_engine.merge_lists(ip_blacklist, dom_ips)

        for rep in my_dynamic_report:
            #YARA RULES
            hash_dict = parse_engine.hash_from_dynRep(rep)
            remediation_engine.yara_rules_building(hash_dict)

            #REGISTRY
            if(os == "windows"):
                reg_orig = parse_engine.registry_from_dynRep(rep, reg_orig)
    
            #TTPs
            TTPs_list = parse_engine.TTPs_from_dynRep(rep, TTPs_list)

            #DANGEROUS EVENTS
            DE_dict = parse_engine.dEvents_from_dynRep(rep, DE_dict)
    
    #Remediation steps
    remediation_engine.TTPs(parse_engine.TTPs_from_ttpFile("other/TTPs.txt"), TTPs_list)
    remediation_engine.dangerous_events(DE_dict)
    remediation_engine.ip_block_rules(ip_blacklist, os)
    if firewall_flag == 1:
        remediation_engine.to_another_syntax(os, ip_blacklist)
    remediation_engine.registry_operations(reg_orig, 0)
    remediation_engine.registry_operations(reg_ma, 1)

if __name__ == "__main__":
    main()


