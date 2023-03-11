import sys

###################################################################################################################################
#method in order to take out ips from overview
def ip_from_overview(overview):
    ip_list = []
    try:
        if 'targets' in overview:
            targets = overview['targets'][0]
            if 'iocs' in targets:
                iocs = targets.get('iocs')
                if "ips" in iocs:
                    ip_list = iocs.get('ips')      
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with list indexes or dictionaries structure on ips")

    return ip_list


###################################################################################################################################
#method in order to take out domains from overview
def domains_from_overview(overview):
    domain_list = []
    try:
        if 'targets' in overview:
            targets = overview['targets'][0]
            if 'iocs' in targets:
                iocs = targets.get('iocs')
                if 'domains' in iocs:
                    domain_list = iocs.get('domains')
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with list indexes or dictionaries structure on domains")

    return domain_list


###################################################################################################################################
#method in order to take out URLs from overview
def urls_from_overview(overview):
    urls_list = []
    try:
        if 'targets' in overview:
            targets = overview['targets'][0]
            if 'iocs' in targets:
                urls_list = targets.get('iocs').get('urls')
        
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with list indexes or dictionaries structure on urls")
    return urls_list


###################################################################################################################################
#method in order to take out task names from overview
def tasks_from_overview(overview):
    try:
        if 'targets' in overview:
            targets = overview['targets'][0]
            if 'tasks' in targets:
                tasks_list = targets.get('tasks')
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with list indexes or dictionaries structure on tasks")
    return tasks_list


###################################################################################################################################
#method in order to take out request's status from the sample query
def status_from_sampleQuery(sampleQuery):
    status = sampleQuery.get('status')
    return status


###################################################################################################################################
#method in order to extract only ids of reports (report not of the same file) in the search engine output
def ids_from_SampleList(sample_list, myFilename):
    try:
        ids = []
        for el in sample_list:
            if "id" in el and "filename" in el:
                id = el.get('id')
                filename = el.get('filename')
                #avoid repetitions of ids
                if (id != filename != None) and (id not in ids) and (filename != myFilename):
                    ids.append(id)
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit('some problem with dictionary structure on ids')
    return ids


###################################################################################################################################
#method to extract malware family from the overview.
def family_from_overview(overview):
    family_list = []
    try:
        #triage return a family list that can eventually contain more than one family
        if "analysis" in overview:
            analysis = overview.get('analysis')
            if "family" in analysis:
                family_list = analysis.get("family")
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on family name")

    return family_list


###################################################################################################################################
#method in order to extract the attack campaign if available
def campaign_from_overview(overview):
    campaign = None
    try:
        if "analysis" in overview:
            analysis = overview.get('analysis')
            if "tags" in analysis:
                tag_list = analysis.get('tags')
                if tag_list != 'None':
                    for el in tag_list:
                        el_div = el.split(':')
                        if el_div[0] == 'campaign':
                            campaign = el_div[1]
                            break

    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on campaign name")

    return campaign


###################################################################################################################################
#method in order to get filename of the submitted file from the overview
def filename_from_overview(overview):
    try:
        filename = overview.get('sample').get('target')
        return filename
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on filename search")


###################################################################################################################################
#method in order to get OS (Windows or Linux) from the overview
def OS_from_overview(overview):
    try:
        if 'tasks' in overview:
            tasks = overview.get('tasks')
            d_keys = list(tasks.keys())
            first_task = tasks.get(d_keys[0])
            os = first_task.get("os")
            if('windows' in os):
                os_s = 'windows'
            else:
                os_s = 'linux'
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on OS search")

    return os_s


###################################################################################################################################
#method in order to parse all the hashes of a dynamic report and the relative sizes
def hash_from_dynRep(dynamic_report):
    try:
        #create a dictionary of pairs hash - size
        hashes = {}
        if "task" in dynamic_report:
            task = dynamic_report.get("task")
            if "sha256" in task and "size" in task:
                hash = task.get("sha256")
                size = task.get("size")
                if(hash != None):
                    hashes[hash] = size
        if "dumped" in dynamic_report:
            dumped = dynamic_report.get("dumped")
            for dump in dumped:
                if "sha256" in task and "size" in task:
                    hash = dump.get("sha256")
                    size = dump.get("size")
                    if(hash != None):
                        hashes[hash] = size
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on hash search")
    return hashes


###################################################################################################################################
#method in order to parse registry entries and the related operation
def registry_from_dynRep(dynamic_report, reg_dict):
    try:
        #return a dictionary composed by pairs (operation performed + registry key)-([score, name that explains the key opened])

        if "signatures" in dynamic_report:
            signatures = dynamic_report.get("signatures")
            for sig in signatures:
                if "indicators" in sig and "score" in sig:
                    indicators_list = sig.get("indicators")
                    score = sig.get("score")
                    #the name can be also None if not present in the report, it's not crucial
                    name = sig.get("name")
                    for ind in indicators_list: 
                        if "ioc" in ind and "description" in ind:
                            ioc = ind.get("ioc")
                            description = ind.get("description")
                            ioc_desc = description + "\t" + ioc
                            #check if I selected effectively a registry entry
                            if ioc[:9] == "\REGISTRY":
                                reg_dict[ioc_desc] = [score, name]
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on registry search")
    return reg_dict


###################################################################################################################################
#method in order to parse TTPs from dynamic report
def TTPs_from_dynRep(dynamic_report, ttp_list):
    ttp = []
    try:
        if "analysis" in dynamic_report:
            analysis = dynamic_report.get("analysis")
            if "ttp" in analysis:
                ttp = analysis.get("ttp")
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on TTP parsing from dynamic report")

    #remove eventual duplicates in the TTP list
    difference = set(ttp) - set(ttp_list)
    ttp = ttp_list + list(difference)

    return ttp


###################################################################################################################################
#method in order to retrieve TTPs from the TTPs custom file
def TTPs_from_ttpFile(path):
    ttps_dict = {}
    f = open(path, "r")
    lines = f.readlines()
    i = 0
    desc = ""
    while i < len(lines):
        line = lines[i]
        my_line = line.split("\t")
        if(len(my_line) == 3):
            TTP = my_line[0]
            desc = my_line[1] + " - " + my_line[2]
            i = i+1
            if i < len(lines):
                my_nextLine = lines[i].split("\t")
                while len(my_nextLine) != 3 and i < len(lines):
                    desc = desc + " - " + my_nextLine[0] + " - " + my_nextLine[1]
                    i = i+1
                    my_nextLine = lines[i].split("\t")
            ttps_dict[TTP] = desc
    f.close

    return ttps_dict


###################################################################################################################################
#method in ordet to extract dangerous events from the dynamic report
def dEvents_from_dynRep(dynamic_report, my_dict):
    try:
        if "signatures" in dynamic_report:
            sig = dynamic_report.get("signatures")
            for el in sig:
                if "score" in el:
                    score = el.get("score")
                    if int(score) >= 8:
                        name = ""
                        if "name" in el:
                            name = el.get("name")
                        desc = ""
                        if " desc" in el:
                            desc = el.get("desc")
                        name_desc = name + " - " + desc
                        my_dict[name_desc] = score
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on dangerous events parsing from overview")
    return my_dict


###################################################################################################################################
# method in order to parse tags from overview
def tags_from_overview(overview):
    tags = []
    try:
        if "analysis" in overview:
            analysis = overview["analysis"]
            if "tags" in analysis:
                tags = analysis["tags"]
                rem = []
                for i in range(len(tags)):
                    el = tags[i]
                    if "family" in el or "campaign" in el:
                        rem.append(el)
                for el in rem:
                    tags.remove(el)
    except:
        exc_info = sys.exc_info()
        print(exc_info)
        sys.exit("some problem with dictionary structure on ssdeep parsing from overview")
    return tags

###################################################################################################################################
#method in order to merge 2 lists avoiding repetitions
def merge_lists(first_list, second_list):
    in_first = set(first_list)
    in_second = set(second_list)
    in_second_but_not_in_first = in_second - in_first
    result = first_list + list(in_second_but_not_in_first)

    return result



###################################################################################################################################
#method in order to remove from the ip list the whitelisted addresses
def rem_whitelisted(all_ip):
    whitelist_path = "other\\whitelisted_ip.txt"
    whitelist = []
    with open(whitelist_path, "r") as whitelist_f:
        for line in whitelist_f:
            whitelist.append(line.strip("\n"))

    rem = []
    for el in all_ip:
        if el in whitelist:
            rem.append(el)
    
    all_ip_filtered = [x for x in all_ip if x not in rem]

    return all_ip_filtered
