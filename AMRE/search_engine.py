import requests
from datetime import date
from calendar import monthrange
from nslookup import Nslookup

###################################################################################################################################
#user parameters
get_api_ulr = "https://tria.ge/api/v0/search"
api_key = "insert-here-your-api-key"


###################################################################################################################################
#method in order to search for a list of ids of malware with the matching family and campaing(if available), and from the chosen date
def search_for_rep(query, From, To, data):

    headers = {'Authorization' : 'Bearer '+ api_key}
    query = query + " from:"+ From +" to:" + To
    response = requests.get(get_api_ulr, params = {"query": query}, headers = headers)

    if response.status_code == 200 :
        response = response.json()
        dataR = data + response.get("data")
        next = response.get("next")
    else:
        print(response.raise_for_status())
    return dataR, next


###################################################################################################################################
#recursive metod in order to join all the lists of samples in the desired time interval
def search_for_rep_rec(families, From, To, campaign, tags):
    constraints = ""
    for el in families:
        if ":" in el:
            constraints = constraints + " "+ el
        else:
            constraints = constraints + " family:" + el 
    
    for el in tags:
        constraints = constraints + " tag:" + el

    if campaign != None:
        constraints = constraints + " campaign:" + campaign

    sample_list, next = search_for_rep(constraints, From, To, [])
    while next != None:
        sample_list, next = search_for_rep(constraints, From, next, sample_list)
    return sample_list


###################################################################################################################################
#auxiliar function to find the date back in time from where start to find reports
def days_back_rec(days_to_back, today_number, today_month, today_year):
    
    new_number = today_number
    new_month = today_month
    new_year = today_year
    new_date = ''

    #calculate days to sub to the past months
    if days_to_back >= int(today_number):
        days_remaining = days_to_back - int(today_number)#51
        #check how many days_to back has the last passed month
        new_month = (int(today_month) - 1)%13
        if new_month == 0:
            new_month = 12
            #if month is 0 we go back to december of the previous year
            new_year = int(new_year) - 1 
        month,days_last_month = monthrange(int(new_year), int(new_month))
        new_number = days_last_month

        if days_remaining < days_last_month:
            new_number = days_last_month - days_remaining
            new_date = str(new_year) + "-" + str(new_month) + "-" + str(new_number)
        else:
            new_date = days_back_rec(days_remaining, new_number, new_month, new_year)     
    else:
        new_number = int(today_number) - days_to_back
        new_date = str(new_year) + "-" + str(new_month) + "-" + str(new_number)

    return new_date


###################################################################################################################################
#recursive function to find the date back in time from where start to find reports
def days_back(days_back):

    today = date.today()
    today_number = today.strftime("%d")#09
    today_month = today.strftime("%m")#11
    today_year = today.strftime("%Y")#2022

    #start the recursive function
    new_date = days_back_rec(days_back, today_number, today_month, today_year)
    return new_date


###################################################################################################################################
#method in order to lookup on domains to extract ips
def ips_from_domain(domain_list):
    # Initialize Nslookup
    dns_query = Nslookup(verbose = False)
    ip_list = []

    for domain in domain_list:
        ips_record = dns_query.dns_lookup(domain)
        if any(ips_record.answer):
            for ip in ips_record.answer:
                if(ip not in ip_list):
                    ip_list.append(ip)    

    return ip_list