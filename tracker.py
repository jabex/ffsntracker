import dns.resolver
import random
import math
import csv
import time
from time import sleep

import logging
import logging.handlers

logger = logging.getLogger(__name__)

domainlist = []
_ATTEMPTS   = 5

def loadfile(filename, fieldnames):
    if len(domainlist)!=0 : domainlist[:] = []
    
    with open(filename, 'rb') as csvfile:
        reader = csv.DictReader(csvfile, fieldnames=fieldnames, delimiter=';')
        next(reader)
        for row in reader:
            # Exlude queried domain but that are expired 
            if not(int(row['attempts'])>_ATTEMPTS):
                aux = [ row['domain'].strip(), row['attempts'], row['last_ttl'], row['last_ts']]
                domainlist.append(aux)
                
def updatefilelist(filename, fieldnames):
    with open(filename, 'wb') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
        writer.writeheader()
        
        for item in domainlist:
            domain = item[0].strip()
            attempts = int(item[1])
            last_ttl = item[2]
            last_ts = item[3]
            
            if (attempts<= _ATTEMPTS):
                writer.writerow({'domain': domain, 
                                'attempts': attempts, 
                                'last_ttl': last_ttl,
                                'last_ts':  last_ts
                            })

def updatearraylist(cur_index, cur_time, cur_attempts, cur_answers):
    'update array'
    domainlist[cur_index][1] = cur_attempts
    if (cur_answers!=None): 
        domainlist[cur_index][2] = cur_answers.rrset.ttl
    else:
        domainlist[cur_index][2] = 0
    
    domainlist[cur_index][3] = cur_time
    
def selectdomain():
    freshness = []
    for item in domainlist:
        freshness.append(int(item[2])+int(item[3]))
        
    index = min(xrange(len(freshness)), key=freshness.__getitem__)
    return index 

def selectsleptime(last_ts, last_ttl):
    if (last_ts==0) : return 1
   
    t_sleep = int(math.floor(random.uniform(0,50)))
    ts_now = int(time.time())
    delta_time = (ts_now - last_ts) + t_sleep
    
    if (delta_time < last_ttl):
        t_sleep = (last_ttl-delta_time)+((5*t_sleep)/4)
        
    return t_sleep

def ipobfuscator(cur_ip):
    cur_ip = cur_ip.split(".")
    cur_ip = map(float,cur_ip)
    cur_ip = (255 - cur_ip[0]) * 256**3 + (255 - cur_ip[1]) * 256**2 + (255 - cur_ip[2]) * 256 + (255 - cur_ip[3])
    return  cur_ip/1000

def updatetracker(tracker, cur_time, cur_answers, cur_domain ):
    
    ip = []
    for data in cur_answers:
        ip.append(str(ipobfuscator(data.address)))
        
    ipstr = ','.join(ip)
    
    with open(tracker, 'ab') as csvfile:
        writer = csv.writer(csvfile, delimiter=';')
        
        row = ()
        row = row + (cur_domain,)
        row = row + (cur_time,)
        row = row + (cur_answers.rrset.ttl,)
        row = row + (ipstr,) 
        
        writer.writerow(row)

def querydomain(domain, attempts):
    answers = None
    retval = []
    flag = False
    
    try:
        answers = dns.resolver.query(domain, 'A')
        
        logger.info( "[+] TTL : %s", answers.rrset.ttl)
        for data in answers:
            logger.info( "[+] Ip : %s", data.address )
            
    # http://www.dnspython.org/docs/1.14.0/dns.resolver.Resolver-class.html
    except dns.resolver.NXDOMAIN:
        logger.error("[-] Error:  the query name does not exist.")
        attempts += 1 

    except dns.resolver.NoNameservers:
        logger.error("[-] Error: No non-broken nameservers are available to answer the question.")
        attempts += 1
    
    except dns.resolver.YXDOMAIN:
        logger.error("[-] Error: The query name is too long after DNAME substitution.") 
        attempts += 1
        
    except dns.resolver.Timeout:
        logger.error("[-] Error: No answers could be found in the specified lifetime.")
        attempts += 1
    else:
        attempts = 0
        flag = True

    retval.append([attempts, answers])
    return retval
        
    
def main():
    filename = "domainlist.csv"
    logfile  = "domain_answer.log"
    tracker  = "domain_tracker.csv"
    fieldnames = ['domain', 'attempts', 'last_ttl', 'last_ts']
    
    logger.setLevel(logging.INFO)
    handler = logging.handlers.TimedRotatingFileHandler(logfile, when="midnight", backupCount=30)
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    logger.info(">>> Load domain list from file %s", filename)
    loadfile(filename,fieldnames)

    while (len(domainlist)>0):
        # Select a domain
        index = selectdomain()
        curitem = domainlist[index]
        
        # Get domain informations
        domain   = curitem[0] 
        attempts = int(curitem[1]) 
        last_ttl = int(curitem[2])
        last_ts  = int(curitem[3])
        logger.info(">>> Select domain %s", domain)
        
        # Sleep
        t_sleep = selectsleptime(last_ts, last_ttl)
        logger.info(">>> The scheduler staying sleep for %d seconds", t_sleep)
        sleep(t_sleep)
        
        # Do query
        ret_value = querydomain(domain,attempts)
        cur_attempts = ret_value[0][0]
        cur_answers = ret_value[0][1]
        cur_time = int(time.time())
        
        # Update domain list in memory
        updatearraylist(index, cur_time, cur_attempts, cur_answers)
        updatefilelist(filename,fieldnames)
        loadfile(filename,fieldnames)
        logger.info(">>> List updated on disk and reloaded")
        
        if cur_answers!= None:
            # Add tracker info
            updatetracker(tracker, cur_time, cur_answers, domain)
            logger.info(">>> Tracker updated")
            
        if cur_attempts > _ATTEMPTS:
            logger.warning(">>> The domain %s seems expired", domain )   


if __name__ == "__main__":         
    main()
