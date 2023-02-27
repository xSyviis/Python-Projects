#Michael Feltner
#CYBR-260-40
#Final Assignment - Vulnerability Scanner using Nmap and Metasploit
#The purpose of this program is to conduct an nmap scan of a given IP, range, or subnet. This identifies available hosts, hostnames, and open TCP ports. It utilizes this information to conduct an SMB vulnerability scan through metasploit using the MsfRpc. The results of both the nmap and vulnerability scan are output to CSV.


import nmap
import pandas as pd
import csv
from pymetasploit3.msfrpc import MsfRpcClient
import time

nm = nmap.PortScanner()

#Ask user for the IP/Range to scan
scanrange = input("Please provide the IP range you would like to scan: ")
#Function Name: scanhosts
#Purpose: This function uses nmap scanner to find all hosts on a network
#Inputs: It uses the user assigned variable 'hosts' and the predefined arguments of '-T4 -F --system-dns'
#Returns: It returns 3 lines to the user: The first is the hostname, The second is "Open TCP Ports", and the #third is a list of all open ports on the host.
def scanhosts():
    #define the hosts to scan and arguments in nmap
    scan_range = nm.scan(hosts=scanrange, arguments='-T4 --system-dns')
    nm.all_hosts()
    hosts = []   
    for host in nm.all_hosts():
     hosts.append({
        #Gather the host IP and add to the column "host"
        "host": host,
        #Gather the hostname, if possible, and add to the column "hostnames"
        "hostnames": nm[host].hostnames(),
        #Gather all Open TCP ports and add to the column "open ports"
        "open ports": nm[host].all_tcp()
        })
    #create the dataframe for pandas to generate the csv.
    df = pd.DataFrame(hosts)
    #convert the dataframe
    df.to_csv("c:/Users/test/Documents/School/CYBR-260-40/nmap_scan_results.csv", index=False)
    return()

#Function Name: vulnscan
#Purpose: This function uses the output from scanhosts() to identify which hosts have tcp port 445 open. Once hosts are identified, it connects to the MsfRpc server. It then runs the smb_ms17_010 Metasploit module against the identified hosts to see if they are vulnerable to exploit. Finally, it returns the results of the vulnerability scan in a csv file. 
#Inputs: It begins by ingesting the document from nmap. Then using defined inputs, it connects to the remote metasploit server. It then accepts a defined input for the module to be used by Metasploit.
#Returns: This returns the results of the vulnscan to a csv.
def vuln_scan():
    #Write new csv VulnScanResults
    with open('c:/Users/test/Documents/School/CYBR-260-40/VulnScanResults.csv', 'w', newline='') as csvfile2:
        spamwriter = csv.writer(csvfile2, delimiter=',')
        #Create headers in CSV.
        spamwriter.writerow(['Host', 'Scanner Module', 'Results', 'Reason'])
        #Read the csv delimited with commas
        with open('c:/Users/test/Documents/School/CYBR-260-40/nmap_scan_results.csv', newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            for row in spamreader:
                #For each instance of port 445 found in index 2 (open ports), run the vulnerability scan
                if '445' in row[2]:
                    #connect to the MsfRpc server at designated IP with provided password
                    client = MsfRpcClient('<INPUT RPC SERVER PASSWORD HERE>', server='<INPUT LOCAL RPC SERVER IP HERE>', ssl=False)
                    #define the type and module to be used from MetaSploit
                    auxiliary = client.modules.use('auxiliary', 'scanner/smb/smb_ms17_010')
                    #Using the csv, set RHOSTS to the value found at index 0(host IP)
                    auxiliary['RHOSTS'] = row[0]
                    #assign the output of the successful scan to the variable msg
                    msg = auxiliary.execute()
                    #If job ID is anything except none, the scan initiated successfully
                    print(msg)
                    #pause for 5 seconds to allow the scan to complete
                    time.sleep(5)
                    #Using the uuid output in execute, stored in msg, return the results of the scan to the variable export.
                    export = client.call('module.results', [msg['uuid']])
                    #Write Host IP, Module used, results, and reason to csv
                    spamwriter.writerow([row[0],'scanner/smb/smb_ms17_010', export['result']['message'], export['result']['reason']])
    return

#Function Name: run
#Purpose: This contains both functions and is executes the program
#Inputs: none
#Returns: none
def run():
    scanhosts()
    vuln_scan()

run()
