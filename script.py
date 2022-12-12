# IMPORT 
import os
import argparse
from util import utils


# AGRUMENTS
def arguments():
    parser = argparse.ArgumentParser(description = utils.banner())
    parser.add_argument('-f', '--nmap-file', action = 'store', dest = 'nmapfile',required = True, help = 'Nmap XML file')
    parser.add_argument('-l', '--limit', action = 'store', dest = 'limit', default='4', required = False, help = 'Limit CVEs per CPE to get')
    parser.add_argument('-t', '--type', action = 'store', dest = 'types',default='txt',required = False, help = 'Name of output type for logs(txt or csv)')
    args = parser.parse_args()
    if args.nmapfile:
            return os.path.abspath(args.nmapfile),args.limit,args.types

# VARIABILI FINALI
nmapfile,limit,types = arguments()
utils.parser(nmapfile,int(limit),types)

#CVE SCAN
#CVEID=""
#r = nvdlib.searchCVE(CVEID)[0]

#print("----------------------------------")
#print(r.id)
#print(r.v31severity + ' - ' + str(r.v31score))
#print(r.descriptions[0].value)
#print("----------------------------------")
