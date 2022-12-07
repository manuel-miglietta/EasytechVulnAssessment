import os
import argparse
from util import utils

def arguments():
    parser = argparse.ArgumentParser(description = utils.banner())
    parser.add_argument('-f', '--nmap-file', action = 'store', dest = 'nmapfile',required = True, help = 'Nmap XML file')
    parser.add_argument('-v', '--vittima', action = 'store', dest = 'vittima',required = False, help = 'Target IP')
    parser.add_argument('-l', '--limit', action = 'store', dest = 'limit', default='4', required = False, help = 'Limit CVEs per CPE to get')
    parser.add_argument('-t', '--type', action = 'store', dest = 'types',default='txt',required = False, help = 'Name of output type for logs(txt or csv)')
    args = parser.parse_args()
    if args.nmapfile:
        if os.path.isfile(args.nmapfile):
            return os.path.abspath(args.nmapfile),args.limit,args.types
        else:
            print ('Il file esplicitato non esiste')
            exit(1)
    if args.vittima:
      try:
        IP = args.vittima
      except:
        print ('Impossibile assegnare la variabile')
        exit(1)

nmapfile,limit,types = arguments()
utils.parser(nmapfile,int(limit),types)
