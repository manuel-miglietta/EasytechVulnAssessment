# IMPORT
import os
import argparse
from util import utils

#SCAN PORT
parser = argparse.ArgumentParser()
args = parser.parse_args()

def arguments():

    # ARGUMENTS 
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--file', action = 'store', dest = 'nmapfile',required = True, help = 'Nmap XML file')
    parser.add_argument('-l', '--limit', action = 'store', dest = 'limit', default='100000000000000000000', required = False, help = 'Limit CVEs per CPE to get')
    parser.add_argument('-t', '--type', action = 'store', dest = 'types',default='txt',required = False, help = 'Name of output type for logs(txt or csv)')
    parser.add_argument('-v', '--vittima', action = 'store', dest = 'vittima',required = True, help = 'Indirizzo IP della "vittima"')
    parser.add_argument('-r', '--helpo', action = 'help', dest = 'helpo',default='Help',required = False, help = 'Just an help command')
    
    args = parser.parse_args()

    # GRUPPO AGRUMENTS
    nmapfile,limit,types,vittima = arguments()
    utils.parser(vittima,nmapfile,int(limit),types)


    #IP VARIABLE (-h) SU XML DA QUESTO FILE 
    IP = args.vittima
    with open(args.nmapfile, "wb") as f:
        f.write(IP=IP)

    #CHECK XML FILE
    if args.nmapfile:
        if os.path.isfile(args.nmapfile):
            return os.path.abspath(args.nmapfile),args.limit,args.types,args.vittima
        else:
            print ('File XML non trovato!')
            exit(1)
    else:
        parser.print_help()

    #HELP
    if args.helpo:
      print (' Help Menù ')
      print (' --------- ')
      print (' Welcome to help menu')
      print (' ° f/file > select Nmap XML FIle')
      print (' ° l/limit > select limit of vulnerability software can find')
      print (' ° t/type > select time of output logs (txt or csv)')
      print (' ° v/vittima > select target IP')
      print (' ° h/help > view this menù')

#CVE SCAN
#CVEID=""
#r = nvdlib.searchCVE(CVEID)[0]

#print("----------------------------------")
#print(r.id)
#print(r.v31severity + ' - ' + str(r.v31score))
#print(r.descriptions[0].value)
#print("----------------------------------")
