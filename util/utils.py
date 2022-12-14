import requests
from lxml import html
import xml.etree.ElementTree as treant
from termcolor import colored
import warnings
import json

warnings.simplefilter("ignore")

def prepare_cpe(cpe):
 if containsNumber(cpe) == True:
   word=cpe.split(':')
   name=word[2]
   types=word[3]
   if len(word) >= 5:
    version=word[4]
    ret=name+" "+types+" "+version
    return ret
   return 0 
 return 0

def containsNumber(value):
 for character in value:
  if character.isdigit():
   return True
 return False

def risk_color(risk):
  if "LOW" in risk:
    return colored(risk,"green")
  if "MEDIUM" in risk:
    return colored(risk,"yellow")
  if "HIGH" in risk:
    return colored(risk,"red")
  if "CRITICAL" in risk:
    return colored(risk,"red",attrs=['blink'])

def banner():
    print (open('banner.txt','r').read())



def parser_response_csv(content,csv_str):

    data = json.loads(content)

    for vuln in data['result']['CVE_Items']:
        cve=vuln['cve']['CVE_data_meta']['ID']
        url="https://nvd.nist.gov/vuln/detail/"+cve
        data=vuln['publishedDate']
        descrizione=vuln['cve']['description']['description_data'][0]['value']
        try:
            cvss2=vuln['impact']['baseMetricV2']['severity']
        except:
            cvss2="NULL"
        try:
            cvss3=vuln['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except:
            cvss3="NULL"
        # use pipes '|' because field description have ',' this can crash parsers
        row=csv_str+cve+"|"+url+"|"+date+"|"+cvss2+"|"+cvss3+"|"+description
        with open('Report.csv', 'a+') as f:
            f.write(row+"\n")
        print(row)


def parser_response(content):
    data = json.loads(content)
    for vuln in data['result']['CVE_Items']:
        url="https://nvd.nist.gov/vuln/detail/"+str(vuln['cve']['CVE_data_meta']['ID'])
        print("\n\tURL: "+colored(url,"cyan"))
        print("\tDate: "+vuln['publishedDate'])
        print("\tDescription:"+colored(vuln['cve']['description']['description_data'][0]['value'],"yellow"))
        try:
            print("\tCVSS V2 Risk: "+risk_color(vuln['impact']['baseMetricV2']['severity']))
        except: 
            print("\t")
        
        try:
            print("\tCVSS V3 Risk: "+risk_color(vuln['impact']['baseMetricV3']['cvssV3']['baseSeverity']))
        except:
            print("\t")
    

def getCPE(cpe,limit):
    cpe = prepare_cpe(cpe)
    if cpe != 0:
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword="+cpe+"&resultsPerPage="+str(limit)
        r = requests.get(url)
        if r.status_code == 200:
            return r.text
        else:
            return False
    return False

def fix_cpe_str(str):
    return str.replace('-',':')

def parser(filenmap,limit,type_output):
    tree = treant.parse(filenmap)
    root = tree.getroot()
    for child in root.findall('host'):
        for k in child.findall('address'):
            host = k.attrib['addr']
            print(host)

            for y in child.findall('ports/port'):
                current_port = y.attrib['portid']
                for z in y.findall('service/cpe'):
                    if len(z.text) > 4:
                        cpe = fix_cpe_str(z.text)
                        result = getCPE(cpe,limit)
                        if result:
                            if("csv" in type_output):
                                string_csv=str(host)+"|"+str(current_port)+"|"+str(cpe)+"|"
                                parser_response_csv(result,string_csv)
                            else:
                                print (colored("Host: " + host,"cyan"))
                                print (colored("Port: " + current_port,"cyan"))
                                print (colored("cpe: " + cpe,"cyan"))
                                print ("connection refused, OS checker failed")
                                parser_response(result)


            for y in child.findall('os'):
                for z in y.findall('osmatch/osclass/cpe'):
                    if len(z.text) > 1:
                        cpe = fix_cpe_str(z.text)
                        result = getCPE(cpe,limit)
                        if result:
                            if("csv" in type_output):
                                string_csv=str(host)+"|"+str(cpe)+"|"
                                parser_response_csv(result,string_csv)
                            else:
                                print (colored("Host: " + host,"cyan"))
                                print (colored("cpe: " + cpe,"cyan"))
                                parser_response(result)
                                
    if "csv" in type_output:
        print("\n\tGuarda il risultato in Report.csv")

