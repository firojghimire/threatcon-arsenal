import os
import time
import logging
import json
import urllib
import traceback
import socket
from talos import TalosIP
from bad_ips import badips
from av_api import av_api

av = av_api()
sb = TalosIP()
bi = badips()

JSON_FILE='result.json'
API_KEY=''
def search_intel(JSON_FILE, indicator):
        outfile = open(JSON_FILE, 'w+')
        doc=dict()
        SBdata = {}
        VTdata = {}
        AVdata = {}
        BIdata = {}
        try:
            b = False
            check_indicator = indicator.split('.')

            try:
              for i in check_indicator:
                if int(i) in range(0, 256):
                  b = True
            except:
              pass

            print indicator + " Talos check "
            if indicator not in SBdata:
              if b == True:
                try:
                  SBdata[indicator] = sb.lookup_ip(indicator)
                  print SBdata[indicator]
                except Exception, e:
                  print('Error: '+ str(e))
              else:
                try:
                  SBdata[indicator] = sb.lookup_domain(indicator)
                  print SBdata[indicator]
                except:
                  pass
            else:
              doc = dict(doc, **SBdata[indicator])
              print SBdata[indicator]
            print indicator + " Alien check "
            if indicator not in AVdata:
              if b == True:
                try:
                  AVdata[indicator] = av.av_ip(indicator)
                  print AVdata[indicator]
                except:
                  pass
              else:
                try:
                  AVdata[indicator] = av.av_domain(indicator)
                  print AVdata[indicator]
                except:
                  pass
              doc = dict(doc, **AVdata[indicator])

            else:
              doc = dict(doc, **AVdata[indicator])
              print AVdata[indicator]




            print indicator + " BadIP check "
            if indicator not in BIdata:
              try:
                BIdata[indicator] = bi.bad_ip(indicator)
                print BIdata[indicator]
                doc = dict(doc, **BIdata[indicator])
              except:
                pass
            else:
              print BIdata[indicator]
              doc = dict(doc, **BIdata[indicator])




            print indicator + " VirusTotal check "
            if indicator not in VTdata:
                if b == True:
                  try:
                    VTdata[indicator] = get_VT_score_ip(indicator)
                    print "VTScore="+str(VTdata[indicator])
                    doc['VT_score'] = VTdata[indicator]
                  except Exception as e:
                    print e
                    pass
                else:
                  try:
                    VTdata[indicator] = get_VT_score_domain(indicator)
                    print "VTScore="+str(VTdata[indicator])
                    doc['VT_score'] = VTdata[indicator]
                  except Exception as e:
                    print e
                    pass
            else:
              doc['VT_score'] = VTdata[indicator]
              print "VTScore="+VTdata[indicator]
            try:
                json.dump(doc,outfile)
                outfile.write('\n')
            except Exception,e:
                print e
            print('Finished')
        except:
            pass
        outfile.close()

#get VT_Score
def get_VT_score_ip(ip):
  url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
  parameters = {'ip': ip, 'apikey':API_KEY}
  try:
      response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
      #print(response)
      response_dict = json.loads(response)

      if response_dict['detected_urls']:
         if response_dict['detected_urls'][0]['positives']:
            return response_dict['detected_urls'][0]['positives']

         else:
           # print("URL detected. No information")
            return 0
      else:
          #print("Missing IP address")
          return 0

  except ValueError:
      #print("No JSON object could be decoded")
      return 0

  except:
      #print("Something happened")
      return 0

def get_VT_score_domain(domain):
  url = 'https://www.virustotal.com/vtapi/v2/domain/report'
  parameters = {'domain': domain, 'apikey':API_KEY}
  try:
      response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
      #print(response)
      response_dict = json.loads(response)

      if response_dict['detected_urls']:
         if response_dict['detected_urls'][0]['positives']:
            return response_dict['detected_urls'][0]['positives']

         else:
           # print("URL detected. No information")
            return 0
      else:
          #print("Missing IP address")
          return 0

  except ValueError:
      #print("No JSON object could be decoded")
      return 0

  except:
      #print("Something happened")
      return 0

def main():
    try:
        indicator=raw_input("enter the indicator ip or domain >> ")
        search_intel(JSON_FILE, indicator)
    except  Exception, err:
        pass
    #traceback.print_exc()

if __name__ == '__main__':
    main()
