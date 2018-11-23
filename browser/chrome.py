import os
import sqlite3
import operator
import json
import urllib
import matplotlib.pyplot as plt
import pprint
import time
from talos import TalosIP
data=[]
sb = TalosIP()
conf=open("config","r")
configs=conf.readlines()
API_KEY=configs[0].split("=")[1].strip()
path=configs[1].split("=")[1].strip()
db_name=configs[2].split("=")[1].strip()
def get_VT_score(look):
	url = 'https://www.virustotal.com/vtapi/v2/domain/report'
	parameters = {'domain': look, 'apikey':API_KEY}
	check_indicator = look.split('.')
	try:
		for i in check_indicator:
			if int(i) in range(0, 256):
				url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
				parameters = {'ip': look, 'apikey':API_KEY}
	except:
		pass
	
	try:
		#print url
		#print parameters
		response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
		response_dict = json.loads(response)
		#pp = pprint.PrettyPrinter(indent=4)
		#pp.pprint(response_dict)
		if response_dict['detected_urls']:
			if response_dict['detected_urls'][0]['positives']:
				return response_dict['detected_urls'][0]['positives']
			
			else:
				print("URL detected. No information")
				return 0
		else:	
			print("Missing IP address")
			return 0

	except ValueError:
		print response
		print("No JSON object could be decoded")
		return 0

	except Exception as ex:
		print ex
		print("Something happened")
		return 0

def parse(url):
	try:
		parsed_url_components = url.split('//')
		sublevel_split = parsed_url_components[1].split('/', 1)
		domain = sublevel_split[0].replace("www.", "")
		return domain
	except IndexError:
		print "URL format error!"



history_db = os.path.join(path, db_name)

#querying the db
c = sqlite3.connect(history_db)
cursor = c.cursor()
select_statement = "SELECT urls.url, urls.visit_count FROM urls, visits WHERE urls.id = visits.url;"
cursor.execute(select_statement)

results = cursor.fetchall() #tuple

sites_count = {} #dict makes iterations easier :D

for url, count in results:
	url = parse(url)
	if url in sites_count:
		sites_count[url] += 1
	else:
		sites_count[url] = 1
all_urls=[]
for a in sites_count.keys():
	all_urls.append(str(a))
y=0
for l in all_urls:
	kk={}
	b=False
	l=l.split(":")[0]
	if "." in l:
		pass
	else:
		continue
	k=l.split(".")
	for i in k:
		try:
			if int(i) in range(0, 256):
				b=True
			else:
				b=False
		except:
			b=False
			pass
	try:
		if b==True:
			p = sb.lookup_ip(l)
		else:
			p = sb.lookup_domain(l)
	except:
		continue
	o=get_VT_score(l)
	try:
		u=p["web_reputation"]
	except:
		continue
	kk["url"]=l
	kk["web_reputation"]=u
	kk["vt_score"]=o
	try:
		data.append(kk)
	except:
		continue
	print kk
	y=y+1
	print "--"
	time.sleep(12)

file_wrt=open("data.file","w+")
json.dump(data,file_wrt)
file_wrt.close()

