#!/usr/bin/python
import requests, json

#URL
badip = "https://badips.com/get/info/"

class badips(object):
	def __parse_results(self, json_result):
		result = {}
		try:
			result['Listed'] = json_result.get('Listed')
		except:
			result['Listed'] = 'NA'
		try:
			result['Categories'] = json_result.get('Categories')
		except:
			result['Categories'] = 'NA'
		try:
			result['Scores'] = json_result.get('Score')
		except:
			result['Scores'] = 'NA'
		try:
			result['IP'] = json_result.get('IP')
		except:
			result['IP'] = 'NA'
		file = open('badip.json', 'w')
		file.write(json.dumps(result))
		file.close()
		return result
	def bad_ip(self, search_string):
		#print "ready"
		try:
			json_result = requests.get(badip +'%(search_string)s' %{'search_string':search_string}, timeout=30).json()
		except:
			return {"badip_resp":"could not fetch data from badip"}
		return self.__parse_results(json_result)
	

	
