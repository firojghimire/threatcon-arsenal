#!/usr/bin/python
import requests, re, time, json
from OTXv2 import OTXv2
import IndicatorTypes
import get_malicious

'''
###########################################################################
Uses:
av_feed = av.domain('rigotechnology.com')
###########################################################################
'''

#OTX Information
otx_server = 'https://otx.alienvault.com/'
api_key = ""
otx = OTXv2(api_key, server=otx_server)

class av_api(object):
	def __parse_domain(self, domain_result):
		result = {}
		try:
			result['otx_url'] = domain_result['malware']['next']
		except:
			result['otx_url']='NA'
		try:
			result['url'] = domain_result['url_list']['url_list'][0]['url']
		except:
			result['url'] = 'NA'
		try:
			result['ip'] = domain_result['url_list']['url_list'][0]['result']['urlworker']['ip']
		except:
			result['ip'] = 'NA'
		try:
			result['indicator'] = domain_result['general']['indicator']
		except:
			result['indicator'] = 'NA'
		'''try:
			count = domain_result['general']['pulse_info']['count']
			i = 0

			for pulse_id in domain_result['general']['pulse_info']['pulses']:
				pulses= pulse_id['id']
				pulse_name = pulse_id['name']
				result['pulse_description_'+str(i)] = {"id":pulses, "name": pulse_name}
				i +=1

		except:
			result['pulse_description'] = "NA"'''
		try:
			count = domain_result['general']['pulse_info']['count']
			i = 0
			pulse_name=""
			for pulse_id in domain_result['general']['pulse_info']['pulses']:
				#pulses= pulse_id['id']
				if (i==0):
					comma =""
				else:
					comma=",,,"
				pulse_name = pulse_name+comma+pulse_id['name']
				#result['pulse_description_'+str(i)] = {"id":pulses, "name": pulse_name}
				i +=1
				if(i==3):
					break
			result['pulse_name']=pulse_name
		except:
			result['pulse_name'] = "NA"
		try:
			result['references'] = domain_result['general']['pulse_info']['references']
		except:
			print "no ref"
		file = open('domain.json', 'w')
		file.write(json.dumps(result))
		file.close()
		print result
		return result

	def __parse_ip(self, ip_result):
		result = {}
		try:
			result['otx_url'] = ip_result['malware']['next']
		except:
			result['otx_url']='NA'
		try:
			result['url'] = ip_result['url_list']['url_list'][0]['url']
		except:
			result['url'] = 'NA'
		try:
			result['ip'] = ip_result['url_list']['url_list'][0]['result']['urlworker']['ip']
		except:
			result['ip'] = 'NA'
		try:
			result['indicator'] = ip_result['general']['indicator']
		except:
			result['indicator'] = 'NA'
		try:
			count = ip_result['general']['pulse_info']['count']
			i = 0
			pulse_name=""
			for pulse_id in ip_result['general']['pulse_info']['pulses']:
				#pulses= pulse_id['id']
				if (i==0):
					comma =""
				else:
					comma=",,,"
				pulse_name = pulse_name+comma+pulse_id['name']
				#result['pulse_description_'+str(i)] = {"id":pulses, "name": pulse_name}
				i +=1
				if(i==3):
					break
			result['pulse_name']=pulse_name
		except:
			result['pulse_name'] = "NA"
		try:
			result['references'] = ip_result['general']['pulse_info']['references']
		except:
			print "no ref"
		file = open('ip.json', 'w')
		file.write(json.dumps(result))
		file.close()
		print result
		return result

#Functions for searching ip/domain/hash
	def av_ip(self, search_string):
		print "b"
		ip_result = get_malicious.ip(otx, search_string)
		if len(ip_result) > 0:
			print "a"
			ip_result = otx.get_indicator_details_full(IndicatorTypes.IPv4, search_string)
			return self.__parse_ip(ip_result)
		else:
			return "{The indicator does not exist in any OTX pulses}"
			pass

	def av_domain(self, search_string):
		domain_result = get_malicious.hostname(otx, search_string)
		if len(domain_result) > 0:
			domain_result = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, search_string)
			'''
			file = open('domain3.json', 'w')
			file.write(json.dumps(domain_result))
			file.close()
			'''
			return self.__parse_domain(domain_result)
		else:
			pass



	def av_hash(self, search_string):
		hash_result =  get_malicious.file(otx, search_string)
   		if len(hash_result) > 0:
   			hash_result = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, search_string)
   			return self.__parse_hash(hash_result)
   		else:
   			pass
