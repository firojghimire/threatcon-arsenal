#!/usr/bin/python
from av_api import av_api
import json
s = av_api()

#result = s.av_ip('54.148.159.233')
result = s.av_domain('api.ipify.org')
#result = s.av_hash('af1b82ff61d13d045664bfe3b760736c1243b71f97b851473bbaaa58c0686f75')

print result