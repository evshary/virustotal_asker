#!/usr/bin/python
from subprocess import Popen,PIPE

import json
import urllib
import urllib2
import os
import sys
import time

def main():
	url = "https://www.virustotal.com/vtapi/v2/file/report"

	try:
		with open("setting.conf", "r") as log_file:
			source_path = log_file.readline().strip()
			destination_path = log_file.readline().strip()
			log_path = log_file.readline().strip()
			apikey = log_file.readline().strip()
	
		print "Your source path is "+source_path
		print "Your destination path is "+destination_path
		print "Your log path is "+log_path
		print "Your API key is "+apikey
	except:
		print "Usage: You need to make setting.conf first."
		print "In the file, you should put this content in order:"
		print "source path"
		print "destination path"
		print "log path"
		print "apikey"
		print "./get_mal_result.py"
		sys.exit(0)

	print "Now let's read from "+source_path
	try:
		flist = Popen(["/bin/ls",source_path],stdout=PIPE).stdout.read().split("\n")
		flist.pop()
	except:
		print "Fail to load the source path"
		print "Please check the path!"
		sys.exit(0)

	for fn in flist:
		md5 = os.path.splitext(fn)[0]
		if "_" in md5:
			md5 = md5[0:-2]
		jsonMD5 = destination_path+md5+".json"
		parameters = {"resource":md5,"apikey":apikey}
		
		try:
			print "It's "+md5+" turns."
			data = urllib.urlencode(parameters)
			req = urllib2.Request(url, data)
			response = urllib2.urlopen(req)
			jsonResult = response.read()
			print "Now writing data into "+jsonMD5
			with open(jsonMD5, 'w') as outfile:
				json.dump(jsonResult, outfile, sort_keys = True, indent = 4, ensure_ascii=False)
		except:
			print "Some problems happened with "+md5+"!"
			with open(log_path,"a") as file_handle:
				file_handle.write(md5+"\n")

		time.sleep(15)

if __name__ == '__main__':
	main()
