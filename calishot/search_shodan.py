#! /usr/bin/python3
import shodan
import requests
import time
import re
import math

#Search shodan

def search_shodan(search_str, page_start, page_stop, max_retry):
	content_lengths=[]
	etags=[]
	calibre_IP_list=[]
	for x in range(page_start,page_stop+1):		#range is exclusive of the final value (i.e in range(1,20) goes up to 19)
		#shodan times out _a lot_.  Code below is a bad workaround, needs to be fixed
		for n in range(1,max_retry+1):
			try:
				results = shodan_instance.search(search_str,page=x)
				break	#exit the retry loop if succesful
			except:
				if n<max_retry+1:
					print("error searching shodan, trying again in 10 seconds")
					time.sleep(10)
					continue
				else:	#give information found up until this point.  Means no need to re-search the same pages.
					print(content_lengths)
					print(etags)
					print(calibre_IP_list)
					print('shodan error: failed at page {}'.format(x))
					raise	#raise some sort of exception here						
		for y in results['matches']:
			calibre_IP_list.append('{}:{}'.format(y['ip_str'],y['port']))	#all search results have an IP and port
			try:	#not all searches have a content length field or ETag
				content_lengths.append(re.search("Content-Length: ([0-9]+)",y['data']).group(1))
			except:
				pass
			try:
				etags.append(re.search("ETag: \"([0-9a-z]+)\"",y['data']).group(1))
			except:
				pass
	calibre_IP_list = list(set(calibre_IP_list))
	content_lengths = list(set(content_lengths))
	etags = list(set(etags))
	
	#I'm sure there is a better way to return a bunch of values...	
	return [calibre_IP_list,content_lengths,etags]


#consists of two parts; find potential hosts and check potential hosts
#1) Shodan scan
# Not all calibre libraries have "Server: Calibre" in the banner.
# When hosted with nginx on port 443 they have "Server: nginx...".  Cant search with this, lots of false positves
# Most libraries on port 443 are password protected, however some are not. so we cant ignore these.

#"ETag: [a-b0-9]*" and "Content-Length [0-9]*"  can identify clusters of calibre libraries
#Content-Length may give false positives
#Neither ETag nor content length are unique to a calibre version. Content-Length and ETag have m:m relationship

# ETag and Content-length are useful as search strings for two reasons
#1) searching when a premium shodan account is not available
#2) to find calibre-servers that may have been missed for various reasons (not all hosts have "Server: Calibre" in banner)

#2) Check potential hosts
#When accessing the main page, Calibre injects Auth after returning http 200 status code
#thus cant use shodan to find if the hosts have passwords or not
#Internal calibre pages request Auth first, so use this feature to see if host is accessible or not
#check the url http://ip:port/mobile (assumes /mobile is present on all calibre servers)

#TODO	Check if https is required
#TODO	Code to filter false positives (like annoying honeypots) 
#TODO	check if all calibre servers have /mobile option

#set some values
SHODAN_API_KEY=''									#insert API key here
max_search_retry=10									#shodan times out a lot, set number of times to retry search


shodan_instance = shodan.Shodan(SHODAN_API_KEY)
account=shodan_instance.info()['plan']			#check the account plan of the API key

search_list=[]
if account=='dev':		#different search method depend on account type, dev is more accurate but not free.
	page_stop=math.ceil(shodan_api.count(search_str)['total']/100) #round up to avoid off by 1 error
	page_start=1
	search_list=['ETag Server calibre']
elif account!='dev':		#free accounts
	#this list is taken from the calibre website, I assume it is correct
	version_list=['0.6.55','0.6.54','0.6.53','0.6.52','0.6.51','0.6.50','0.6.49','0.6.48','0.6.47','0.6.46','0.6.45','0.6.44',
				'0.6.43','0.6.42','0.6.41','0.6.40','0.6.39','0.6.38','0.6.37','0.6.36','0.6.35','0.6.34','0.6.33','0.6.32',
				'0.6.31','0.6.30','0.6.29','0.6.28','0.6.27','0.6.26','0.6.25','0.6.24','0.6.23','0.6.22','0.6.21','0.6.20',
				'0.6.19','0.6.18','0.7.59','0.7.58','0.7.57','0.7.56','0.7.55','0.7.54','0.7.53','0.7.52','0.7.51','0.7.50',
				'0.7.49','0.7.48','0.7.47','0.7.46','0.7.45','0.7.44','0.7.43','0.7.42','0.7.41','0.7.40','0.7.38','0.7.37',
				'0.7.36','0.7.35','0.7.34','0.7.33','0.7.32','0.7.31','0.7.30','0.7.29','0.7.28','0.7.27','0.7.26','0.7.25',
				'0.7.24','0.7.23','0.7.22','0.7.21','0.7.20','0.7.19','0.7.18','0.7.17','0.7.16','0.7.15','0.7.14','0.7.13',
				'0.7.12','0.7.11','0.7.10','0.7.9','0.7.8','0.7.7','0.7.6','0.7.5','0.7.4','0.7.3','0.7.2','0.7.1','0.7.0',
				'0.8.70','0.8.69','0.8.68','0.8.67','0.8.66','0.8.65','0.8.64','0.8.63','0.8.62','0.8.61','0.8.60','0.8.59',
				'0.8.58','0.8.57','0.8.56','0.8.55','0.8.54','0.8.53','0.8.52','0.8.51','0.8.50','0.8.49','0.8.48','0.8.47',
				'0.8.46','0.8.45','0.8.44','0.8.43','0.8.42','0.8.41','0.8.40','0.8.39','0.8.38','0.8.37','0.8.36','0.8.35',
				'0.8.34','0.8.33','0.8.32','0.8.31','0.8.30','0.8.29','0.8.28','0.8.27','0.8.26','0.8.25','0.8.24','0.8.23',
				'0.8.22','0.8.21','0.8.20','0.8.19','0.8.18','0.8.17','0.8.16','0.8.15','0.8.14','0.8.13','0.8.12','0.8.11',
				'0.8.10','0.8.9','0.8.8','0.8.7','0.8.6','0.8.5','0.8.4','0.8.3','0.8.2','0.8.1','0.8.0','0.9.44','0.9.43',
				'0.9.42','0.9.41','0.9.40','0.9.39','0.9.38','0.9.37','0.9.36','0.9.35','0.9.34','0.9.33','0.9.32','0.9.31',
				'0.9.30','0.9.29','0.9.28','0.9.27','0.9.26','0.9.25','0.9.24','0.9.23','0.9.22','0.9.21','0.9.20','0.9.19',
				'0.9.18','0.9.17','0.9.16','0.9.15','0.9.14','0.9.13','0.9.12','0.9.11','0.9.10','0.9.9','0.9.8','0.9.7',
				'0.9.6','0.9.5','0.9.4','0.9.3','0.9.2','0.9.1','0.9.0','1.48.0','1.47.0','1.46.0','1.45.0','1.44.0','1.43.0',
				'1.42.0','1.41.0','1.40.0','1.39.0','1.38.0','1.37.0','1.36.0','1.35.0','1.34.0','1.33.0','1.32.0','1.31.0',
				'1.30.0','1.29.0','1.28.0','1.27.0','1.26.0','1.25.0','1.24.0','1.23.0','1.22.0','1.21.0','1.20.0','1.19.0',
				'1.18.0','1.17.0','1.16.0','1.15.0','1.14.0','1.13.0','1.12.0','1.11.0','1.10.0','1.9.0','1.8.0','1.7.0',
				'1.6.0','1.5.0','1.4.0','1.3.0','1.2.0','1.1.0','1.0.0','2.85.1','2.85.0','2.84.0','2.83.0','2.82.0','2.81.0',
				'2.80.0','2.79.1','2.79.0','2.78.0','2.77.0','2.76.0','2.75.1','2.75.0','2.74.0','2.73.0','2.72.0','2.71.0',
				'2.70.0','2.69.0','2.68.0','2.67.0','2.66.0','2.65.1','2.65.0','2.64.0','2.63.0','2.62.0','2.61.0','2.60.0',
				'2.59.0','2.58.0','2.57.1','2.57.0','2.56.0','2.55.0','2.54.0','2.53.0','2.52.0','2.51.0','2.50.1','2.50.0',
				'2.49.0','2.48.0','2.47.0','2.46.0','2.45.0','2.44.1','2.44.0','2.43.0','2.42.0','2.41.0','2.40.0','2.39.0',
				'2.38.0','2.37.1','2.37.0','2.36.0','2.35.0','2.34.0','2.33.0','2.32.1','2.32.0','2.31.0','2.30.0','2.29.0',
				'2.28.0','2.27.0','2.26.0','2.25.0','2.24.0','2.23.0','2.22.0','2.21.0','2.20.0','2.19.0','2.18.0','2.17.0',
				'2.16.0','2.15.0','2.14.0','2.13.0','2.12.0','2.11.0','2.10.0','2.9.0','2.8.0','2.7.0','2.6.0','2.5.0','2.4.0',
				'2.3.0','2.2.0','2.1.0','2.0.0','3.48.0','3.47.1','3.47.0','3.46.0','3.45.2','3.45.1','3.45.0','3.44.0','3.43.0',
				'3.42.0','3.41.3','3.41.2','3.41.1','3.41.0','3.40.1','3.40.0','3.39.1','3.39.0','3.38.1','3.38.0','3.37.0',
				'3.36.0','3.35.0','3.34.0','3.33.1','3.32.0','3.31.0','3.30.0','3.29.0','3.28.0','3.27.1','3.27.0','3.26.1',
				'3.26.0','3.25.0','3.24.2','3.24.1','3.24.0','3.23.0','3.22.1','3.22.0','3.21.0','3.20.0','3.19.0','3.18.0',
				'3.17.0','3.16.0','3.15.0','3.14.0','3.13.0','3.12.0','3.11.1','3.11.0','3.10.0','3.9.0','3.8.0','3.7.0','3.6.0',
				'3.5.0','3.4.0','3.3.0','3.2.1','3.2.0','3.1.1','3.1.0','3.0.0','4.19.0','4.18.0','4.17.0','4.16.0','4.15.0',
				'4.14.0','4.13.0','4.12.0','4.11.2','4.11.1','4.11.0','4.10.1','4.10.0','4.9.1','4.9.0','4.8.0','4.7.0','4.6.0',
				'4.5.0','4.4.0','4.3.0','4.2.0','4.1.0','4.0.0']
	for v in version_list:
		search_list.append('Keep Alive etag server calibre {}'.format(v))		#additional text prevents false positves
	page_start=1
	page_stop=1


content_lengths=[]
etags=[]
addresses=[]
for search_str in search_list:
	print(search_str)
	results = search_shodan(search_str,page_start,page_stop,max_search_retry)
	addresses=addresses+results[0]
	content_lengths=content_lengths+results[1]
	etags=etags+results[2]

#deduplicate these so we only search once
content_lengths = list(set(content_lengths))
etags = list(set(etags))

#search shodan again using etags and content_lengths
for s in content_lengths:
	search_str="Content-Length: {}".format(s)
	results = search_shodan(search_str,1,1,max_search_retry)	#dont want to use up query credits here, only search first 100
	addresses=addresses+results[0]

for s in etags:
	search_str="ETag: {}".format(s)
	results = search_shodan(search_str,1,1,max_search_retry)
	addresses=addresses+results[0]


addresses = list(set(addresses))

#now we poll the potential calibre server to see if it works!
#Ideally we could find this info from shodan, but calibre injects auth request after returning http status code
#Luckily the auth request is sent first for internal calibre pages,
#use status of /mobile as test to see if it's 1) a calibre server and 2) not password protected (i.e returns 200) 
hosts={}
for x in addresses:
	request_string='http://{}/mobile'.format(x)
	print(request_string)
	try:
		r=requests.get(request_string,timeout=5)	#servers are often on a home connection, thus not always online
		hosts[x]=r.status_code
	except:
		hosts[x]='Not_Responding'
		continue

#output list of hosts that dont require authentication
for h in hosts:
	if hosts[h]==200:
		print(h)


