# adfsbrute

A script to test credentials against Active Directory Federation Services (ADFS), calculating the ADFS url of an organization and allowing password spraying or bruteforce attacks. 

The main idea is carrying out password spraying attacks with a random and high delay between each test and using a list of proxies to make the detection by the Blue Team more difficult. Brute force attacks are also possible, or testing credentials with the format *username:password* (for example to test leaked credentials from [Pwndb](https://github.com/davidtavarez/pwndb)). Tested logins will get stored in a log file to avoid testing them twice.


## Usage

```
python3 adfsbrute.py -t TARGET [-u USER] [-U USER_LIST] [-p PASSWORD] [-P PASSWORD_LIST] [-UL userpassword_list]
[-m MIN_TIME] [-M MAX_TIME] [-pl PROXY_LIST] [-r RANDOM_COMBINATIONS] [-l LOG_FILE] [-d DEBUG]
```

The parameters for the attacks are:

	* -t: Target domain. Example: test.com
	
	* -u: Single username
	
	* -U: File with a list of usernames
	
	* -p: Single password
	
	* -P: File with a list of passwords

	* -UP: File with a list of credentials in the format "username:password"

	* -m : Minimum value of random seconds to wait between each test. Default: 300

	* -M : Maximum value of random seconds to wait between each test. Default: 600

	* -pl: Use a proxy list

	* -r: Randomize the combination of users and passwords. Default: True

	* -l: Log file location with already tested credentials. Default: ./tested.txt

	* -d: Show debug messages. Default: True


![example sprayer](https://i.imgur.com/KP5Cxk5.png)


## Note

This script is implemented to test in security audits, DO NOT use without proper authorization from the company owning the ADFS or you will block accounts.