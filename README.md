# o365_slow_spray

This script calculates the ADFS url of an organization and tests one or many users and one or many passwords, allowing password spraying or bruteforce attacks. Implemented for custom ADFS (not against Microsoft) to test in security related audits. 

The idea is carrying out a password spraying attack with a random (and very high) number of seconds between each test and a proxy list to avoid detection. To avoid testing the same credentials the failed ones are stored in a log file.


## Usage

```
python3 main.py -t TARGET [-u USER] [-U USER_LIST] [-p PASSWORD] [-P PASSWORD_LIST] [-m MIN_TIME] [-M MAX_TIME] [-pl PROXY_LIST] [-r RANDOM_COMBINATIONS] [-l LOG_FILE] [-d DEBUG]
```

The parameters for the attacks are:

	* -t: Target domain. Example: test.com
	
	* -u: Single username to test
	
	* -U: File with a list of usernames to test
	
	* -p: Single password to test
	
	* -P: File with a list of passwords to test

	* -m : Minimum value of random seconds to wait between each test. Default: 300

	* -M : Maximum value of random seconds to wait between each test. Default: 600

	* -pl: Use a proxy list

	* -r: Randomize the combination of users and passwords. Default: True

	* -l: Log file location with already tested credentials. Default: ./tested.txt

	* -d: Show debug messages. Default: True


![example sprayer](https://i.imgur.com/KP5Cxk5.png)