# adfsbrute

A script to test credentials against Active Directory Federation Services (ADFS), calculating the ADFS url of an organization and allowing password spraying or bruteforce attacks. 

The main idea is carrying out password spraying attacks with a random and high delay between each test and using a list of proxies or Tor to make the detection by the Blue Team more difficult. Brute force attacks are also possible, or testing credentials with the format *username:password* (for example from [Pwndb](https://github.com/davidtavarez/pwndb)). Tested logins will get stored in a log file to avoid testing them twice.


## Usage

```
./adfsbrute.py -t TARGET [-u USER] [-U USER_LIST] [-p PASSWORD] [-P PASSWORD_LIST] [-UL userpassword_list]
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

	* -tp: Tor password (change IP addresses using Tor)

	* -pl: Use a proxy list (change IP addresses using a list of proxy IPs)

	* -r: Randomize the combination of users and passwords. Default: True

	* -l: Log file location with already tested credentials. Default: ./tested.txt

	* -d: Show debug messages. Default: True


![example sprayer](https://i.imgur.com/KP5Cxk5.png)


## Using Tor

To use Tor to change the IP for every request, you must hash a password:

```
tor --hash-password test123
```

In the file /etc/tor/torrc, uncomment the variable *ControlPort* and the variable *HashedControlPassword*, and in this last one add the hash:

```
ControlPort 9051
HashedControlPassword 16:7F314CAB402A81F860B3EE449B743AEC0DED9F27FA41831737E2F08F87
```

Restart the tor service and use this password as argument for the script ("-tp test123" or "--tor_password 123")

```
service tor restart
```

## Note

This script is implemented to test in security audits, DO NOT use without proper authorization from the company owning the ADFS or you will block accounts.