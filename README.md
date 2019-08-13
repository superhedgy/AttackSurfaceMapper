![alt text](https://img.shields.io/badge/Python-3_only-blue.svg "Python 3 only")

![Attack Surface Mapper Logo](https://npercoco.typepad.com/.a/6a0133f264aa62970b0240a49c6ba4200d-800wi "Attack Surface Mapper Logo")

# AttackSurfaceMapper
Attack Surface Mapper is a reconaissaince tool that uses a mixture of open source intellgence and active techniques to expand the attack surface of your target. You feed in a mixture of one or more domains, subdomains and IP addresses and it uses numerous techniques to find more targets. It enumerates subdomains with bruteforcing and passive lookups, Other IPs of the same network block owner, IPs that have multiple domain names pointing to them and so on.

Once the target list is fully expanded it performs passive reconissence on them, taking screenshots of websites, generating visual maps, looking up credentials in public breaches, passive port scanning with Shodan and scraping employees from LinkedIn.

What this means is you're left with hard actionable data gathered from these processes, targets to scan, websites to attack, email addresses to phish and credentials to bruteforce and spray.

## Demo
[![Alt text](https://img.youtube.com/vi/buIQSf_gmdE/0.jpg)](https://www.youtube.com/watch?v=buIQSf_gmdE)

## Getting Started
These instructions will show you the requirements for and how to use Attack Surface Mapper.

## Setup
As this is a Python based tool, it should theoretically run on Linux, ChromeOS ([Developer Mode](https://www.chromium.org/chromium-os/developer-information-for-chrome-os-devices/generic)), macOS and Windows.

[1] Download and Install Attack Surface Mapper
```
$ git clone https://github.com/superhedgy/AttackSurfaceMapper
$ cd AttackSurfaceMapper
$ python3 -m pip install --no-cache-dir -r requirements.txt
```

[2] Provide Attack Surface Mapper with optional API keys to enable more data gathering
```
Open keylist.asm and enter the API Keys.
```

### Optional Parameters
Additional optional parameters can also be set to choose to include active reconnaissance modules in addition to the default passive modules.

```
|<------ AttackSurfaceMapper - Help Page ------>|

positional arguments:
  targets               Sets the path of the target IPs file.

optional arguments:
  -h, --help            show this help message and exit
  -f FORMAT, --format FORMAT
                        Choose between CSV and TXT output file formats.
  -o OUTPUT, --output OUTPUT
                        Sets the path of the output file.
  -sc, --screen-capture
                        Capture a screen shot of any associated Web Applications.
  -sth, --stealth       Passive mode allows reconaissaince using OSINT techniques only.
  -t TARGET, --target TARGET
                        Set a single target IP.
  -V, --version         Displays the current version.
  -w WORDLIST, --wordlist WORDLIST
                        Specify a list of subdomains.
  -sw SUBWORDLIST, --subwordlist SUBWORDLIST
                        Specify a list of child subdomains.
  -e, --expand          Expand the target list recursively.
  -ln, --linkedinner    Extracts emails and employees details from linkedin.
  -v, --verbose         Verbose ouput in the terminal window.

Authors: Andreas Georgiou (@superhedgy)
	 Jacob Wilkin (@greenwolf)```
```

### Example run command
```
python3 ASM.py -t your.site.com -ln -o demo_run -w resources/top100_sublist.txt
```

## Authors
* [Andreas Georgiou](https://github.com/superhedgy)
* [Jacob Wilkin](https://github.com/Greenwolf)

## Acknowledgments
* Thanks to this tool/technique 1, etc etc, name and list all open source projects got inspirations/code from.
* Thanks to `[Your Name Could Be Here, Come Help Out!]` for contributions to the project.

