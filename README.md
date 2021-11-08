
# DAVISCOVERY 0.1v - host & port discovery tool for Linux

_Yep!!_ Another tool for host & port discovery.
    


## Installation

_This tool needs_:

* Python3.
* NMAP must be installed in your system (Linux).
* Required Python libraries: python3-nmap 1.5.1 (https://pypi.org/project/python3-nmap), netifaces 0.10.9 (https://pypi.org/project/netifaces), requests 2.23.0 (https://pypi.org/project/requests)

Install daviscovery.py dependencies by requirements.txt file:

```bash
  unzip daviscovery.zip -d daviscovery/
  cd daviscovery/
  python3 -m pip install -r requirements.txt
  python3 daviscovery.py
```
    
## Usage/Examples

```bash
kali@kali:~$ python3 daviscovery.py 

[*] usage: daviscovery.py -i <interface>

Options:
-------
        python3 daviscovery.py -i lo
        python3 daviscovery.py -i eth0

```


## Optimizations

* Do it Multiplatform.


## Author

- [davidalejandrocano@gmail.com](mailto:davidalejandrocano@gmail.com)  |  David Alejandro Cano

