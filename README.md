# DHCP PROXY
DHCP Proxy For Deleting and Inserting Relayed Option 82 information

# About

In environments where option 82 is required, the DHCP server must support this option by 
returning this information in its offer. If this is omitted the reply will never get back
to the client as long as the design requires option 82.

This proxy provides a fix by stripping the option 82 information in the request and
re-inserting it in the offer, meaning the server is oblivious about this information.

The long time solution is to use a DHCP server that supports this option, but this proxy is feasable
short time solution

# Installation

1. Install the proxy  according to design

		- DHCP Server <-> THIS_PROXY! <-> Relay Agent <-> DHCP Client
		- Might work in other scenarios as well, but Ye Might Also Be Fecked!

2. Make sure git, python, pip and virtualenv are installed on the platform of choice

		- If not use "yum install " or "apt-get "  to fullfill these dependencies

3. Install scapy. Fret not, Scapy is well-known packet manipulator used by Cisco Systems among others : 

		- pip install scapy

4. Clone from Github (Private Repository)

		- git clone https://github.com/bentole/dhcpProxy.git

5. (Optional) Create a virtual environment to run the app

		- virtualenv ENVDIR 

6. (Optional) Start the virtual environment

		- source ENVDIR/bin/activate
		
7. Change the variables on top of the script according to your setup

		- vi dhcpProyx.py or nano dhcpProxy.py or whatever

7. Start the proxy

		- python ./dhcpProxy.py
		
8. Change the relay information from pointing towards the dhcp server to point towards the proxy

		- For Cisco routers : ip helper-address proxy_addr

8. Good luck, Chuck!

