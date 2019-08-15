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

# Caveats

This script is in early development and is high experimental, yet works as a charm if installed as described.
A major current caveat is that this initial version only supports ONE relay agent. Currently working on this.

Another caveat is that there is little to none fault handling so if it catches an unknown it will CRASH.. So don't put this into production just yet :)

# Installation

1. Install the proxy  according to design

		- DHCP Server <-> THIS_PROXY! <-> Relay Agent <-> DHCP Client
		- Might work in other scenarios as well, but Ye Might Also Be Fecked!

2. Make sure git, python, pip and virtualenv are installed on the platform of choice

		- If not use "yum install " or "apt-get "  to fullfill these dependencies

3. Install scapy. Fret not, Scapy is well-known packet manipulator used by Cisco Systems among others : 

		- pip install scapy

4. Clone from Github

		- git clone https://github.com/bentole/dhcpProxy.git

5. (Optional) Create a virtual environment to run the app

		- virtualenv ENVDIR 

6. (Optional) Start the virtual environment

		- source ENVDIR/bin/activate
		
7. Create a file named settings.py

		- vi dhcpProyx.py or nano dhcpProxy.py or whatever

8. Start the proxy

		- python ./dhcpProxy.py
		
9. Change the relay information from pointing towards the dhcp server to point towards the proxy

		- For Cisco routers : ip helper-address proxy_addr

10. Good luck, Chuck!

# Settings

###### the listener interface for the proxy
INT = 'ens224' 

# ip address of the listener interface
INT_IP = '10.209.0.2' 

# mac address of the listener interface
INT_MAC = '00:0c:29:53:60:a8' 

# mac address of the default gateway OR dhcp server if on same subnet..
GW_MAC = '70:0f:6a:b3:f7:3f'	

# ip address of the dhcp server
DHCP_SRV = '10.210.6.32' 

# ip address of the relay agent
RELAY_AGENT = '10.209.8.1' 

# 'Print messages during processing'
VERBOSE = True 

