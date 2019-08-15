# dhcpProxy
DHCP Proxy For Deleting and Inserting Relayed Option 82

# ABOUT

In environments where option 82 is needed, the DHCP server must support this option as well, by 
returning this information in its offer. If this is omitted the reply will never get back
to its source as long as the design requires option 82.

This proxy provides a fix to this by stripping the option 82 information in the request and
re-inserting it in the offer towards the client.

The long time solution is to use a DHCP server that supports this option, but this proxy is considered
a short time solution

# Installation

1. Install the proxy  according to design
		- DHCP Server <-> THIS_PROXY! <-> Relay Agent <-> DHCP Client
		- Might work in other scenarios as well, but Ye Might Also Be Fecked!

2. Make sure git, python, pip and virtualenv are installed on the platform of choice
		- If not use "yum install " or "apt-get" to complete these dependencies


4. Clone from Github (Private Repository)
		- git clone https://github.com/bentole/dhcpProxy.git

5. (Optional) Create a virtual environment to run the app
		- virtualenv ENVDIR 

6. (Optional) Start the virtual environment
		- source ENVDIR/bin/activate

3. Install scapy using
		- pip install scapy

7. Start the proxy
		- python ./dhcpProxy.py

8. Good luck, Chuck!

# Settings

# the listener interface for the proxy
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

