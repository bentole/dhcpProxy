# DHCP PROXY

DHCP Proxy For Deleting and Inserting Relayed Option 82 information

# About

In environments like Cisco SD Access or Cisco ACI where option 82 is required, the DHCP server must support this by 
returning this information in its replies. If this is omitted the packets will never get back
to the client if the design relies on it.

This proxy provides a fix by stripping the option 82 information in the request and
re-inserting it in the offer, meaning the server is oblivious of this information.

The long time solution is to use a DHCP server that supports this, but 
this proxy is a feasable short time solution

This proxy can be used to manipulate other options as well, yet as of now it's only for option 82.
Open an [issue](https://github.com/bentole/dhcpProxy/issues) if you have any thoughts or ideas on how to 
further utilize or improve this proxy

# Caveats

This proxy is in early development and is highly experimental, yet works as a charm if installed as described.
A major current caveat is that this initial version only supports ONE relay agent. Currently working on this.

Another caveat is that there is little to none fault handling so if it catches an unknown it will CRASH.. So don't put this into production just yet :)


# Installation

1. Install the proxy according to design

		DHCP Server <-> THIS_PROXY! <-> Relay Agent <-> DHCP Client
		Might work in other scenarios as well, but Ye Might Also Be Fecked!

2. Make sure git, python, pip and optionally virtualenv are installed on the platform of choice

		If not use "yum install " or "apt-get "  to fullfill these dependencies

3. Install scapy. Fret not, Scapy is a well-known packet manipulator used by Cisco Systems among others

		pip install scapy
		
4. Clone from Github

		git clone https://github.com/bentole/dhcpProxy.git

5. Create a file named settings.py and put it in the same directory as dhcpProxy.py. See Settings below

		vi settings.py or nano settings.py or whatever

6. Start the proxy

		python ./dhcpProxy.py
		
7. Change the relay information from pointing towards the dhcp server to point towards the proxy

		For Cisco routers : ip helper-address proxy_addr

8. Good luck, Chuck!

# Settings

Copy & paste the below content and save it to settings.py. Just make sure it's placed in the same directory as the main scriptfile.

```
# the listener interface for the proxy
INT = 'ifname' 
# ip address of the listener interface
INT_IP = 'w.x.y.z' 
# ip address of the dhcp server
DHCP_SRV = 'w.x.y.z' 
# Log to the specified file or set to False for no logging
VERBOSE = True
LOGFILE = '/var/log/dhcpproxy.log' # Make sure this is placed in the correct logfolder
```
# Install as service

1. Edit dhcpproxy.service and make sure that the file paths are correct
2. Put dhcpproxy.service file in the correct systemd folder

	-On Centos: /usr/lib/systemd/system
	-On Ubuntu: /etc/systemd/system
	-Might be other locations as well, you'll figure it out.
	
3. Reload systemd to read the new service file

	-sudo systemctl daemon-reload
	
4. Start the service

	-sudo systemctl start dhcpproxy
	
5. Check status or stop

	-sudo systemctl status dhcpproxy
	-sudo systemctl stop dhcpproxy
	
6. Enable at startup

	-sudo systemctl enable dhcpproxy
	
7. Puh, Done! Now tail the logfile to see what's going on

	-tail -f /var/log/dhcpproxy.log
