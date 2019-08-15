#!./bin/python
from scapy.all import sniff, ICMP, Ether, IP, UDP, BOOTP, DHCP, sr, send, sendp, srp, AsyncSniffer
import socket
import time

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('0.0.0.0', 67))

interface = 'the listener interface for the proxy'
dhcp_server = 'ip address of the dhcp server'
my_ip = 'ip address of the interface this proxy listens on'
my_mac = 'mac address of the listener interface'
router_mac = 'mac address of the default gateway OR dhcp server if on same subnet..'
orig_relay = 'the ip address of the original relay'
verbose = 1
p_tracker = {}
discover_msg = "Discover mottatt fra relay {}. Forwarder til server {}".format(orig_relay, dhcp_server)
offer_msg = "Offer mottatt fra server {}. Forwarder til relay {}".format(dhcp_server, orig_relay)
opt82 = 'relay_agent_Information'
msg_type = 'message-type'

filter = 'not ip broadcast \
	  and (ip src {} \
	   or ip src {}) \
	  and (udp port 67 or udp port 68) \
	  and not ip src {}'.format(orig_relay, dhcp_server, my_ip)

def change_pkt_info(pkt, dip=None,giaddr=None, opt82action=None):
	pkt[Ether].src = my_mac
	pkt[Ether].dst = router_mac
	pkt[IP].src = my_ip
	pkt[IP].dst = dip
	pkt[IP].chksum = None
	pkt[UDP].chksum = None
	pkt[BOOTP].giaddr = giaddr	

	if opt82action and p_tracker[pkt[BOOTP].xid]["opt82"]:
		if 'delete' in opt82action:
			print "delete status: {}".format(delete_dhcp_option(pkt, opt82))

		elif 'insert' in opt82action:
			print "insert status: {}".format(set_dhcp_option(pkt, opt82, p_tracker[pkt[BOOTP].xid]["opt82"]))

	pkt[UDP].len = len(pkt[UDP])
	pkt[IP].len = len(pkt[IP])

	return pkt

def set_dhcp_option(pkt, option_key, new_value):
	try:
		pkt[DHCP].options.insert(0, (option_key, new_value))
		return "success"
	except Exception(e):
		return "err {}".format(e)

def delete_dhcp_option(pkt, option_key):
	return __dhcp_option(pkt, option_key, 'delete')

def get_dhcp_option(pkt, option_key):
	return __dhcp_option(pkt, option_key, 'get')

def __dhcp_option(pkt, option_key, action):
	for option in pkt[DHCP].options:
		if option_key in str(option[0]):
			try:
				if 'get' in action:
					return option[1]
				elif 'delete' in action:
					pkt[DHCP].options.remove(option)	
					return "success"
				else:
					raise Exception("unknown operation!")

			except Exception(e):
				return "err: {}".format(e)
		
def is_request(pkt):
	return orig_relay in pkt[IP].src \
	and pkt[BOOTP].op == 1 \
	and get_dhcp_option(pkt, msg_type) == 1

def is_offer(pkt):
	return dhcp_server in pkt[IP].src \
	and pkt[BOOTP].op == 2 \
	and get_dhcp_option(pkt, msg_type) == 2

def pkt_receiver(pkt, p_tracker):
		global orig_relay
		if BOOTP in pkt:
			if is_request(pkt):
				if verbose: print discover_msg
				p_tracker[pkt[BOOTP].xid] = { 
				 'giaddr': pkt[BOOTP].giaddr,	
				 'timestamp': time.time(),
				 'opt82': get_dhcp_option(pkt, opt82),
				}
				fwd_pkt = change_pkt_info(pkt.copy(),
								dip=dhcp_server,
								giaddr=my_ip,
								opt82action='delete')
				sendp(fwd_pkt, iface=interface, verbose=False)

			elif is_offer(pkt):
				if verbose: print offer_msg
				if pkt[BOOTP].xid in p_tracker:
					orig_relay = p_tracker[pkt[BOOTP].xid]['giaddr']
					orig_opt82 = p_tracker[pkt[BOOTP].xid]['opt82']

				else:
					print "fant ikke orig_relay i pakken. hvorfor?"
				fwd_pkt = change_pkt_info(pkt.copy(),
								dip=orig_relay,
								giaddr=orig_relay,
								opt82action='insert')
				sendp(fwd_pkt, iface=interface, verbose=False)
			else:
				print 'noise packet {} -> {}'.format(pkt[IP].src, pkt[IP].dst)
		else:
			print "WTF is this packet doing here : {} -> {}".format(pkt[IP].src,pkt[IP].dst)

def tracker_cleanup():
	for xid, value in p_tracker.items():
		if time.time() - value["timestamp"] > 10:
			p_tracker.pop(xid, None)
if __name__=='__main__':
	try:
		t = AsyncSniffer(iface=interface,filter=filter, prn=lambda pkt: pkt_receiver(pkt, p_tracker))
		t.start()
		print "Status: Ready"
		while True:
			time.sleep(10)
			tracker_cleanup()
		#dump = sniff(filter=filter, prn=lambda pkt: pkt_receiver(pkt, p_tracker))
	
	except KeyboardInterrupt:
		t.stop()
		exit()


