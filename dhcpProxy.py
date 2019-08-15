#!./bin/python
from scapy.all import sniff, ICMP, Ether, IP, UDP, BOOTP, DHCP, sr, send, sendp, srp, AsyncSniffer
import socket
import time
import settings as s

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('0.0.0.0', 67))

<<<<<<< HEAD
=======
interface = 'the listener interface for the proxy'
dhcp_server = 'ip address of the dhcp server'
my_ip = 'ip address of the interface this proxy listens on'
my_mac = 'mac address of the listener interface'
router_mac = 'mac address of the default gateway OR dhcp server if on same subnet..'
orig_relay = 'ip address of the relay agent'
verbose = 1
>>>>>>> 1e3aac97bc2106fe4a00682243a145a87c968a68
p_tracker = {}
discover_msg = "Discover from {}. Relaying to {}".format(s.RELAY_AGENT, s.DHCP_SRV)
offer_msg =    "Offer from {}. Relaying to {}".format(s.DHCP_SRV, s.RELAY_AGENT)
unknown_pkt_msg =  "Irrelevant DHCP pkt received, but that's ok"
no_opt82_msg = "No option 82 found in DHCP header! No worries!"
opt82 = 'relay_agent_Information'
msg_type = 'message-type'

filter = 'not ip broadcast \
	  and (ip src {} \
	   or ip src {}) \
	  and (udp port 67 or udp port 68) \
	  and not ip src {}'.format(s.RELAY_AGENT, s.DHCP_SRV, s.INT_IP)

def change_pkt_info(pkt, dip=None,giaddr=None, opt82action=None):
	pkt[Ether].src = s.INT_MAC
	pkt[Ether].dst = s.GW_MAC
	pkt[IP].src = s.INT_IP
	pkt[IP].dst = dip
	pkt[IP].chksum = None
	pkt[UDP].chksum = None
	pkt[BOOTP].giaddr = giaddr	

	if opt82action and p_tracker[pkt[BOOTP].xid]["opt82"]:
		if 'delete' in opt82action:
			log("Found option 82! Deleting! Status: {}".format(delete_dhcp_option(pkt, opt82)), pkt=pkt)

		elif 'insert' in opt82action:
			log("Re-inserting option 82! Status: {}".format(set_dhcp_option(pkt, opt82, p_tracker[pkt[BOOTP].xid]["opt82"])), pkt=pkt)
	else:
		if pkt[BOOTP].op == 1: log(no_opt82_msg, pkt=pkt)

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
	return s.RELAY_AGENT in pkt[IP].src \
	and pkt[BOOTP].op == 1 \
	and get_dhcp_option(pkt, msg_type) == 1

def is_offer(pkt):
	return s.DHCP_SRV in pkt[IP].src \
	and pkt[BOOTP].op == 2 \
	and get_dhcp_option(pkt, msg_type) == 2

def pkt_receiver(pkt, p_tracker):
		if BOOTP in pkt:
			if is_request(pkt):
				log(discover_msg, pkt=pkt)
				p_tracker[pkt[BOOTP].xid] = { 
				 'giaddr': pkt[BOOTP].giaddr,	
				 'timestamp': time.time(),
				 'opt82': get_dhcp_option(pkt, opt82),
				}
				fwd_pkt = change_pkt_info(pkt.copy(),
								dip=s.DHCP_SRV,
								giaddr=s.INT_IP,
								opt82action='delete')
				sendp(fwd_pkt, iface=s.INT, verbose=False)

			elif is_offer(pkt):
				log(offer_msg, pkt=pkt)
				if pkt[BOOTP].xid in p_tracker:
					#s.RELAY_AGENT = p_tracker[pkt[BOOTP].xid]['giaddr']
					orig_opt82 = p_tracker[pkt[BOOTP].xid]['opt82']

				else:
					log("fant ikke s.RELAY_AGENT i pakken. hvorfor?")
				fwd_pkt = change_pkt_info(pkt.copy(),
								dip=s.RELAY_AGENT,
								giaddr=s.RELAY_AGENT,
								opt82action='insert')
				sendp(fwd_pkt, iface=s.INT, verbose=False)
			else:
				log(unknown_pkt_msg, pkt=pkt)
		else:
			log("WTF is this packet doing here : {} -> {}".format(pkt[IP].src,pkt[IP].dst))

def tracker_cleanup():
	for xid, value in p_tracker.items():
		if time.time() - value["timestamp"] > 10:
			p_tracker.pop(xid, None)
def log(msg, pkt=None):
	if pkt and BOOTP in pkt:
		xid = hex(pkt[BOOTP].xid)
	else:
		xid = "unknown"

	if s.VERBOSE : print '{} - {} : {}'.format(time.asctime(), xid, msg)

if __name__=='__main__':
	try:
		t = AsyncSniffer(iface=s.INT,filter=filter, prn=lambda pkt: pkt_receiver(pkt, p_tracker))
		t.start()
		print "Status: Ready"
		while True:
			time.sleep(10)
			tracker_cleanup()
		#dump = sniff(filter=filter, prn=lambda pkt: pkt_receiver(pkt, p_tracker))
	
	except KeyboardInterrupt:
		t.stop()
		exit()


