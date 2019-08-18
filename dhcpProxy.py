#!/usr/bin/env python
from scapy.all import sniff, ICMP, Ether, IP, UDP, BOOTP, DHCP, sr, send, sendp, srp, AsyncSniffer
import socket
import time
import settings as s

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('0.0.0.0', 67))

p_tracker = {}
discover_msg = "Discover from {ra}. Relaying to {dhcpsrv}"
offer_msg =    "Offer from {ra}. Relaying to {dhcpsrv}"
err_unknown_bootp_pkt =  "Irrelevant DHCP pkt received, but that's ok"
err_unknown_pkt =  "Unknown pkt received. W-T-F!"
no_opt82_msg = "No option 82 found in DHCP header! Should it?"
opt82_found_msg = "Found option 82! Deleting! Status: {status}"
opt82_reinsert_msg = "Re-inserting option 82! Status: {status}"
err_xid_notfound = "Transaction ID not found!"

opt82 = 'relay_agent_Information'
opt_msg_type = 'message-type'
opt_vendor_class_id = 'vendor_class_id'

filter = 'not ip broadcast \
	  and (udp port 67 or udp port 68) \
	  and not ip src {}'.format(s.INT_IP)

def change_pkt_info(pkt, dip=None,giaddr=None, opt82action=None):
	pkt[IP].src = s.INT_IP
	pkt[IP].dst = dip
	pkt[IP].chksum = None
	pkt[UDP].chksum = None
	pkt[BOOTP].giaddr = giaddr	
	
	
	def handle_opt82(args):
		if args: return log(args[1].format(status=args[0](*args[2])), pkt=pkt)	
		return log(no_opt82_msg, pkt=pkt)

	d = { (True, 'delete'): (delete_dhcp_option, 
				 opt82_found_msg, 
				 (pkt, opt82)),
	      (True, 'insert'): (set_dhcp_option, 
				 opt82_reinsert_msg, 
			         (pkt, opt82,p_tracker[pkt[BOOTP].xid]["opt82"])),
	}
	eval_82 = bool(opt82action and p_tracker[pkt[BOOTP].xid]["opt82"])
	handle_opt82(d.get((eval_82, opt82action), None))

	pkt[UDP].len = len(pkt[UDP])
	pkt[IP].len = len(pkt[IP])

	return pkt[IP]

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
		{ 'get' : lambda x: option[1],
		  'delete': lambda x: 'success' if pkt[DHCP].options.remove(option)
    }.get(option_key, lambda x: 'unknown operation')
    
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
	return pkt[BOOTP] \
	and pkt[BOOTP].op == 1 \
	and get_dhcp_option(pkt, opt_msg_type) == 1 \
	and 'PXEClient' in get_dhcp_option(pkt, opt_vendor_class_id)
	return False

def is_offer(pkt):
	return pkt[BOOTP] \
	and s.DHCP_SRV in pkt[IP].src \
	and pkt[BOOTP].op == 2 \
	and get_dhcp_option(pkt, opt_msg_type) == 2
	return False

def handle_request(pkt):
	p_tracker[pkt[BOOTP].xid] = {
	 'giaddr': pkt[BOOTP].giaddr,
	 'timestamp': time.time(),
	 'opt82': get_dhcp_option(pkt, opt82),
	}
	relay_agent = p_tracker[pkt[BOOTP].xid]['giaddr']
	log(discover_msg.format(ra=relay_agent, dhcpsrv=s.DHCP_SRV), pkt=pkt)
	fwd_pkt = change_pkt_info(pkt.copy(),
					dip=s.DHCP_SRV,
					giaddr=s.INT_IP,
					opt82action='delete')
	send(fwd_pkt, iface=s.INT, verbose=False)

def handle_offer(pkt):
	if pkt[BOOTP].xid in p_tracker:
		relay_agent = p_tracker[pkt[BOOTP].xid]['giaddr']
		orig_opt82 = p_tracker[pkt[BOOTP].xid]['opt82']

	else:
		log(err_xid_notfound)
	log(offer_msg.format(ra=relay_agent, dhcpsrv=s.DHCP_SRV), pkt=pkt)
	fwd_pkt = change_pkt_info(pkt.copy(),
				dip=relay_agent,
				giaddr=relay_agent,
				opt82action='insert')
	send(fwd_pkt, iface=s.INT, verbose=False)

def handle_unknown_bootp(pkt):
	log(err_unknown_bootp_pkt, pkt=pkt)

def handle_unknown_pkt(pkt):
	log(err_unknown_pkt, pkt=pkt)	


def pkt_receiver(pkt, p_tracker):
	{ (True, True, False) : handle_request,
	  (True, False, True) : handle_offer,
	  (True, False, False) : handle_unknown_bootp,
	}.get((BOOTP in pkt, is_request(pkt), 
	        is_offer(pkt)), handle_unknown_pkt)(pkt)

def tracker_cleanup():
	for xid, value in p_tracker.items():
		if time.time() - value["timestamp"] > 10:
			p_tracker.pop(xid, None)
def log(msg, pkt=None):
	if pkt and BOOTP in pkt:
		xid = hex(pkt[BOOTP].xid)
	else:
		xid = "unknown"

	if s.VERBOSE : 
		with open(s.LOGFILE,'a') as f: 
			f.write('{} - {} : {}\n'.format(time.asctime(), xid, msg))

if __name__=='__main__':
	try:
		t = AsyncSniffer(iface=s.INT,
				 filter=filter, 
				 prn=lambda pkt: pkt_receiver(pkt, p_tracker))
		t.start()
		print "Status: Ready"
		while True:
			time.sleep(10)
			tracker_cleanup()	
	except KeyboardInterrupt:
		t.stop()
		exit()
