import threading
from scapy import *
import session_class

FILE_LOGGER = "./Ssniffer_logger.log"

class Sniffer(object):
	"""
	The Ssniffer smart sniffer that will
	alert if we got a malware
	"""

	# This function is to inform that we start using our
	# Ssniffer to check what is good and bad
	def __init__(self, ourIP):
		self.file = open(FILE_LOGGER, "w")
		self.ourIP = ourIP
		self.current_packet = None
		self.sessions = {}

		# Sexy information about our Ssinffer
		print "Hello everyone this is the Ssniffer"
		print "This sinffer is much better then any other sniffer beacuse:"
		print "These sniffer give you a warning if you are trying to reach a malware"
		print "Or a malicious hacker trying to reach/hack your computer"
		print "So, thank you for using us and hope we will do a great job"


    def make_stemp(self,pkt):
        ip_send = pkt[IP].src
        ip_rec = pkt[IP].dst

        if TCP in pkt:
            port_send = pkt[TCP].sport
            port_rec  = pkt[TCP].dport
            protocol  = "TCP"
        elif UDP in pkt:
            port_send = pkt[UDP].sport
            port_rec  = pkt[UDP].dport
            protocol  = "UDP"
        elif ICMP in pkt:
            port_send = pkt[ICMP].sport
            port_rec  = pkt[ICMP].dport
            protocol  = "ICMP"
        else:
            return None # if not TCP or UDP or ICMP

        return (ip_send, ip_rec, port_send, port_rec, protocol)

    def set_session(self, packet, stemp):
        self.sessions[stemp] = session_class.session(packet, stemp)

	# This function will give us the next packet to check if correct
    def update_next_packet(self):
		packet = sniff(filter="tcp.len > 0", count = 1)
		(ip_send, ip_rec, port_send, port_rec) = make_stemp(packet)
		stemp = set([ip_send, ip_rec, port_send, port_rec])
        if self.sessions.get(stemp) is None:
            threading.Thread(target=(self.set_sessions()), args={packet, stemp})
        else:
            threading.Thread(target=self.sessions[stemp].update_session, args={packet}).start()