import threading
from scapy.all import *
import session_class


class Sniffer(object):
    """
    The sniffer smart sniffer that will
    alert if we got a malware
    """

    # This function is to inform that we start using our
    # sniffer to check what is good and bad
    def __init__(self, our_ip):
        # self.file = open(FILE_LOGGER, "w")
        self.our_ip = our_ip
        print "our ip is:"
        print our_ip
        self.current_packet = None
        self.sessions = {}

    def get_sessions(self):
        return self.sessions

    def make_stamp(self, pkt):

        if IP in pkt:
            ip_send = pkt[IP].src
            ip_rec = pkt[IP].dst
        else:
            return None

        if TCP in pkt:
            port_send = pkt[TCP].sport
            port_rec = pkt[TCP].dport
            protocol = "TCP"

        elif UDP in pkt:
            port_send = pkt[UDP].sport
            port_rec = pkt[UDP].dport
            protocol = "UDP"

        elif ICMP in pkt:
            port_send = 1  # pkt[ICMP].sport
            port_rec = 1  # pkt[ICMP].dport
            protocol = "ICMP"

        else:
            return None  # if not TCP or UDP or ICMP

        return ip_send, ip_rec, port_send, port_rec, protocol

    def set_session(self, packet, stemp, our_ip):
        self.sessions[stemp] = session_class.session(packet, stemp, our_ip)

    def decide_stamp(self, five_tuple):
        isLeft = False
        if self.our_ip != str(five_tuple[0]):
            temp1, temp2 = five_tuple[1], five_tuple[3]
            five_tuple[1], five_tuple[3] = five_tuple[0], five_tuple[2]
            five_tuple[0], five_tuple[2] = temp1, temp2
            isLeft = True
        return tuple(five_tuple), isLeft

    # This function will give us the next packet to check if correct
    def update_next_packet(self):
        packet = sniff(count=1)  # filter = "tcp.len > 0",
        packet = packet[0]

        if IP not in packet:
            return

        ip_send = packet[IP].src
        ip_rec = packet[IP].dst

        if ip_send != self.our_ip and ip_rec != self.our_ip:
            return
        print packet.summary()
        if self.make_stamp(packet) is not None:
            ip_send, ip_rec, port_send, port_rec, protocol = self.make_stamp(packet)
            five_tuple = [ip_send, ip_rec, port_send, port_rec, protocol]

            stamp, john = self.decide_stamp(five_tuple)

            if self.sessions.get(stamp) is None:
                threading.Thread(target=self.set_session, args=[packet, stamp, self.our_ip]).start()
            else:
                threading.Thread(target=self.sessions[stamp].update_session, args=[packet, john]).start()

        else:
            print "some kind of error ? None"
