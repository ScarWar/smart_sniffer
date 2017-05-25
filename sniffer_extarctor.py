from scapy.all import *
from pandas import DataFrame
import sys

mega = 1024**2

from session_class import Session


def get_n_big(packets):
    cnt = 0
    for p in packets:
        print get_packet_size(p[0])
        if get_packet_size(p[0]) >= 1000:
            cnt += 1
    return cnt


def get_n_small(packets):
    cnt = 0
    for p in packets:
        if get_packet_size(p[0]) <= 300:
            cnt += 1
    return cnt


def get_packet_size(pkt):
    return len(pkt)


def get_lens_per_sec(packets):
    total = 0
    for p in packets:
        total += get_packet_size(p)
    time_dif = packets[-1][1] - packets[0][1]
    return total / time_dif


def is_client(_packet):
    """
    SYN = 0x02
    ACK = 0x10
    :param _packet: 
    :return: source ip if client
    """
    t = _packet[TCP]
    if t.flags & 0x02 and not t.flags & 0x10:
        return True
    return False


def cap_session(pcap_path):
    capture = rdpcap(pcap_path)
    first = True
    curr_session = None
    session_info = [0, ] * 5
    for packet in capture:
        if not packet.haslayer(TCP) and not packet.haslayer(IP) and packet.len <= 0:
            pass

        if first:
            first = False
            if is_client(packet):
                session_info[0] = packet[IP].src
                session_info[1] = packet[IP].dst
                session_info[4] = "TCP"
                curr_session = Session(packet, session_info, session_info[0])
            else:
                return None
        else:
            curr_session.update_session(packet)

    return curr_session


'''
Simple sniffer
'''


class FeatureGetter(object):
    """docstring for feature getter """

    def __init__(self, session):
        self.session = session
        self.all_packets = session.combined
        self.in_pkts = session.income
        self.out_pkts = session.outcome

    def get_feat(self):
        proto = self.session.session_info[4] == "TCP"
        # first_pkt = self.all_packets[0] #the one who started the tcp connection
        # starter = first_pkt.getlayer(S.IP).src

        nfull_pkt_s = get_n_small(self.in_pkts)  # number of full packets in the client
        nfull_pkt_c = get_n_big(self.out_pkts)  # number of small packets in the client
        # get max/mean len of packet
        cc_len_sec = get_lens_per_sec(self.in_pkts)
        # get max/mean out_pkt
        cl_len_sec = get_lens_per_sec(self.out_pkts)
        # max_cc_delay, mean_cc_delay = self.get_cc_delay_statistics()  # use in_pkt
        return proto, nfull_pkt_c, nfull_pkt_s, cc_len_sec, cl_len_sec

    def get_cc_delay_statistics(self):
        for p in self.all_packets:
            pass
        
SERVER = ''
OTHER = ''
OUT=''

SERVER = ''
OTHER = ''
OUT=''

def data_gen():
	lst = []
	for file in os.listdir(input_dir):
		st = os.stat(file)
		if st.st_size > 30* mega:
			continue
		s = cap_session(file)
		getter = FeatureGetter(s)
		lst.append((getter,('malware')))
		print "mal feat ext. {}".file

	for file in os.listdir(OTHER):
		st = os.stat(file)
		if st.st_size > 30* mega:
			continue
		s = cap_session(file)
		getter = FeatureGetter(s)
		lst.append((getter,('benign')))
		print "benign feat ext. {}".file
	df = DataFrame(lst, columns=['features', 'lables'])
	df.to_csv(OUT)
	print "Done writting feat."


def main(argv):
    _session = cap_session(argv[1])
    if _session is None:
        print 'Shit happens'
        sys.exit(0)
    getter = FeatureGetter(_session)
    print getter.get_feat()


if __name__ == '__main__':
    main(sys.argv)
