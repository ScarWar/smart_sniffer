from scapy.all import *
import sys

from session_class import session


def get_n_full(packets):
    cnt = 0
    for p in packets:
        # ip = p[0].getlayer(S.IP)
        print p[0]
        # if p.len == 1514:  # max len of packet
        #     cnt += 1
    return cnt


def get_lens_per_sec(packets):
    total = 0
    for x in packets:
        total += x[0].len
    time_dif = packets[-1][0] - packets[0][0]
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
                curr_session = session(packet, session_info, session_info[0])
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
        self.in_pkt = session.income
        self.out_pkt = session.outcome

    def get_feat(self):
        proto = self.session.session_info[4] == "TCP"
        # first_pkt = self.all_packets[0] #the one who started the tcp connection
        # starter = first_pkt.getlayer(S.IP).src

        nfull_pkt_c = get_n_full(self.in_pkt)  # number of full packets in the client
        nfull_pkt_s = get_n_full(self.out_pkt)  # number of full packets in the client
        # get max/mean len of packet
        cc_len_sec = get_lens_per_sec(self.in_pkt)
        # get max/mean out_pkt
        cl_len_sec = get_lens_per_sec(self.out_pkt)
        # max_cc_delay, mean_cc_delay = self.get_cc_delay_statistics()  # use in_pkt
        return proto, nfull_pkt_c, nfull_pkt_s, cc_len_sec, cl_len_sec

    def get_cc_delay_statistics(self):
        for p in self.all_packets:
            pass


def main(argv):
    _session = cap_session(argv[1])
    if _session is None:
        print 'Shit happens'
        sys.exit(0)
    getter = FeatureGetter(_session)
    print getter.get_feat()


if __name__ == '__main__':
    main(sys.argv)
