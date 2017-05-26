from numpy import asarray

from scapy.all import *
from pandas import DataFrame
import sys
from session import Session
from multiprocessing import Pool

MiB = 1 << 30


def get_n_big(packets):
    cnt = 0
    for p in packets:
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


def get_max_delay(session, our_ip):
    cnt_c = 0
    cnt_s = 0
    curr = session.combined[0]
    for i in xrange(1, len(session.combined)):
        pkt_tuple = session.combined[i]
        prev = curr
        curr = pkt_tuple

        if curr[1] - prev[1] > 1:
            if curr[0][IP].src == our_ip:
                cnt_c += 1
            else:
                cnt_s += 1
    return cnt_c, cnt_s


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
    tcp = _packet.getlayer(TCP)
    if tcp.sport > tcp.dport:  # if the sport is higher then likely it is the client
        return True
    return False


# get delay average for session
def get_delay_average(session, our_ip):
    cnt_A = 0
    cnt_B = 0
    delay_sum_A = 0
    delay_sum_B = 0
    curr = session.combined[0]
    for i in xrange(1, len(session.combined)):
        pkt_tuple = session.combined[i]
        prev = curr
        curr = pkt_tuple
        if prev[0][IP].src != our_ip and curr[0][IP].src == our_ip and i < len(session.combined) - 1:
            i += 1  # to skip the
            pkt_tuple = session.combined[i]
            prev = curr
            curr = pkt_tuple
            while prev[0][IP].src == our_ip and curr[0][IP].src == our_ip and i < len(session.combined) - 1:
                delay_sum_A += (curr[1] - prev[1])
                i += 1
                pkt_tuple = session.combined[i]
                prev = curr
                curr = pkt_tuple
                cnt_A += 1

            delay_sum_B += (curr[1] - prev[1])
            cnt_B += 1
    r1 = r2 = 0
    if cnt_A != 0:
        r1 = delay_sum_A / cnt_A
    if cnt_B != 0:
        r2 = delay_sum_B / cnt_B
    return r1, r2


def cap_session(pcap_path):
    capture = rdpcap(pcap_path)  # TODO when go live change to session capture
    first = True
    curr_session = None
    session_info = [0, ] * 3
    for pkt in capture:
        if not pkt.haslayer(TCP) and not pkt.haslayer(IP) and pkt.len <= 0:
            continue

        if first:
            first = False
            if is_client(pkt):
                session_info[0] = pkt[IP].src
                session_info[1] = pkt[IP].dst
                session_info[2] = "TCP"
                curr_session = Session(pkt, session_info, session_info[0])
            else:
                session_info[0] = pkt[IP].dst
                session_info[1] = pkt[IP].src
                session_info[2] = "TCP"
                curr_session = Session(pkt, session_info, session_info[0])
        else:
            curr_session.update_session(pkt)

    return curr_session


class SessionFeatureExtractor(object):
    """
        Simple class for extraction of features from pcap files
        
    """

    def __init__(self, session):
        self.session = session
        self.all_packets = session.combined
        self.in_pkts = session.income
        self.out_pkts = session.outcome

    def get_feat(self):
        # if self.session.session_info[2] == "TCP":
        #     proto = 1
        # else:
        #     proto = 0
        curr_features = 1
        n_features = 7
        # number of full packets in the client
        num_small_packets_pkt_s = get_n_small(self.in_pkts)
        print "Extracted " + str(curr_features) + " features out of " + str(n_features)

        # number of small packets in the client
        num_small_pkt_c = get_n_big(self.out_pkts)
        curr_features += 1
        print "Extracted " + str(curr_features) + " features out of " + str(n_features)

        # get max/mean len of packet
        cc_len_sec = get_lens_per_sec(self.in_pkts)
        curr_features += 1
        print "Extracted " + str(curr_features) + " features out of " + str(n_features)

        # get max/mean out_pkt
        cl_len_sec = get_lens_per_sec(self.out_pkts)
        curr_features += 1
        print "Extracted " + str(curr_features) + " features out of " + str(n_features)

        # get average server client delay time
        avg_c2c, avg_s2c2s = get_delay_average(self.session, self.session.our_ip)  # use in_pkt
        curr_features += 2
        print "Extracted " + str(curr_features) + " features out of " + str(n_features)

        max_c, max_s = get_max_delay(self.session, self.session.our_ip)
        curr_features += 2
        print "Extracted " + str(curr_features) + " features out of " + str(n_features)

        return num_small_pkt_c, num_small_packets_pkt_s, cc_len_sec, cl_len_sec, avg_c2c, avg_s2c2s, max_c, max_s


def get_features_pcap_file((input_dir, pcap_file, label)):
    st = os.stat(input_dir + "/" + pcap_file)
    if st.st_size > 30 * MiB:
        return None
    s = cap_session(input_dir + "/" + pcap_file)
    print "Start extraction from " + pcap_file
    getter = SessionFeatureExtractor(s)
    return list(getter.get_feat()) + [label]


def data_gen(input_dir, label, output_file, save=True):
    pool = Pool(8)
    func_input = [(input_dir, pcap_file, label) for pcap_file in os.listdir(input_dir)]
    data = pool.map(get_features_pcap_file, func_input)
    # pool.close()
    # pool.join()
    print "features extracted from %s" % input_dir
    df = DataFrame(data)
    if save:
        df.to_csv(output_file)
    print "Done writing features"
    return df


def main(argv):
    _session = cap_session(argv[1])
    if _session is None:
        print 'Shit happens'
        sys.exit(0)

    getter = SessionFeatureExtractor(_session)
    print getter.get_feat()


if __name__ == '__main__':
    main(sys.argv)
