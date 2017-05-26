from scapy.all import *
from pandas import DataFrame
import sys
from sessions import Session
from multiprocessing import Pool
mega = 1024 ** 2


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
        if curr[1] - prev[1] > 1.3:
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

    return delay_sum_A / cnt_A, delay_sum_B / cnt_B


def get_max_delay(session, our_ip):
    cnt_c = 0
    cnt_s = 0
    curr = session.combined[0]
    for i in xrange(1, len(session.combined)):
        pkt_tuple = session.combined[i]
        prev = curr
        curr = pkt_tuple
        if curr[1] - prev[1] > 0.5:
            if curr[0][IP].src == our_ip:
                cnt_c += 1
            else:
                cnt_s += 1
    total = cnt_c + cnt_s
    if total == 0:
        return 0, 0
    return cnt_c / total, cnt_s / total


def cap_session(pcap_path):
    capture = rdpcap(pcap_path)
    first = True
    curr_session = None
    session_info = [0, ] * 3
    for packet in capture:
        if not packet.haslayer(TCP) and not packet.haslayer(IP) and packet.len <= 0:
            continue
        if first:
            first = False
            if is_client(packet):
                session_info[0] = packet[IP].src
                session_info[1] = packet[IP].dst
                session_info[2] = "TCP"
                curr_session = Session(packet, session_info, session_info[0])
            else:
                session_info[0] = packet[IP].dst
                session_info[1] = packet[IP].src
                session_info[2] = "TCP"
                curr_session = Session(packet, session_info, session_info[0])
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
        if self.session.session_info[2] == "TCP":
            proto = 1
        else:
            proto = 0
        nfull_pkt_s = get_n_small(self.in_pkts)  # number of full packets in the client
        nfull_pkt_c = get_n_big(self.out_pkts)  # number of small packets in the client
        # get max/mean len of packet
        cc_len_sec = get_lens_per_sec(self.in_pkts)
        # get max/mean out_pkt
        cl_len_sec = get_lens_per_sec(self.out_pkts)
        avrg_c2c, avrg_s2c2s = get_delay_average(self.session, self.session.our_ip)  # use in_pkt
        max_c, max_s = get_max_delay(self.session, self.session.our_ip)
        return proto, nfull_pkt_c, nfull_pkt_s, cc_len_sec, cl_len_sec, avrg_c2c, avrg_s2c2s, max_c, max_s


SERVER = ''
OTHER = ''
OUT = ''


def get_features_pcap_file(input_dir, file, label):
    st = os.stat(input_dir + "/" + file)
    target = []
    if st.st_size > 30 * mega:
        return None
    s = cap_session(input_dir + "/" + file)
    getter = FeatureGetter(s)
    return list(getter.get_feat()) + [label]


def data_gen(input_dir, label, output_file, save=True):
    lst = []
    data = []
    with Pool(10) as pool:
        jobs = []
        for file in os.listdir(input_dir):
            jobs.append(pool.apply_async(get_features_pcap_file, (input_dir, file, label)))
        for job in jobs:
            result = job.get()
            if result:
                data.append(result)
                print "feat extracted from %s" % result[-1]

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
    getter = FeatureGetter(_session)
    print getter.get_feat()


if __name__ == '__main__':
    main(sys.argv)
