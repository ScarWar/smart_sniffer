import scapy.all as S

'''





'''


class feature_getter(object):
    """docstring for feater_geter"""

    def __init__(self, session):
        self.session = session
        all_packets = self.session.all()
        in_pkt = self.session.inp()
        out_pkt = self.session.outp()

    def get_feat(self):
        proto = (self.session.protocol == "TCP")
        # first_pkt = self.all_packets[0] #the one who started the tcp connection
        # starter = first_pkt.getlayer(S.IP).src

        nfull_pkt_c = get_n_full(self.in_pkt)  # number of full packets in the client
        nfull_pkt_s = get_n_full(self.out_pkt)  # nuber of full packets in the client
        # get max/mean len of packet
        cc_len_sec = get_lens_per_sec(self.in_pkt)
        # get max/mean out_pkt
        cl_len_sec = get_lens_per_sec(self.out_pkt)
        max_cc_delay, mean_cc_delay = self.get_cc_delay_statistics()  # use in_pkt
        return proto, nfull_pkt_c, nfull_pkt_s, cc_len_sec, cl_len_sec

    def get_n_full(packets):
        cnt = 0
        for p in packets:
            # ip = p[0].getlayer(S.IP)
            if p.len == 1514:  # max len of packet
                cnt += 1
        return cnt

    def get_lens_per_sec(packets):
        total = 0
        for x in packets:
            total += x.len
        time_dif = x[-1] - x[0]
        return total / time_dif

    def get_cc_delay_statistics(self):
        for x in self.all_packets:
            pass
