import threading

import scapy.all as s

lst = dict()


def check_if_got_fin(pkt):
    FIN = 0x01
    F = pkt["TCP"].flags
    if F & FIN:
        return True
    return False


class Session(object):
    """
        This class will hold us, a session connection
        and will update (from given packet) and enter
        the new packet to the session and check if it
        is a FIN packets, if so it says that the socket
        Done
    
        lock - no one will change us
        input - packets that our IP received
        output - packets that we sent
        combined - both input and output packets order by time received
        session_info - ip_in, ip_out, port_in, port_out is arr
         - session_info[0] is ip_send
         - session_info[1] is ip_rec
         - session_info[2] is port_send
         - session_info[3] is port_rec
         - session_info[4] is protocol of usage
    """

    def __init__(self, pkt, session_info, our_ip):
        self.our_ip = our_ip
        self.lock = threading.Lock()

        if str(session_info[0]) == our_ip:
            self.income = [(pkt, 0)]
            self.outcome = []
        else:
            self.outcome = [(pkt, 0)]
            self.income = []

        self.combined = [(pkt, 0)]
        self.session_info = session_info
        self.start_time = pkt.time
        self.got_fin = False

    def update_session(self, pkt):
        """
        add packet to session
        :param pkt: packet to add
        """
        time_now = pkt.time

        # check if lock available and check it
        self.lock.acquire()

        self.combined += [(pkt, time_now - self.start_time)]

        if pkt[s.IP].src == self.our_ip:
            self.outcome += [(pkt, time_now - self.start_time)]
        else:
            self.income += [(pkt, time_now - self.start_time)]

        # if we got fin ack we can send it to ML to detect if correct
        # this can be only in tcp
        if s.TCP in pkt:
            self.got_fin = check_if_got_fin(pkt)
        else:
            self.got_fin = True

        # unlock the lock
        self.lock.release()
