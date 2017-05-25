from scapy.all import *
import time
import threading


class session(object):
    '''
    This class will hold us, a session connection
    and will update (from given packet) and enter
    the new packet to the session and check if it
    is a FIN packets, if so it says that the socket
    Done
    '''

    # lock - no one will change us
    # input - packets that our IP recived
    # output - packters that we sent
    # combined - both input and output packets order by time recieved
    # session_info - ip_in, ip_out, port_in, port_out is arr
    # - session_info[0] is ip_send
    # - session_info[1] is ip_rec
    # - session_info[2] is port_send
    # - session_info[3] is port_rec
    # - session_info[4] is protocol of usage
    def __init__(self, packet, session_info, our_ip):
        self.our_ip = our_ip
        self.lock = threading.Lock()

        if str(session_info[0]) == our_ip:
            self.income = [(packet, 0)]
            self.outcome = []
        else:
            self.outcome = [(packet, 0)]
            self.income = []

        self.combined = [(packet, 0)]
        self.session_info = session_info
        self.start_time = time.time()
        self.got_fin = False

    # to check if the session ends
    def check_if_got_fin(self, packet):
        FIN = 0x01
        F = packet["TCP"].flags
        if F & FIN:
            return True
        return False

    # update the correct session
    def update_session(self, packet):
        time_now = time.time()

        # check if lock availabe and check it
        self.lock.acquire()

        self.combined += [(packet, time_now - self.start_time)]

        if packet[IP].src == self.our_ip:
            self.outcome += [(packet, time_now - self.start_time)]
        else:
            self.income += [(packet, time_now - self.start_time)]

        # if we got fin ack we can send it to ML to detect if correct
        # this can be only in tcp
        if TCP in packet:
            self.got_fin = self.check_if_got_fin(packet)
        else:
            self.got_fin = True

        # unlock the lock
        self.lock.release()

