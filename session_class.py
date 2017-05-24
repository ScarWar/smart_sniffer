from scapy.all import *
import time
import threading

lst = list()

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
        self.our_ip         = our_ip
        self.lock           = threading.Lock()
        self.income         = list((packet, 0))
        self.outcome        = list((packet, 0))
        self.combined       = list((packet, 0))
        self.session_info   = session_info
        self.start_time     = time.time()
        self.protocol = session_info[4]

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
        self.lock.aquire(locking=True)

        self.combined.append((packet, time_now - self.start_time))
        if self.session_info[0] == self.our_ip:
            self.outcome.append((packet, time_now - self.start_time))
        elif self.session_info[1] == self.our_ip:
            self.income.append((packet, time_now - self.start_time))

        # if we got fin ack we can send it to ML to detect if correct
        if self.check_if_got_fin(packet) == True:
            lst.append(self)

        # unlock the lock
        self.lock.release()

