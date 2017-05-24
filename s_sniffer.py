import scapy.all as S

FILE_LOGGER = "./Ssniffer_logger.log"


# The Flow:
# 1. need to sniff object
# 2. extract features
# 3. use ML
# 4. 	bad:
#			-- show result, warning and continue
# 		good:
#			-- continue
#
# Quesiton need to solve
# 1. how to extracet features from pakets


class S_sniffer(object):
    """
    The Ssniffer smart sniffer that will
    alert if we got a malware
    """

    # This function is to inform that we start using our
    # Ssniffer to check what is good and bad
    def __init__(self, ourIP):
        self.file = open(FILE_LOGGER, "w")
        self.ourIP = ourIP
        self.sessions = {}
        self.current_packet
        print("Hello everyone this is the Ssniffer")
        print("This sinffer is much better then any other sniffer beacuse:")
        print("These sniffer give you a warning if you are trying to reach a malware")
        print("Or a malicious hacker trying to reach/hack your computer")
        print("So, thank you for using us and hope we will do a great job")

    # return (IPsrc, PORTsrc, IPdst, PORTdst)
    def make_stemp(self, packet):

    # This function will give us the next packet to check if correct
    def get_and_update_next_packet(self):
        self.current_packet = S.sniff(count=1)
        packet = self.current_packet
        (IPsrc, PORTsrc, IPdst, PORTdst, proto) = make_stemp(packet)
        stemp = {IPsrc, PORTsrc, IPdst, PORTdst, proto}

        if self.sessions.get(stemp) is None:
            self.sessions[stemp] = {}
            if self.ourIP == IPsrc:
                self.sessions[stemp]["income"] = packet
                return self.sessions[stemp]["income"]
            else:
                self.sessions[stemp]["outcome"] = packet
                return self.sessions[stemp]["outcome"]
        else:
            if self.ourIP == IPsrc:
                if self.sessions[stemp].get("income") is None:
                    self.sessions[stemp]["income"] = packet
                else:
                    self.sessions[stemp]["income"] += packet
                    return self.sessions[stemp]["income"]
            else:
                if self.sessions[stemp].get("outcome") is None:
                    self.sessions[stemp]["outcome"] = packet
                else:
                    self.sessions[stemp]["outcome"] += packet
                    return self.sessions[stemp]["outcome"]

    def Warning_Mode(self, packet):


def main():
    better_sniffer = S_sniffer()

    while True:
        better_sniffer.update_next_packet()
        if ML_detection() is True:
            better_sniffer.Warning_Mode()
        else:
            continue


# This function will detect if the packet is malicious or not
# It will get thier output after genereta a classifier
# return true if the packet seems cool
# return false otherwise
def ML_detection(packet):
    return True
