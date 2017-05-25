import s_sniffer
import threading
from session_class import *

sniffer = s_sniffer.sniffer()


def sniffer_run():
    while True:
        sniffer.update_next_packet()


def is_good(session):
    if session is None:
        return True
    return True


def show_result(pkt):
    print "A transmitted file during the last session may contain harmful software to your computer"
    x = raw_input("Would you like to see the details of the suspicious packet? (y/n)")
    if x == 'y':
        print pkt

def ml_classifier():
    while True:
        while len(lst) == 0:
            continue
        sess = lst.pop(0)
        if is_good(sess) is False:
            show_result(sess)


def main():
    threading.Thread(target=sniffer_run()).start()
    threading.Thread(targer=ml_classifier()).start()
    print "Press Enter in order to make the sniffer stop"
    raw_input()

# if __name__ == '__main__':
