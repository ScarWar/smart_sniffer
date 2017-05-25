import s_sniffer
import threading
import collections
from session_class import *
from sniffer_classifier import *
from sniffer_extarctor import *

sniffer = s_sniffer.sniffer()
Classifier_Path = "classifier.txt"


def filter_retransmissions(pkt_list):
    seen = set()
    return [x for x in pkt_list if x[0]['TCP'].seq not in seen and not seen.add(x[0]['TCP'].seq)]


def sniffer_run():
    while True:
        sniffer.update_next_packet()


def show_result(pkt):
    print "A transmitted file during the last session may contain harmful software to your computer"
    x = raw_input("Would you like to see the details of the suspicious packet? (y/n)")
    if x == 'y':
        print pkt


def ml_classifier():
    classifier = SnifferClassifier(["prot", "fpackets_s", "fpackets_c", "data_per_time_c", "data_per_timer_s", "delay"],
                                   ["malware", "benign"])  # need to ask Arik what you give
    classifier.load(Classifer_Path)
    while True:
        while len(lst) == 0:
            continue
        sess = lst.pop(0)
        sess.income = filter_retransmissions(sess.income)
        sess.outcome = filter_retransmissions(sess.outcome)
        sess.combined = filter_retransmissions(sess.combined)
        features = FeatureGetter(sess)
        if calssifier.check_if_malware(features.get_feat()) is False:
            show_result(sess)


def main():
    threading.Thread(target=sniffer_run()).start()
    threading.Thread(targer=ml_classifier()).start()
    print "Press Enter in order to make the sniffer stop"
    raw_input()

# if __name__ == '__main__':
