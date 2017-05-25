import s_sniffer
import threading
from session_class import *
from sniffer_classifier import *
from sniffer_extarctor import *

sniffer = s_sniffer.sniffer()
Classifier_Path = "classifier.txt"


def sniffer_run():
    while True:
        sniffer.update_next_packet()


def show_result(pkt):
    print "A transmitted file during the last session may contain harmful software to your computer"
    x = raw_input("Would you like to see the details of the suspicious packet? (y/n)")
    if x == 'y':
        print pkt

def ml_classifier():
    classifier = SnifferClassifier(["prot", "fpackets_s", "fpackets_c", "data_per_time_c", "data_per_timer_s"],
                                   ["malware", "benign"])  # need to ask Arik what you give
    classifier.load(Classifer_Path)
    while True:
        while len(lst) == 0:
            continue
        sess = lst.pop(0)
        features = FeatureGetter(sess)
        if calssifier.check_if_malware(features.get_feat()) is False:
            show_result(sess)


def main():
    threading.Thread(target=sniffer_run()).start()
    threading.Thread(targer=ml_classifier()).start()
    print "Press Enter in order to make the sniffer stop"
    raw_input()

# if __name__ == '__main__':
