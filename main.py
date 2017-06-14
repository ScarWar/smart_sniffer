import socket

import s_sniffer
import sniffer_classifier
from session import *
from session import lst
# from sniffer_classifier import *
from sniffer_extractor import *


# import threading
# import collections
# import numpy as np


def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
    s.close()


sniffer = s_sniffer.Sniffer(get_my_ip())
Classifier_Path = "RandomForest.clf"


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
    # normlizer_matrix = np.asarray([[0, 0, 1000, 3000, 300, 0, 0, 0, 0],
    #                                [1, 300, 1514, 100000, 100000, 0.5, 2, 1],
    #                                [2, 10, 10, 100, 100, 5, 3, 100, 100]])  # lower, upper, number of bins
    classifier = sniffer_classifier.SnifferClassifier([
        "protocol"
        "server side packets",
        "client side packets",
        "data per sec server",
        "data per sec client",
        "average data server",
        "server delay",
        "max delay server",
        "max delay client"],
        ["malware", "benign"],
        # normalizer_matrix=normlizer_matrix)
    )
    classifier.load_classifier(Classifier_Path)
    while True:
        while len(lst) == 0:
            continue
        sess = lst.pop(0)
        sess.income = filter_retransmissions(sess.income)
        sess.outcome = filter_retransmissions(sess.outcome)
        sess.combined = filter_retransmissions(sess.combined)
        features = SessionFeatureExtractor(sess)
        if classifier.check_if_malware(features.get_feat) is False:
            show_result(sess)


def main():
    threading.Thread(target=sniffer_run()).start()
    threading.Thread(target=ml_classifier()).start()
    print "Press Enter in order to make the sniffer stop"
    raw_input()


if __name__ == '__main__':
    main()
