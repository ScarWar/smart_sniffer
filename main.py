import s_sniffer
import threading

sniffer = s_sniffer.sniffer()


def sniffer_run():
    while True:
        sniffer.update_next_packet()


def is_good(session):
    pass


def show_result():
    pass


def ml_classifier():
    while True:
        while (len(lst) == 0):
            continue
        session = list.pop(0)
        if is_good(session) == False:
            show_result()


def main():
    threading.Thread(target=sniffer_run()).start()
    threading.Thread(targer=ml_classifier()).start()
    print "Press Enter in order to make the sniffer stop"
    raw_input()


if __name__ == '__main__':
    main()
