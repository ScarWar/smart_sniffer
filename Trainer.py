import numpy as np
import pandas
from pandas import DataFrame as df

import sniffer_extarctor, sniffer_classifier

bad = df.from_csv('bad_data')
good = df.from_csv('good_data')
# data = sniffer_extarctor.data_gen("Test/SERVER", "malware", "bad_data", save=True)
# new_data = sniffer_extarctor.data_gen("Test/OTHER", "benign", "good_data", save=True)
# data = pandas.concat([data, new_data], ignore_index=True)
data = pandas.concat([bad, good], ignore_index=True)
X_train, X_test, y_train, y_test = sniffer_classifier.split_data2traning_and_test(data.iloc[:, :-1], data.iloc[:, -1])
#
normlizer_matrix = np.asarray([[0, 0, 1000, 3000, 300, 0, 0, 0, 0],
                               [1, 300, 1514, 100000, 100000, 0.5, 2, 1],
                               [2, 10, 10, 100, 100, 5, 3, 300, 300]])  # lower, upper, number of bins
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
    normalizer_matrix=normlizer_matrix)

classifier.train_classifier(X_train, y_train)
# print classifier.classifier_err(X_test, y_test)
print X_test
print classifier.generate_confusion_matrix(X_test, y_test)
