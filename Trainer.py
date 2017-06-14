# import numpy as np
import pandas
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.svm import NuSVC, SVC
# from pandas import DataFrame as df
from sklearn.tree import DecisionTreeClassifier

import sniffer_classifier
import sniffer_extractor

# bad = df.from_csv('bad_data_v1')
# good = df.from_csv('good_data_v1')
data = sniffer_extractor.data_gen("Test/SERVER", "malware", "bad_data_v2", save=True)
new_data = sniffer_extractor.data_gen("Test/OTHER", "benign", "good_data_v2", save=True)
data = pandas.concat([data, new_data], ignore_index=True)
# data = pandas.concat([bad, good], ignore_index=True)
X_train, X_test, y_train, y_test = sniffer_classifier.split_data2traning_and_test(data.iloc[:, :-1], data.iloc[:, -1])

# normalizer_matrix = np.asarray([[0, 0, 1000, 3000, 300, 0, 0, 0, 0],
#                                [1, 300, 1514, 100000, 100000, 0.5, 2, 1],
#                                [2, 10, 10, 100, 100, 5, 3, 300, 300]])  # lower, upper, number of bins
classifiers = [
    [
        DecisionTreeClassifier(max_depth=3),
        "Decision Tree Classifier"
    ],
    [
        RandomForestClassifier(max_depth=3, bootstrap=False),
        "Random Forest Classifier"
    ],
    [
        ExtraTreesClassifier(max_depth=3, bootstrap=False),
        "Extra Trees Classifier"
    ],
    [
        SVC(),
        "SVC"
    ],
    [
        NuSVC(),
        "NuSVC"
    ]
]
feature_names = [
    "server side packets",
    "client side packets",
    "data per sec server",
    "data per sec client",
    "average data server",
    "server delay",
    "max delay server",
    "max delay client"
]
target_names = [
    "malware",
    "benign"
]
for clf in classifiers:
    # confusion_matrix = np.zeros([2, 2])
    err = 0
    classifier = sniffer_classifier.SnifferClassifier(feature_names, target_names, classifier=clf[0])
    classifier.train_classifier(X_train, y_train)
    err += classifier.classifier_err(X_test, y_test)
    print clf[1] + " results:"
    print classifier.generate_confusion_matrix(X_test, y_test)
    # for i in xrange(5):
    #     pass
    # confusion_matrix = np.add(confusion_matrix, classifier.generate_confusion_matrix(X_test, y_test))

    # avg_conf_mat = np.multiply(confusion_matrix, 1 / 5)
    # print "Average confusion matrix\n" + str(avg_conf_mat)

    avg_err = err
    print "Average error - " + str(avg_err)
# normalizer_matrix=normalizer_matrix)

# classifier.create_graphviz_file("Tree classifier")

# classifier.save_classifier("RandomForest.clf")
