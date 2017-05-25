import pydotplus as pdp
from sklearn import tree
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.externals import joblib
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
import numpy as np


def select_bin(x, lower_value, upper_value, n_bins=10):
    """
    :type x: float
    :type n_bins: integer
    :type upper_value: float
    :type lower_value: float
    """
    assert lower_value <= upper_value
    v = [] * (n_bins - 1)
    if x <= lower_value:
        return 0
    if x >= upper_value:
        return n_bins - 1
    for y in xrange(1, n_bins - 2):
        v.append(lower_value + y * (float(lower_value + upper_value)) / n_bins)
    for y in xrange(1, n_bins - 2):
        if v[y] <= x <= v[y + 1]:
            return y
    return None


def split_data2traning_and_test(data, target, test_size=0.33):
    """
    :param test_size: float between 0.0 and 1.0
    :param data: input
    :param target: output
    :return: X_train, X_test, y_train, y_test 
    """
    return train_test_split(data, target, test_size=test_size)


class SnifferClassifier(object):
    """Simple decision tree classifier using AdaBoost"""

    def __init__(self, feature_names, target_names, normalizer_matrix=None):
        super(SnifferClassifier, self).__init__()
        self.clf = RandomForestClassifier()  # DecisionTreeClassifier()
        self.feature_names = feature_names
        self.target_names = target_names
        if normalizer_matrix is None:
            self.normalize_matrix = np.ones((len(feature_names), 3))
        else:
            self.normalize_matrix = normalizer_matrix

    def save_classifier(self, file_name):
        joblib.dump(self.clf, file_name)
        print "Classifier saved to file: " + file_name

    def load_classifier(self, file_name):
        self.clf = joblib.load(file_name)
        print "Classifier loaded from file: " + file_name

    def train_classifier(self, data, target):
        self.clf = self.clf.fit(data, target)
        print "Training finished"

    def classifier_err(self, data, target):
        return 1.0 - self.clf.score(data, target)

    def check_if_malware(self, data, show_prob=False):
        # Calculate prediction
        predict = self.clf.predict([data])
        is_malware = False

        if 0 != predict[0]:  # if the predictions is malware set flag to True
            is_malware = True

        if show_prob:  #
            # Calculate probability
            predict_prob = self.clf.predict_proba(data)

            for i in range(len(self.target_names)):
                print self.target_names[i] + " with probability of " + str(predict_prob[i][0])

        return is_malware

    def ada_boost_classifier(self, data, target, learning_rate=1, n_estimators=400, enable_ada=False):
        ada_boost = AdaBoostClassifier(
            base_estimator=self.clf,
            learning_rate=learning_rate,
            n_estimators=n_estimators,
            algorithm="SAMME.R")
        ada_boost.fit(data, target)
        if not enable_ada:
            self.clf = ada_boost
        print "AdaBoost training finished"

    def ada_boost_classifier_err(self, data, target, learning_rate=1, n_estimators=400, score=False):
        ada_boost = AdaBoostClassifier(
            base_estimator=self.clf,
            learning_rate=learning_rate,
            n_estimators=n_estimators,
            algorithm="SAMME.R")
        ada_boost.fit(data, target)
        score = ada_boost.score(data, target)
        if not score:
            print "Fitness score: " + str(score)
        return 1.0 - score

    def normalize_data(self, data):
        shape = data.shape
        for i in xrange(shape[0]):
            for j in xrange(shape[1]):
                n_v = self.normalize_matrix[j]
                data[i][j] = select_bin(data[i][j], n_v[0], n_v[1], n_v[2])

    def create_graphviz_file(self, file_name):
        dot_data = tree.export_graphviz(self.clf, out_file=None,
                                        feature_names=self.feature_names,
                                        class_names=self.target_names,
                                        filled=True, rounded=True,
                                        special_characters=True)
        graph = pdp.graph_from_dot_data(dot_data)
        graph.write_pdf(file_name + ".pdf")
        print "Decision graph created"

    def generate_confusion_matrix(self, data, target, truth):
        classifier = self.clf.fit(data, target)
        pred = classifier.predict([data])
        return confusion_matrix(truth, pred)
