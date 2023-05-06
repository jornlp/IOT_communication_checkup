from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

import deviceSetup
from buttonWorker import ButtonWorker
from confWorker import ConfWorker
from httpWorker import HTTPWorker

import re


class Ui_httpWindow(object):
    def __init__(self):
        super().__init__()

    # def closeEvent(self, event):
    #     deviceSetup.clear_http_rules(self.ip, self.port)
    #     event.accept()

    def setupUi(self, HTTPWindow, dict_entry):
        self.dict_entry = dict_entry
        self.ip = dict_entry[3]
        self.port = dict_entry[1]

        HTTPWindow.setObjectName("MainWindow")
        HTTPWindow.resize(1075, 882)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        HTTPWindow.setFont(font)
        self.centralwidget = QtWidgets.QWidget(HTTPWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(70, 30, 941, 781))
        self.widget.setObjectName("widget")

        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")

        self.info = QtWidgets.QLabel(self.widget)
        self.info.setAlignment(QtCore.Qt.AlignCenter)

        self.info.setText("MITM attempt on: {0}:{1}".format(self.ip, self.port))
        self.verticalLayout.addWidget(self.info)

        self.scroll_area = QtWidgets.QScrollArea(self.widget)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setObjectName("scroll_area")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 937, 715))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")

        self.intercept_scrollArea_layout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)

        self.scroll_area.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout.addWidget(self.scroll_area)
        self.start_proxy = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.start_proxy.setFont(font)
        self.start_proxy.setObjectName("start_proxy")

        self.start_proxy.clicked.connect(self.configure_iptables_http)

        self.verticalLayout.addWidget(self.start_proxy)

        self.stop_proxy = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.stop_proxy.setFont(font)
        self.stop_proxy.setObjectName("stop_proxy")

        self.stop_proxy.clicked.connect(self.stop_thread)
        self.stop_proxy.setEnabled(False)

        self.verticalLayout.addWidget(self.stop_proxy)

        HTTPWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(HTTPWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1075, 22))
        self.menubar.setObjectName("menubar")
        HTTPWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(HTTPWindow)
        self.statusbar.setObjectName("statusbar")
        HTTPWindow.setStatusBar(self.statusbar)

        self.retranslateUi(HTTPWindow)
        QtCore.QMetaObject.connectSlotsByName(HTTPWindow)

    def retranslateUi(self, HTTPWindow):
        _translate = QtCore.QCoreApplication.translate
        HTTPWindow.setWindowTitle(_translate("MITM Page", "MITM Page"))

        self.start_proxy.setText(_translate("HTTPWindow", "Start attack attempt! DEVICE MUST BE CONNECTED FIRST"))
        self.stop_proxy.setText(_translate("HTTPWindow", "Stop attack attempt!"))

    def configure_iptables_http(self):
        self.start_proxy.setEnabled(False)
        self.stop_proxy.setEnabled(True)
        self.conf_thread = ConfWorker(self.ip, self.port, True)
        self.conf_thread.finished.connect(self.start_attack)
        self.conf_thread.finished.connect(self.conf_thread.quit)
        self.conf_thread.finished.connect(self.conf_thread.deleteLater)
        self.conf_thread.start()

    def start_attack(self):
        # thread om proxy te draaien
        self.http_thread = HTTPWorker(self.ip, self.port)
        self.http_thread.captured.connect(self.update_scroll_area)
        self.http_thread.finished.connect(self.http_thread.quit)
        self.http_thread.finished.connect(self.http_thread.deleteLater)
        self.http_thread.finished.connect(lambda: self.stop_proxy.setEnabled(False))
        self.http_thread.finished.connect(lambda: self.start_proxy.setEnabled(True))
        self.http_thread.start()

        self.start_proxy.setText("Performing attack on {0}:{1}".format(self.ip, self.port))

    def stop_thread(self):
        # rules verwijderen uit iptables
        self.conf_thread = ConfWorker(self.ip, self.port, False)
        self.conf_thread.finished.connect(self.conf_thread.quit)
        self.conf_thread.finished.connect(self.conf_thread.deleteLater)
        self.conf_thread.start()

        # knoppen terug enablen
        self.button_thread = ButtonWorker()
        self.button_thread.finished.connect(self.button_thread.quit)
        self.button_thread.finished.connect(self.button_thread.deleteLater)
        self.button_thread.start()

        self.http_thread.terminate()
        self.stop_proxy.setEnabled(False)
        self.start_proxy.setText("Start attack! (reconnect device first)")
        self.start_proxy.setEnabled(True)

    def update_scroll_area(self, side, data):
        intercept_label = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        intercept_label.setTextFormat(Qt.RichText)

        r = re.compile(r'<.*?>')
        data = r.sub('', data)

        intercept_label.setText("<b>{0}</b><br>{1}".format(side, data))
        intercept_label.setStyleSheet("border: 1px solid black; font-size: 10pt;")

        self.intercept_scrollArea_layout.addWidget(intercept_label)
