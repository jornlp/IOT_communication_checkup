import sys

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMainWindow

import deviceSetup
from buttonWorker import ButtonWorker
from certificateForgerWorker import CFWorker
from confWorker import ConfWorker

import re

from tlsWorker import TLSWorker


class Ui_tlsWindow(QMainWindow):
    def __init__(self):
        super().__init__()

    def setupUi(self, TLSWindow, dict_entry, window_number):
        self.dict_entry = dict_entry
        self.ip = dict_entry[3]
        self.port = dict_entry[1]
        self.proxy_port = "8081"
        self.proxy_counter = deviceSetup.proxy_counter
        deviceSetup.proxy_counter += 1
        self.window_number = window_number

        TLSWindow.setObjectName("MainWindow")
        TLSWindow.resize(1075, 882)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        TLSWindow.setFont(font)
        self.centralwidget = QtWidgets.QWidget(TLSWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(70, 30, 941, 781))
        self.widget.setObjectName("widget")

        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")

        self.info = QtWidgets.QLabel(self.widget)
        self.info.setAlignment(QtCore.Qt.AlignCenter)

        self.info.setText("TLS MITM attempt on: {0}:{1}".format(self.ip, self.port))
        self.verticalLayout.addWidget(self.info)

        self.comboBox_method = QtWidgets.QComboBox(self.widget)
        self.comboBox_method.setObjectName("comboBox_inputInterface")
        options = ["self signed", "full chain copy"]
        self.comboBox_method.addItems(options)
        self.verticalLayout.addWidget(self.comboBox_method)

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
        self.start_proxy.clicked.connect(self.start_attack)

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

        TLSWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(TLSWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1075, 22))
        self.menubar.setObjectName("menubar")
        TLSWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(TLSWindow)
        self.statusbar.setObjectName("statusbar")
        TLSWindow.setStatusBar(self.statusbar)

        self.retranslateUi(TLSWindow)
        QtCore.QMetaObject.connectSlotsByName(TLSWindow)

    def retranslateUi(self, TLSWindow):
        _translate = QtCore.QCoreApplication.translate
        TLSWindow.setWindowTitle(_translate("MITM Page", "MITM Page"))

        self.start_proxy.setText(_translate("TLSWindow", "Start attack attempt! (device must be connected first)"))
        self.stop_proxy.setText(_translate("TLSWindow", "Stop attack attempt!"))

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        deviceSetup.tlsWindows_opened.remove(self.window_number)
        self.close_window()
        print("TLS proxy page closed.")
        sys.stdout.flush()

    def close_window(self):
        self.conf_thread = ConfWorker(self.ip, self.port, False, self.proxy_port)
        self.conf_thread.finished.connect(self.conf_thread.quit)
        self.conf_thread.finished.connect(self.conf_thread.deleteLater)
        self.conf_thread.start()

    def configure_iptables_tls(self, proxy_port):
        self.proxy_port = proxy_port
        self.start_proxy.setEnabled(False)
        self.stop_proxy.setEnabled(True)
        self.conf_thread = ConfWorker(self.ip, self.port, True, proxy_port)
        self.conf_thread.finished.connect(self.conf_thread.quit)
        self.conf_thread.finished.connect(self.conf_thread.deleteLater)
        self.conf_thread.start()

    def change_start_button(self):
        self.start_proxy.setText("Start attack! (reconnect device first)")

    def start_attack(self):

        # certificate forgery
        if self.comboBox_method.currentText() == "self signed":
            self.cert_thread = CFWorker(self.ip, 1, self.proxy_counter)
            self.cert_thread.finished.connect(self.cert_thread.quit)
            self.cert_thread.finished.connect(self.cert_thread.deleteLater)
            self.cert_thread.finished.connect(lambda: self.setup_proxy(1))
            self.cert_thread.start()

        elif self.comboBox_method.currentText() == "full chain copy":
            self.cert_thread = CFWorker(self.ip, 2, self.proxy_counter)
            self.cert_thread.finished.connect(self.cert_thread.quit)
            self.cert_thread.finished.connect(self.cert_thread.deleteLater)
            self.cert_thread.finished.connect(lambda: self.setup_proxy(2))
            self.cert_thread.start()

    def setup_proxy(self, option):
        # thread om proxy te draaien
        self.tls_thread = TLSWorker(self.ip, self.port, option, self.proxy_counter)

        # hier weet je de definitieve proxy poort
        self.tls_thread.config.connect(self.configure_iptables_tls)
        self.tls_thread.config.connect(lambda: self.start_proxy.setText("Performing attack on {0}:{1}, via local "
                                                                        "port {2}".format(self.ip, self.port,
                                                                                          self.proxy_port)))

        self.tls_thread.captured.connect(self.update_scroll_area)
        self.tls_thread.finished.connect(self.tls_thread.quit)
        self.tls_thread.finished.connect(self.tls_thread.deleteLater)
        self.tls_thread.finished.connect(self.change_start_button)
        self.tls_thread.finished.connect(lambda: self.stop_proxy.setEnabled(False))
        self.tls_thread.finished.connect(lambda: self.start_proxy.setEnabled(True))
        self.tls_thread.start()

    def stop_thread(self):
        # rules verwijderen uit iptables
        self.conf_thread = ConfWorker(self.ip, self.port, False, self.proxy_port)
        self.conf_thread.finished.connect(self.conf_thread.quit)
        self.conf_thread.finished.connect(self.conf_thread.deleteLater)
        self.conf_thread.start()

        # knoppen terug enablen
        # self.button_thread = ButtonWorker()
        # self.button_thread.finished.connect(self.button_thread.quit)
        # self.button_thread.finished.connect(self.button_thread.deleteLater)
        # self.button_thread.start()

        self.tls_thread.terminate()
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
