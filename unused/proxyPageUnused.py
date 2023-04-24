from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QCloseEvent

import proxyConfigureWorker
import deviceSetup
import proxyWorker


class Ui_proxyWindow(object):
    def setupUi(self, MainWindow, input_interface):
        self.config_proxy()


        self.input_interface = input_interface
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1347, 902)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        self.tableWidget.setGeometry(QtCore.QRect(150, 100, 1061, 621))
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(2)
        self.tableWidget.setRowCount(1)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1347, 22))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Proxy page"))
        item = self.tableWidget.verticalHeaderItem(0)
        item.setText(_translate("MainWindow", "test"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Packet data"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Time"))

    def config_proxy(self):
        self.proxy_conf_thread = proxyConfigureWorker.proxyConfigureWorker(deviceSetup.input_interface,
                                                                           deviceSetup.packet_dict)

        # upon finish end thread
        self.proxy_conf_thread.finished.connect(self.proxy_conf_thread.quit)
        self.proxy_conf_thread.start()

        self.start_proxy()

    def start_proxy(self):
        self.proxy_thread = proxyWorker.proxyWorker(deviceSetup.input_interface, deviceSetup.packet_dict)

        # upon finish end thread
        self.proxy_thread.finished.connect(self.proxy_thread.deleteLater)
        self.proxy_thread.start()
