# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'proxyPage.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_ProxyWindow(object):
    def setupUi(self, ProxyWindow):
        ProxyWindow.setObjectName("MainWindow")
        ProxyWindow.resize(1042, 833)
        self.centralwidget = QtWidgets.QWidget(ProxyWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(40, 30, 961, 721))
        self.widget.setObjectName("widget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.textBrowser = QtWidgets.QTextBrowser(self.widget)
        self.textBrowser.setObjectName("textBrowser")
        self.verticalLayout.addWidget(self.textBrowser)


        self.start_proxy_button = QtWidgets.QPushButton(self.widget)
        self.start_proxy_button.setObjectName("start_proxy_button")
        self.verticalLayout.addWidget(self.start_proxy_button)

        self.start_proxy_button.clicked.connect(self.start_proxy)



        self.end_test_button = QtWidgets.QPushButton(self.widget)
        self.end_test_button.setObjectName("end_test_button")
        self.verticalLayout.addWidget(self.end_test_button)
        ProxyWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(ProxyWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1042, 22))
        self.menubar.setObjectName("menubar")
        ProxyWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(ProxyWindow)
        self.statusbar.setObjectName("statusbar")
        ProxyWindow.setStatusBar(self.statusbar)

        self.retranslateUi(ProxyWindow)
        QtCore.QMetaObject.connectSlotsByName(ProxyWindow)

    def retranslateUi(self, ProxyWindow):
        _translate = QtCore.QCoreApplication.translate
        ProxyWindow.setWindowTitle(_translate("Proxy Check-up Page", "Proxy Check-up Page"))
        self.start_proxy_button.setText(_translate("ProxyWindow", "Start Proxy Check-up"))
        self.end_test_button.setText(_translate("ProxyWindow", "End Test"))

    def start_proxy(self):
        pass
