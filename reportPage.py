# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'reportPage.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

import report


class Ui_ReportWindow(object):
    def setupUi(self, reportWindow):
        reportWindow.setObjectName("MainWindow")
        reportWindow.resize(1184, 878)
        self.centralwidget = QtWidgets.QWidget(reportWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(140, 10, 901, 801))
        self.widget.setObjectName("widget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")


        self.comboBox = QtWidgets.QComboBox(self.widget)
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItems(report.host_set)
        self.comboBox.currentIndexChanged.connect(self.add_scaninfo_from_host)



        self.verticalLayout.addWidget(self.comboBox)


        self.scrollArea = QtWidgets.QScrollArea(self.widget)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")


        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 897, 766))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.label_scrollArea_layout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)


        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout.addWidget(self.scrollArea)
        reportWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(reportWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1184, 22))
        self.menubar.setObjectName("menubar")
        reportWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(reportWindow)
        self.statusbar.setObjectName("statusbar")
        reportWindow.setStatusBar(self.statusbar)

        self.retranslateUi(reportWindow)
        QtCore.QMetaObject.connectSlotsByName(reportWindow)

    def retranslateUi(self, reportWindow):
        _translate = QtCore.QCoreApplication.translate
        reportWindow.setWindowTitle(_translate("reportWindow", "reportWindow"))


    def add_scaninfo_from_host(self):
        for i in reversed(range(self.label_scrollArea_layout.count())):
            widgetToRemove = self.label_scrollArea_layout.itemAt(i).widget()
            self.label_scrollArea_layout.removeWidget(widgetToRemove)
            widgetToRemove.setParent(None)

        for host in report.host_report_output_normal:
            if host == self.comboBox.currentText():
                normal_label = QtWidgets.QLabel(self.scrollAreaWidgetContents)
                normal_label.setTextFormat(Qt.RichText)
                normal_label.setText(str(report.host_report_output_normal[host]))
                normal_label.setStyleSheet("border: 1px solid black; font-size: 10pt;")
                self.label_scrollArea_layout.addWidget(normal_label)
        for host in report.host_report_output_tls:
            if host == self.comboBox.currentText():
                special_label = QtWidgets.QLabel(self.scrollAreaWidgetContents)
                special_label.setTextFormat(Qt.RichText)
                special_label.setText(str(report.host_report_output_tls[host]))
                special_label.setStyleSheet("border: 1px solid black; font-size: 10pt;")
                self.label_scrollArea_layout.addWidget(special_label)