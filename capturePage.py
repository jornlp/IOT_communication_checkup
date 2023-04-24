# -*- coding: utf-8 -*-
# Form implementation generated from reading ui file 'capturePage.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

from PyQt5 import QtCore, QtGui, QtWidgets

import report
import reportPage
from captureWorker import CaptureWorker
from reportWorker import ReportWorker


class Ui_captureWindow(object):
    def setupUi(self, CaptureWindow, input_interface):
        self.input_interface = input_interface

        CaptureWindow.setObjectName("MainWindow")
        CaptureWindow.resize(1075, 882)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        CaptureWindow.setFont(font)
        self.centralwidget = QtWidgets.QWidget(CaptureWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(70, 30, 941, 781))
        self.widget.setObjectName("widget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.scroll_area = QtWidgets.QScrollArea(self.widget)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setObjectName("scroll_area")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 937, 715))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")

        self.packet_scrollArea_layout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)

        self.scroll_area.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout.addWidget(self.scroll_area)
        self.start_capture = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.start_capture.setFont(font)
        self.start_capture.setObjectName("start_capture")

        self.start_capture.clicked.connect(self.start_packet_capture)

        self.verticalLayout.addWidget(self.start_capture)
        self.stop_capture = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.stop_capture.setFont(font)
        self.stop_capture.setObjectName("stop_capture")

        self.stop_capture.clicked.connect(self.stop_thread)

        self.verticalLayout.addWidget(self.stop_capture)
        CaptureWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(CaptureWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1075, 22))
        self.menubar.setObjectName("menubar")
        CaptureWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(CaptureWindow)
        self.statusbar.setObjectName("statusbar")
        CaptureWindow.setStatusBar(self.statusbar)

        self.retranslateUi(CaptureWindow)
        QtCore.QMetaObject.connectSlotsByName(CaptureWindow)
    def retranslateUi(self, captureWindow):
        _translate = QtCore.QCoreApplication.translate
        captureWindow.setWindowTitle(_translate("Capture Page", "Capture Page"))
        self.start_capture.setText(_translate("captureWindow", "Start capture!"))
        self.stop_capture.setText(_translate("captureWindow", "Stop capture!"))
        #self.main_screen.setText(_translate("captureWindow", "Main screen"))

    def start_packet_capture(self):
        self.capture_thread = CaptureWorker(self.input_interface)

        # update scroll area upon relevant capture
        self.capture_thread.captured.connect(self.update_scroll_area)

        # upon finish end thread
        self.capture_thread.finished.connect(self.capture_thread.quit)
        self.capture_thread.finished.connect(self.capture_thread.deleteLater)
        self.capture_thread.start()

        # Final resets
        self.start_capture.setEnabled(False)
        self.start_capture.setText("Capturing on %s..." % self.input_interface)
        self.stop_capture.setEnabled(True)
        self.capture_thread.finished.connect(
            lambda: self.start_capture.setEnabled(True)
        )

    def stop_thread(self):
        self.capture_thread.terminate()
        self.stop_capture.setEnabled(False)
        self.start_capture.setText("Start capture! (connect device first)")
        self.start_capture.setEnabled(True)
        self.write_report()




    def update_scroll_area(self, packet_info, packet_dict):
        # create a QLabel widget to hold the packet information
        packet_label = QtWidgets.QPushButton(self.scrollAreaWidgetContents)
        # if(packet_dict["TL"] != "UDP" and packet_dict["TL"] != "TCP"):
        #     packet_label.setEnabled(False)

        packet_label.setEnabled(False)
        packet_label.setText(packet_info)

        #packet_label.clicked.connect(lambda: self.start_proxy_window(packet_dict))

        # elif packet_dict['transport'] == "UDP":
        #     packet_label.clicked.connect(lambda: self.start_UDP_proxy_window(packet_dict))

        # add the label to the packet layout
        self.packet_scrollArea_layout.addWidget(packet_label)


    def write_report(self):
        #thread oproepen die bij finishen de report page opent
        self.report_thread = ReportWorker(self.input_interface)

        # update scroll area upon relevant capture
        self.report_thread.finished.connect(self.open_report)

        # upon finish end thread
        self.report_thread.finished.connect(self.report_thread.quit)
        self.report_thread.finished.connect(self.report_thread.deleteLater)
        self.report_thread.start()

    def open_report(self):
        #nodige data uit report.py halen
        self.reportWindow = QtWidgets.QMainWindow()
        self.ui = reportPage.Ui_ReportWindow()
        self.ui.setupUi(self.reportWindow)
        self.reportWindow.show()




