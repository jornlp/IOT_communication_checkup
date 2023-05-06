from PyQt5.QtCore import QThread, pyqtSignal

import report
import sys
import capturePage

class ButtonWorker(QThread):
    # finished
    finished = pyqtSignal()

    def __init__(self):
        super().__init__()

    def run(self):
        for stream_nr in report.stream_button_dictionary.keys():
            dict_entry = report.stream_dst_ip_dictionary_TCP[stream_nr]
            if dict_entry[2] == "HTTP" or \
                    dict_entry[2] == "TLS":
                button = report.stream_button_dictionary[stream_nr]
                button.setEnabled(True)
                button.connect(lambda: capturePage.Ui_captureWindow.start_proxy_window(dict_entry))


                # TODO CONNECT WITH STARTPROXYWINDOW // NODIGE DATA MEEGEVEN MET CONNECT EN DAN AFH VAN HTTP OF TLS
                #  EEN ANDERE PROXY OPSTARTEN

        self.finished.emit()
