from PyQt5.QtCore import QThread, pyqtSignal

import report
import sys
class ButtonWorker(QThread):
    # finished
    finished = pyqtSignal()
    hit = pyqtSignal(int, list)

    def __init__(self):
        super().__init__()

    def run(self):


        for stream_nr in report.stream_button_dictionary.keys():
            dict_entry = report.stream_dst_ip_dictionary_TCP[stream_nr]
            self.hit.emit(stream_nr, dict_entry)

        self.finished.emit()
