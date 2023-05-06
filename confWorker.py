from PyQt5.QtCore import QThread, pyqtSignal

import deviceSetup


class ConfWorker(QThread):

    finished = pyqtSignal()

    def __init__(self, ip, port, add):
        self.add = add
        self.ip = ip
        self.port = port
        super().__init__()

    def run(self):
        if self.add:
            deviceSetup.configure_http(self.ip, self.port)
            self.finished.emit()
        else:
            deviceSetup.clear_http_rules(self.ip, self.port)
            self.finished.emit()
