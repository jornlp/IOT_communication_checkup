from PyQt5.QtCore import QThread, pyqtSignal

import deviceSetup


class ConfWorker(QThread):

    finished = pyqtSignal()

    def __init__(self, ip, port, add, listening_port):
        self.add = add
        self.ip = ip
        self.port = port
        self.listening_port = listening_port
        super().__init__()

    def run(self):
        if self.add:
            deviceSetup.configure_reroute(self.ip, self.port, self.listening_port)
            self.finished.emit()
        else:
            deviceSetup.clear_reroute_rules(self.ip, self.port, self.listening_port)
            self.finished.emit()
