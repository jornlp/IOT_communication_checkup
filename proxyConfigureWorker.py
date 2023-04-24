from PyQt5.QtCore import QThread, pyqtSignal

from deviceSetup import configure_proxy


class proxyConfigureWorker(QThread):
    # finished
    finished = pyqtSignal()

    def __init__(self, input_interface, packet_dict):
        super().__init__()
        self.packet_dict = packet_dict

    def run(self):

        #config iptables to redirect to proxy
        configure_proxy(self.packet_dict["src_port"], self.packet_dict["dst_port"], self.packet_dict["src_ip"], self.packet_dict["dst_ip"])

        self.finished.emit()
