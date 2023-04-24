# https://rileymacdonald.ca/2019/01/24/python-write-tcp-proxy-inspection-fuzzing/

import sys
import socket
import threading
from PyQt5.QtCore import QThread, pyqtSignal

from proxy import server_loop


class proxyWorker(QThread):
    # finished
    finished = pyqtSignal()

    def __init__(self, input_interface, packet_dict):
        super().__init__()
        self.src_ip = packet_dict["src_ip"]
        self.dst_ip = packet_dict["dst_ip"]
        self.src_port = packet_dict["src_port"]
        self.dst_port = packet_dict["dst_port"]

    def run(self):
        pass