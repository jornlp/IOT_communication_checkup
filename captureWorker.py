import dns.resolver
import pyshark
from PyQt5.QtCore import QThread, pyqtSignal
import netifaces as ni

import report


class CaptureWorker(QThread):
    # progress
    captured = pyqtSignal(str, dict, int, bool)

    # finished
    finished = pyqtSignal()

    def __init__(self, input_interface):
        super().__init__()
        self.input_interface = input_interface

    def run(self):
        input_ip = ni.ifaddresses(self.input_interface)[ni.AF_INET][0]["addr"]
        first = True
        own_ip = ""

        capture = pyshark.LiveCapture(interface=self.input_interface, monitor_mode=False)
        for packet in capture.sniff_continuously():
            if "IP" in packet:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst

                # al het verkeer van en naar de input-interface uitfilteren
                if ip_src != input_ip and ip_dst != input_ip:
                    if packet.transport_layer == "UDP":

                        src_port = packet.udp.srcport
                        dst_port = packet.udp.dstport
                        UDP_streamNumber = int(packet.udp.stream)

                        if UDP_streamNumber not in report.UDP_capture_dictionary:
                            report.UDP_capture_dictionary[UDP_streamNumber] = []
                            report.UDP_capture_dictionary[UDP_streamNumber].append(packet)


                            if ip_dst == own_ip:
                                server_ip = ip_src
                                server_port = src_port
                                try:
                                    host = str(dns.resolver.resolve(dns.reversename.from_address(server_ip), "PTR")[0])
                                except dns.resolver.NXDOMAIN:
                                    host = ip_src
                            else:
                                server_ip = ip_dst
                                server_port = dst_port
                                try:
                                    host = str(dns.resolver.resolve(dns.reversename.from_address(server_ip), "PTR")[0])
                                except dns.resolver.NXDOMAIN:
                                    host = ip_dst



                            packet_info = packet.highest_layer + " (convo ID: " + str(UDP_streamNumber) + ")" + "\n hostA: " + ip_src \
                                          + "   hostB: " + ip_dst + "\n hostA port: " + src_port + "   hostB port: " + dst_port + "   " + host

                            packet_dict = {"transport": str(packet.highest_layer), "src_ip": ip_src, "dst_ip": ip_dst,
                                           "src_port": src_port, "dst_port": dst_port, "TL": "UDP", "server_ip": server_ip}

                            protocol = packet.highest_layer
                            report.stream_dst_ip_dictionary_UDP[UDP_streamNumber] = [host, server_port, protocol, server_ip]

                            self.captured.emit(packet_info, packet_dict, UDP_streamNumber, False)
                        else:
                            report.UDP_capture_dictionary[UDP_streamNumber].append(packet)

                    if packet.transport_layer == "TCP":
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                        TCP_streamNumber = int(packet.tcp.stream)

                        if TCP_streamNumber not in report.TCP_capture_dictionary:

                            # iot contacteert server eerst!
                            if first:
                                own_ip = ip_src
                                first = False

                            report.TCP_capture_dictionary[TCP_streamNumber] = []
                            report.TCP_capture_dictionary[TCP_streamNumber].append(packet)

                            if ip_dst == own_ip:
                                server_ip = ip_src
                                server_port = src_port
                                try:
                                    host = str(dns.resolver.resolve(dns.reversename.from_address(server_ip), "PTR")[0])
                                except dns.resolver.NXDOMAIN:
                                    host = ip_src
                            else:
                                server_ip = ip_dst
                                server_port = dst_port
                                try:
                                    host = str(dns.resolver.resolve(dns.reversename.from_address(server_ip), "PTR")[0])
                                except dns.resolver.NXDOMAIN:
                                    host = ip_dst

                            packet_info = packet.highest_layer + " (convo ID: " + str(TCP_streamNumber) + ")" + "\n hostA: " + ip_src + "   hostB: " + ip_dst + \
                                          "\n hostA port: " + src_port + "   hostB port: " + dst_port + "   " + host

                            packet_dict = {"transport": str(packet.highest_layer), "src_ip": ip_src, "dst_ip": ip_dst,
                                           "src_port": src_port, "dst_port": dst_port, "TL": "TCP", "server_ip": server_ip, "server_port": server_port}

                            protocol = packet.highest_layer

                            # "" => for potential TLS info
                            report.stream_dst_ip_dictionary_TCP[TCP_streamNumber] = [host, server_port, protocol, server_ip,
                                                                                     ["decoy", "decoy", []]]

                            self.captured.emit(packet_info, packet_dict, TCP_streamNumber, True)

                        else:
                            report.TCP_capture_dictionary[TCP_streamNumber].append(packet)

        self.finished.emit()
