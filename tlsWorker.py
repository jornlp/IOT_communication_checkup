from PyQt5.QtCore import QThread, pyqtSignal

import report
import socket
import sys
import ssl

class TLSWorker(QThread):
    finished = pyqtSignal()
    captured = pyqtSignal(str, str)

    def __init__(self, ip, port, option):
        super().__init__()
        self.ip = ip
        self.port = port
        self.option = option

    def run(self):
        # geen mogelijkheid tot nieuwe proxy starten als proxy draait
        for stream_nr in report.stream_button_dictionary.keys():
            button = report.stream_button_dictionary[stream_nr]
            button.setEnabled(False)

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        if self.option == 1:
            server_context.load_cert_chain('forgedCertificates/fakeSELFSIGNED.pem', 'forgedCertificates/fakeSELFSIGNEDKEY.pem')
        elif self.option == 2:
            server_context.load_cert_chain('forgedCertificates/serverCERTCHAIN.pem', 'forgedCertificates/fakeSERVERKEY.pem')

        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE

        # proxy
        proxy_ip = "172.16.1.1"
        proxy_port = 8081

        # endpoint
        server_host = self.ip
        server_port = self.port

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind((proxy_ip, proxy_port))
            sock.listen(1)
            print("Man-in-the-middle proxy listening on {0}:{1}".format(proxy_ip, proxy_port))
            sys.stdout.flush()
            with server_context.wrap_socket(sock, server_side=True) as ssl_sock:

                try:
                    client_sock, addr = ssl_sock.accept()
                except:
                    self.captured.emit("FAILED MITM ATTEMPT", "Client did not trust the offered certificates.")

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
                    with client_context.wrap_socket(server_sock, server_hostname=server_host) as ssl_sock_server:
                        ssl_sock_server.connect((server_host, server_port))
                        print("Connected to server {0}:{1}".format(server_host, server_port))
                        sys.stdout.flush()
                        client_sock.settimeout(0.2)
                        ssl_sock_server.settimeout(0.2)

                        while True:
                            try:
                                client_data = client_sock.recv(4096)
                                if not client_data:
                                    break
                                print(client_data)
                                ssl_sock_server.sendall(client_data)
                                self.captured.emit("client", str(client_data))
                                print("Data sent to server.")
                            except:
                                pass
                            try:
                                server_data = ssl_sock_server.recv(4096)
                                if not server_data:
                                    break
                                print(server_data)
                                client_sock.sendall(server_data)
                                self.captured.emit("server", str(server_data))

                                print("Data sent to client.")
                                sys.stdout.flush()
                            except:
                                pass

                        client_sock.close()
                        ssl_sock_server.close()
                        print('Communication ended.')
                        self.finished.emit()