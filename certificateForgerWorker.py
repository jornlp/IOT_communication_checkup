from PyQt5.QtCore import QThread, pyqtSignal

import report
from OpenSSL.crypto import (X509Extension, X509,
        dump_privatekey, dump_certificate,
        load_certificate, load_privatekey,
        PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM


class CFWorker(QThread):
    finished = pyqtSignal()
    def __init__(self, ip, option):
        super().__init__()
        self.ip = ip
        self.option = option

    def run(self):

        # make self signed cert based on server cert
        if self.option == 1:
            certs = report.cert_collection_per_ip[self.ip][0]

            # 0 is server certificate
            server_cert = certs[0]

            rootKey = PKey()
            rootKey.generate_key(TYPE_RSA, 2048)
            cert = X509()
            cert.set_version(server_cert.get_version())
            cert.set_serial_number(server_cert.get_serial_number())
            cert.set_subject(server_cert.get_subject())
            cert.set_issuer(cert.get_subject())
            cert.set_notBefore(server_cert.get_notBefore())
            cert.set_notAfter(server_cert.get_notAfter())
            cert.set_pubkey(rootKey)

            for i in range(server_cert.get_extension_count()):
                cert.add_extensions([server_cert.get_extension(i)])

            cert.sign(rootKey, "sha256")

            with open("forgedCertificates/fakeSELFSIGNED.pem", 'wb+') as f:
                f.write(dump_certificate(FILETYPE_PEM, cert))

            with open("forgedCertificates/fakeSELFSIGNEDKEY.pem", 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, rootKey))

            self.finished.emit()

        # copy server cert and sign with root
        elif self.option == 2:
            pass


        # copy full chain
        else:
            pass
