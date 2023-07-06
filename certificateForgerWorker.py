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

            root_key = PKey()
            root_key.generate_key(TYPE_RSA, 2048)
            cert = X509()
            cert.set_version(server_cert.get_version())
            cert.set_serial_number(server_cert.get_serial_number())
            cert.set_subject(server_cert.get_subject())
            cert.set_issuer(cert.get_subject())
            cert.set_notBefore(server_cert.get_notBefore())
            cert.set_notAfter(server_cert.get_notAfter())
            cert.set_pubkey(root_key)

            for i in range(server_cert.get_extension_count()):
                cert.add_extensions([server_cert.get_extension(i)])

            cert.sign(root_key, "sha256")

            with open("forgedCertificates/fakeSELFSIGNED.pem", 'wb+') as f:
                f.write(dump_certificate(FILETYPE_PEM, cert))

            with open("forgedCertificates/fakeSELFSIGNEDKEY.pem", 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, root_key))

            self.finished.emit()

        # copy full chain
        elif self.option == 2:
            certs = report.cert_collection_per_ip[self.ip][0]
            rootCert = report.cert_collection_per_ip[self.ip][1]

            if (certs[-1].get_issuer() == certs[-1].get_subject()) and (rootCert != ''):
                certs.pop(-1)


            # rootcert namaken
            root_key = PKey()
            root_key.generate_key(TYPE_RSA, 2048)
            certRoot = X509()
            certRoot.set_version(rootCert.get_version())
            certRoot.set_serial_number(rootCert.get_serial_number())
            certRoot.set_subject(rootCert.get_subject())
            certRoot.set_issuer(rootCert.get_subject())
            certRoot.set_notBefore(rootCert.get_notBefore())
            certRoot.set_notAfter(rootCert.get_notAfter())
            certRoot.set_pubkey(root_key)

            for i in range(rootCert.get_extension_count()):
                certRoot.add_extensions([rootCert.get_extension(i)])

            certRoot.sign(root_key, "sha256")

            # forge fake chain based on original chain
            with open("forgedCertificates/fakeROOT.pem", 'wb+') as f:
                f.write(dump_certificate(FILETYPE_PEM, certRoot))

            server_cert_chain = "forgedCertificates/serverCERTCHAIN.pem"
            chain_list = []

            for certificate in reversed(list((certs))):

                intermediate_key = PKey()
                intermediate_key.generate_key(TYPE_RSA, 2048)
                intermediate_cert = X509()

                intermediate_cert.set_version(certificate.get_version())
                intermediate_cert.set_serial_number(certificate.get_serial_number())
                intermediate_cert.set_subject(certificate.get_subject())
                intermediate_cert.set_issuer(certificate.get_issuer())
                intermediate_cert.set_notBefore(certificate.get_notBefore())
                intermediate_cert.set_notAfter(certificate.get_notAfter())
                intermediate_cert.set_pubkey(intermediate_key)

                for i in range(certificate.get_extension_count()):
                    intermediate_cert.add_extensions([certificate.get_extension(i)])

                intermediate_cert.sign(root_key, "sha256")

                chain_list.append(intermediate_cert)

                root_key = intermediate_key

                with open("forgedCertificates/fakeSERVERKEY.pem", 'wb+') as f:
                    f.write(dump_privatekey(FILETYPE_PEM, intermediate_key))

            # empty file if necessary
            with open(server_cert_chain, 'w'):
                pass

            for cert in reversed(list((chain_list))):
                with open(server_cert_chain, 'ab') as chain:
                    chain.write(dump_certificate(FILETYPE_PEM, cert))

            self.finished.emit()
