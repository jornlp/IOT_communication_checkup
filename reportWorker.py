import ssl
import sys

from PyQt5.QtCore import QThread, pyqtSignal

import report
import dns.resolver
from pyshark.capture.capture import TSharkCrashException

import pyshark

import OpenSSL.crypto
import ssl
import os

trustedCerDir = 'trustedCerts/'


Unknown = ""



class ReportWorker(QThread):
    # finished
    finished = pyqtSignal()

    def __init__(self, input_interface):
        super().__init__()
        self.input_interface = input_interface

    def getCerts(self, allCerts):
        certificates = []
        for i, cert in enumerate(allCerts):
            c = allCerts[i].binary_value
            certPEM = ssl.DER_cert_to_PEM_cert(c)
            finalCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certPEM)
            certificates.append(finalCert)
        return certificates

    def getRoot(self, allCerts):


        rootCert = ''
        highest = allCerts[-1].binary_value
        highestPEM = ssl.DER_cert_to_PEM_cert(highest)
        highestCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, highestPEM)

        for filename in os.listdir(trustedCerDir):
            if filename.endswith(".pem"):
                with open("%s%s" % (trustedCerDir, filename), 'rb') as f:
                    cert = f.read()
                file_to_check = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

                if highestCert.get_issuer() == file_to_check.get_issuer():
                    rootCert = file_to_check
        return rootCert

    def verifyCerts(self, certs, rootCert):
        results = []

        store = OpenSSL.crypto.X509Store()
        try:
            store.add_cert(rootCert)
        except:
            results.append("/")
            return results


        for cert in reversed(list((certs))):
            # print(cert.get_issuer().CN)
            store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)

            try:
                results.append(store_ctx.verify_certificate())
            except:
                results.append("Invalid cert")

            store.add_cert(cert)
        return results

    def run(self):

        for stream_nr in report.TCP_capture_dictionary.keys():
            host = report.stream_dst_ip_dictionary[stream_nr][0]
            counter = 0

            for p in report.TCP_capture_dictionary[stream_nr]:

                try:
                    http_test = p.http
                    if "HTTP" not in report.stream_dst_ip_dictionary[stream_nr]:
                        report.stream_dst_ip_dictionary[stream_nr][2] = "HTTP"
                except:
                    pass

                if "TLS" in str(p.layers):
                    if "TLS" not in report.stream_dst_ip_dictionary[stream_nr]:
                        report.stream_dst_ip_dictionary[stream_nr][2] = "TLS"

                    version = ""
                    if p.tls.get_field_value("handshake_type") == "2":

                        host = host + " {0}".format(counter)
                        if str(p.tls.get_field_value("handshake_extensions_key_share_group")) != "None":
                            version = "TLSv1.3"
                        else:
                            tls_version = p.tls.handshake_version

                            if tls_version == "0x0303":
                                version = "TLSv1.2"
                            elif tls_version == "0x0302":
                                version = "TLSv1.1"
                            elif tls_version == "0x0301":
                                version = "TLSv1.0"
                            else:
                                version = "unknown"

                        cipher = p.tls.handshake_ciphersuite
                        report.cipher_TLSVersion_verified_dictionary[host] = [cipher, version, ""]

                    if "handshake_certificates" in p.tls.field_names:
                        allCerts = p.tls.handshake_certificate.all_fields

                        certs = self.getCerts(allCerts)
                        rootCert = self.getRoot(allCerts)
                        res = self.verifyCerts(certs, rootCert)

                        fRes = []

                        for item in res:
                            if str(item) == "None":
                                fRes.append("Valid Cert")
                            elif str(item) == "/":
                                fRes.append("<b>!!Root CA unknown to this device, couldn't verify chain.!!</b>")
                            else:
                                fRes.append("<b>!!Mismatch in chain!!</b>")
                        report.cipher_TLSVersion_verified_dictionary[host][2] = fRes


        for key in report.stream_dst_ip_dictionary.keys():

            #every host once in report_output
            report.host_report_output_normal[report.stream_dst_ip_dictionary[key][0]] = str(report.stream_dst_ip_dictionary[key][0] + "<br>")

            #stream dest can have hosts multiple times
            report.host_set.add(report.stream_dst_ip_dictionary[key][0])


        print(report.stream_dst_ip_dictionary)
        print(report.cipher_TLSVersion_verified_dictionary)

        for stream_nr in report.stream_dst_ip_dictionary.keys():
            host = report.stream_dst_ip_dictionary[stream_nr][0]
            port = int(report.stream_dst_ip_dictionary[stream_nr][1])
            protocol = report.stream_dst_ip_dictionary[stream_nr][2]
            combowarning = ""


            if protocol == "HTTP" and port != 80:
                combowarning = "<b>!!odd port for HTTP!!</b>"
            elif protocol == "TLS" and port != 443:
                combowarning = "<b>!!odd port for TLS!!</b>"
            elif protocol == "TCP" and port != 443:
                combowarning = "<b>!!odd port for TCP!!</b>"
            elif protocol == "DNS" and port != 53:
                combowarning = "<b>o!!dd port for DNS!!</b>"

            report.host_report_output_normal[host] += "protocol: {0}<br>".format(protocol) + "port: {0}<br>".format(port) + " {0}<br>".format(combowarning)

        for host in report.cipher_TLSVersion_verified_dictionary.keys():
            actual_host = host.split(" ")[0]
            report.host_report_output_tls[actual_host] = actual_host + "<br>"

        for host in report.cipher_TLSVersion_verified_dictionary.keys():
            actual_host = host.split(" ")[0]

            cipher = report.cipher_TLSVersion_verified_dictionary[host][0]
            version = report.cipher_TLSVersion_verified_dictionary[host][1]
            verified = report.cipher_TLSVersion_verified_dictionary[host][2]

            version_warning = ""
            if version == "TLSv1.0":
                version_warning = "<b>!!seriously outdated TLS version!!</b>"
            elif version == "TLSv1.1":
                version_warning = "<b>!!seriously outdated TLS version!!</b>"
            elif version == "TLSv1.2":
                version_warning = "<b>!!update to TLSv1.3!!</b>"

            report.host_report_output_tls[actual_host] += "TLS-version: {0}".format(version) + "        {0}<br>".format(version_warning) + "cipher used: {0}<br>".format(cipher) + "chain verification per certificate: {0}<br>".format(verified)

        self.finished.emit()
