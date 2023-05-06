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

from socket import socket

from OpenSSL import SSL, crypto

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

    def getRootX509(self, allCerts):
        rootCert = ''
        highestCert = allCerts[-1]
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

        # self signed ontvangen?
        if (certs[-1].get_issuer() == certs[-1].get_subject()) and (rootCert != ''):

            self_signed_store = crypto.X509Store()
            self_signed_store.add_cert(rootCert)
            self_signed_context = crypto.X509StoreContext(self_signed_store, certs[-1])

            try:
                test = self_signed_context.verify_certificate()
                certs.pop(-1)
                results.append(test)
                if len(certs) == 0:
                    return results
            except crypto.X509StoreContextError:
                results.append("selfsignedfailed")
                return results


        store = OpenSSL.crypto.X509Store()
        try:
            store.add_cert(rootCert)
        except:
            results.append("/")
            return results

        for cert in reversed(list((certs))):
            store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)

            try:
                results.append(store_ctx.verify_certificate())
            except:
                results.append("Invalid cert")
            store.add_cert(cert)
        return results

    def get_certificates(self, host, port):
        server = socket()
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        print('Connecting to {0} to get certificates...'.format(host))
        conn = SSL.Connection(context, server)
        certs = []

        try:
            conn.connect((host, int(port)))
            conn.do_handshake()
            certs = conn.get_peer_cert_chain()

        except SSL.Error as e:
            print('Error: {0}'.format(str(e)))
            exit(1)

        # server cert on index 0
        return certs

    def run(self):

        for stream_nr in report.TCP_capture_dictionary.keys():

            host = report.stream_dst_ip_dictionary_TCP[stream_nr][0]
            ip = report.stream_dst_ip_dictionary_TCP[stream_nr][3]

            counter = 0
            done = False

            # packets afgaan voor elke stream
            for p in report.TCP_capture_dictionary[stream_nr]:

                try:
                    http_test = p.http
                    if "HTTP" not in report.stream_dst_ip_dictionary_TCP[stream_nr]:
                        report.stream_dst_ip_dictionary_TCP[stream_nr][2] = "HTTP"
                except:
                    pass

                if "TLS" in str(p.layers):
                    if "TLS" not in report.stream_dst_ip_dictionary_TCP[stream_nr]:
                        report.stream_dst_ip_dictionary_TCP[stream_nr][2] = "TLS"

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
                        report.stream_dst_ip_dictionary_TCP[stream_nr][4] = [cipher, version, ["couldn't fetch "
                                                                                               "certificates (TLS1.3)"]]

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
                                fRes.append("<b>!!Root CA unknown to tool, couldn't verify chain!!</b>")
                            elif str(item) == "selfsignedfailed":
                                fRes.append("<b>!!Self signed root not trusted!!</b>")
                            else:
                                fRes.append("<b>!!Mismatch in chain!!</b>")

                        report.stream_dst_ip_dictionary_TCP[stream_nr][4][2] = fRes

                    elif report.stream_dst_ip_dictionary_TCP[stream_nr][4][1] == "TLSv1.3" and not done:

                        not_found = False

                        try:
                            # X509 certs
                            allCerts = self.get_certificates(ip, report.stream_dst_ip_dictionary_TCP[stream_nr][1])
                            rootCert = self.getRootX509(allCerts)
                            res = self.verifyCerts(allCerts, rootCert)
                        except:
                            not_found = True

                        fRes = []

                        if not_found:
                            fRes.append("Certificates couldn't be acquired.")
                        else:
                            for item in res:
                                if str(item) == "None":
                                    fRes.append("Valid Cert")
                                elif str(item) == "/":
                                    fRes.append("<b>!!Root CA unknown to tool, couldn't verify chain!!</b>")
                                elif str(item) == "selfsignedfailed":
                                    fRes.append("<b>!!Self signed root not trusted!!</b>")
                                else:
                                    fRes.append("<b>!!Mismatch in chain!!</b>")

                        report.stream_dst_ip_dictionary_TCP[stream_nr][4][2] = fRes
                        done = True

        for stream_nr in report.stream_dst_ip_dictionary_TCP.keys():
            host = report.stream_dst_ip_dictionary_TCP[stream_nr][0]
            port = report.stream_dst_ip_dictionary_TCP[stream_nr][1]
            protocol = report.stream_dst_ip_dictionary_TCP[stream_nr][2]
            ip = report.stream_dst_ip_dictionary_TCP[stream_nr][3]
            tls_info = report.stream_dst_ip_dictionary_TCP[stream_nr][4][1]

            report.host_report_output_normal_TCP[stream_nr] = [host, "output"]

            report.host_set.add(host)

            combowarning = ""

            if protocol == "HTTP" and port != 80:
                combowarning = "<b>!!odd port for HTTP!!</b>"
            elif protocol == "TLS" and (port != 443 and port != 8443):
                combowarning = "<b>!!odd port for TLS!!</b>"
            elif protocol == "TCP" and port != 443:
                combowarning = "<b>!!odd port for TCP!!</b>"

            report.host_report_output_normal_TCP[stream_nr][
                1] = "ip: {0}<br>stream number: {1}<br>protocol: {2}<br>port: {3}<br>{4}<br>".format(ip, stream_nr,
                                                                                                     protocol, port,
                                                                                                     combowarning)

            if tls_info != "decoy":
                cipher = report.stream_dst_ip_dictionary_TCP[stream_nr][4][0]
                version = report.stream_dst_ip_dictionary_TCP[stream_nr][4][1]
                verified = report.stream_dst_ip_dictionary_TCP[stream_nr][4][2]

                version_warning = ""
                if version == "TLSv1.0":
                    version_warning = "<b>!!seriously outdated TLS version!!</b>"
                elif version == "TLSv1.1":
                    version_warning = "<b>!!seriously outdated TLS version!!</b>"
                elif version == "TLSv1.2":
                    version_warning = "<b>!!update to TLSv1.3!!</b>"

                report.host_report_output_normal_TCP[stream_nr][1] += "<br>TLS-version: {0}        {1}<br>cipher " \
                                                                      "used: {2}<br>chain " \
                                                                      "verification per certificate: {3}<br>".format(
                    version, version_warning, cipher, verified)

        for stream_nr in report.stream_dst_ip_dictionary_UDP.keys():
            host = report.stream_dst_ip_dictionary_UDP[stream_nr][0]
            port = report.stream_dst_ip_dictionary_UDP[stream_nr][1]
            protocol = report.stream_dst_ip_dictionary_UDP[stream_nr][2]
            ip = report.stream_dst_ip_dictionary_UDP[stream_nr][3]

            report.host_report_output_normal_UDP[stream_nr] = [host, "output"]

            report.host_set.add(host)

            combowarning = ""
            if protocol == "DNS" and port != 53:
                combowarning = "<b>o!!dd port for DNS!!</b>"

            report.host_report_output_normal_UDP[stream_nr][1] = "ip: {0}<br>stream number: {1}<br>protocol: " \
                                                                 "{2}<br>port: {3}<br>{4}<br>".format(ip, stream_nr,
                                                                                                      protocol, port,
                                                                                                      combowarning)

        self.finished.emit()
