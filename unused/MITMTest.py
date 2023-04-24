import sys
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget
from mitmproxy import ctx
from mitmproxy.tools.main import mitmdump
from mitmproxy.addons import streambodies
from threading import Thread

class TlsAttackCounter:
    def __init__(self):
        self.count = 0

    def request(self, flow):
        if flow.request.scheme == "https":
            if self.is_tls_attack_successful(flow):
                self.count += 1
                ctx.log.info(f"Successful TLS attack count: {self.count}")

    def is_tls_attack_successful(self, flow):
        # Implement your own method to detect successful TLS attacks.
        pass

class AttackCounterWindow(QWidget):
    def __init__(self, counter):
        super().__init__()
        self.counter = counter
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        label = QLabel(f"Successful TLS attacks: {self.counter.count}")
        layout.addWidget(label)
        self.setLayout(layout)
        self.setWindowTitle("TLS Attack Counter")

def run_mitmproxy():
    addons = [streambodies.StreamBodies(), TlsAttackCounter()]
    sys.argv = ["mitmdump", "--set", "stream_large_bodies=memory", "-s", __file__]
    mitmdump(argv=sys.argv, mode="regular", onboarding=False, addons=addons)

def main():
    app = QApplication(sys.argv)
    counter = TlsAttackCounter()
    window = AttackCounterWindow(counter)
    window.show()

    proxy_thread = Thread(target=run_mitmproxy)
    proxy_thread.setDaemon(True)
    proxy_thread.start()

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()