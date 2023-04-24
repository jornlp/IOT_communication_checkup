import subprocess
import atexit
import sys

import proxyWorker

global input_interface
global output_interface
global packet_dict


def configure_device():
    atexit.register(restore_state, input_interface, output_interface)

    # setup to make dnsmasq work properly, check call > call
    subprocess.call(["sudo", "systemctl", "disable", "systemd-resolved"])
    subprocess.call(["sudo", "systemctl", "stop", "systemd-resolved"])
    subprocess.call(["sudo", "unlink", "/etc/resolv.conf"])

    res = "nameserver 8.8.8.8"
    f = open('/etc/resolv.conf', 'w')
    f.write(res)
    f.close()

    # dhcpcd on Ubuntu
    with open('/etc/netplan/01-network-manager-all.yaml', 'w') as net:
        l1 = "network:\n"
        l2 = "  version: 2\n"
        l3 = "  renderer: NetworkManager\n"
        l4 = "  ethernets:\n"
        l5 = "      %s:\n" % input_interface
        l6 = "          dhcp4: no\n"
        l7 = "          addresses: [172.16.1.1/16]"
        net.writelines([l1, l2, l3, l4, l5, l6, l7])

    subprocess.call(['sudo', 'netplan', 'apply'])

    subprocess.call(['sudo', 'systemctl', 'stop', 'dnsmasq'])
    with open('/etc/dnsmasq.conf', 'w') as dns:
        l1 = "interface=%s\n" % input_interface
        l2 = "bind-dynamic\n"
        l3 = "domain-needed\n"
        l4 = "bogus-priv\n"
        l5 = "dhcp-range=172.16.1.2,172.16.1.200,24h\n"
        l6 = "dhcp-option=option:netmask,255.255.255.0\n"
        dns.writelines([l1, l2, l3, l4, l5, l6])

    # Restart dnsmasq service
    subprocess.call(['sudo', 'systemctl', 'enable', 'dnsmasq.service'])
    subprocess.call(['sudo', 'systemctl', 'start', 'dnsmasq.service'])

    # write rules to necessary files
    # 1: enable forwarding on device
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # 2: alter ip tables
    subprocess.call(
        ["iptables", "-A", "FORWARD", "-i", input_interface, "-o", output_interface, "-j",
         "ACCEPT"])
    subprocess.call(
        ["iptables", "-A", "FORWARD", "-i", output_interface, "-o", input_interface, "-m",
         "state", "--state", "RELATED,ESTABLISHED",
         "-j", "ACCEPT"])
    subprocess.call(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", output_interface, "-j", "MASQUERADE"])


# reverse setup
def restore_state(inputI, outputI):
    # disable forwarding again
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=0"])

    # restore firewall rules
    subprocess.call(["iptables", "-D", "FORWARD", "-i", inputI, "-o", outputI, "-j", "ACCEPT"])
    subprocess.call(
        ["iptables", "-D", "FORWARD", "-i", outputI, "-o", inputI, "-m", "state", "--state", "RELATED,ESTABLISHED",
         "-j", "ACCEPT"])
    subprocess.call(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", outputI, "-j", "MASQUERADE"])

    with open('/etc/netplan/01-network-manager-all.yaml', 'w') as net:
        l1 = "network:\n"
        l2 = "  version: 2\n"
        l3 = "  renderer: NetworkManager\n"
        net.writelines([l1, l2, l3])

    subprocess.call(['sudo', 'netplan', 'apply'])

    # Stop dnsmasq
    subprocess.call(["sudo", "systemctl", "disable", "dnsmasq.service"])
    subprocess.call(["sudo", "systemctl", "stop", "dnsmasq.service"])

    dnsmasq = ""
    f = open("/etc/dnsmasq.conf", "w")
    f.write(dnsmasq)
    f.close()

    subprocess.call(["sudo", "unlink", "/etc/resolv.conf"])

    res = "nameserver 127.0.0.53\nnameserver 8.8.8.8"
    f = open("/etc/resolv.conf", "w")
    f.write(res)
    f.close()

    subprocess.call(["sudo", "systemctl", "enable", "systemd-resolved"])
    subprocess.call(["sudo", "systemctl", "start", "systemd-resolved"])

    print("Exited successfully.")


# iptables -t nat -A PREROUTING -p <protocol> -s <source IP> --sport
# <source port> -d <destination IP> --dport <destination port> -j DNAT --to-destination 127.0.0.1:8080
def configure_proxy(src_port, dst_port, src_ip, dst_ip):
    atexit.register(remove_proxy_iptables, src_port, dst_port, src_ip, dst_ip)

    subnet_remote = ".".join(dst_ip.split(".")[:-1]) + ".0/16"

    subnet_source = ".".join(src_ip.split(".")[:-1]) + ".0/16"

    print("setup", subnet_remote)
    print("setup", subnet_source)

    iptables_command = ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", input_interface, "-p", "tcp", "-j",
                        "REDIRECT", "--to-port", "8080"]
    subprocess.call(iptables_command)


    print("proxy setup")

    sys.stdout.flush()

    subprocess.call(['sudo', 'iptables', '-S'])

    # sudo iptables -t nat -L -n
    subprocess.call(["sudo", "iptables", "-t", "nat", "-L", "-n"])


def remove_proxy_iptables(src_port, dst_port, src_ip, dst_ip):
    subnet_remote = ".".join(dst_ip.split(".")[:-1]) + ".0/16"
    subnet_source = ".".join(src_ip.split(".")[:-1]) + ".0/16"

    print("proxy remove")
    print("remove", subnet_remote)
    print("remove", subnet_source)
    sys.stdout.flush()

    iptables_command = ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-i", input_interface, "-p", "tcp", "-j",
                        "REDIRECT", "--to-port", "8080"]
    subprocess.call(iptables_command)


