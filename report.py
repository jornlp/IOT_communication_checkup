#id = streamKey, value = list of matching packets
TCP_capture_dictionary = {}
UDP_capture_dictionary = {}

#nr: host, port, protocol
stream_dst_ip_dictionary = {}

cipher_TLSVersion_verified_dictionary = {}

host_set = set()


#host: report string
host_report_output_normal = {}
host_report_output_tls = {}