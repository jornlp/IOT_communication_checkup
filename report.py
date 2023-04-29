# id = streamKey, value = list of matching packets
TCP_capture_dictionary = {}
UDP_capture_dictionary = {}

# nr: host, port, protocol
stream_dst_ip_dictionary_TCP = {}
stream_dst_ip_dictionary_UDP = {}



#Todo: streamnr: cipher, version, verified, host, ip
cipher_TLSVersion_verified_dictionary = {}

host_set = set()

# host: report string
host_report_output_normal_TCP = {}
host_report_output_normal_UDP = {}
host_report_output_tls = {}
