import pyshark
import sys
import sys

ERROR_CODES={'INCORRECT_USAGE':1,'PROCESS_ERROR':2,'PLOTTING_ERROR':3,
'UNSUPPORTED_PLATFORM':4,'UNKNOWN':5}
DHCP_PACKET_TYPES={}

def get_current_platform(): #identify current operating system
    if sys.platform.startswith('linux')
        return 'linux'
    elif sys.platform.startswith('win32')
        return 'windows'
    else:
        print('Unsupported Platform!')
        exit(ERROR_CODES['UNSUPPORTED_PLATFORM'])
    pass

def live_port_scan_pyshark(): #scan packets in real time using pyshark
    
    pass

def live_port_scan_tshark(): #scan packets in real time with tshark
    if cur_platform=='linux':
        cmd="sh ../scripts/dhcp_reset.sh"
        tshark_cmd="tshark -Y 'dhcp'"
        proc_var=subprocess.Popen(args=['sh', '../scripts/dhcp_reset.sh'])
        capture_proc=subprocess.Popen(args=['tshark','-a','duration:30','-w', 'linux_test_output.pcap'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        capture_proc.wait()
    else:
        
    pass

def scan_pcap_file(fname): #scan a file
    pass

def analyse_packet(pkt): #extract data about packet
    pass

def plot():
    try:
        print()
    except Exception as e:
        print(e)
        sys.exit(ERROR_CODES['PLOTTING_ERROR'])

def packet_read():
    packet_file=sys.argv[1]
    cap=pyshark.FileCapture(input_file=packet_file)
    for pkt in cap:
        if 'DHCP' in pkt:
            print("dstn address: ",pkt['ip'].dst)
            print("src address: ",pkt.ip.src)
            print("sniff time: ",pkt.sniff_time)
            print("sniff timestamp: ",pkt.sniff_timestamp)
            print("highest layer: ",pkt.highest_layer)
            print("packet length: ",pkt.length)
            if(pkt.dhcp.type=='1'):
                print("client to server")
            if(pkt.dhcp.type=='2'):
                print("server to client")
            if(pkt.dhcp.option_value=='07'):
                print("release")
            elif(pkt.dhcp.option_value=='01'):
                print("discover")
            elif(pkt.dhcp.option_value=='02'):
                print("offer")
            elif(pkt.dhcp.option_value=='03'):
                print("request")
            elif(pkt.dhcp.option_value=='04'):
                print("decline")
            elif(pkt.dhcp.option_value=='05'):
                print("acknowledgement")
            elif(pkt.dhcp.option_value=='06'):
                print("negative acknowledgement")
            if(str(pkt['ip'].dst)=='255.255.255.255'):
                print("broadcast")
            else:
                print("unicast")
    cap.close()

if __name__=="__main__":
    if len(sys.argv)!=2:
        print("Incorrect usage! Correct usage is: python <script_name>.py <pcap_file>")
        sys.exit(ERROR_CODES['INCORRECT_USAGE'])
    packet_read()