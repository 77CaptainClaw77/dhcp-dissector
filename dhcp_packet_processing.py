import pyshark
import sys

ERROR_CODES={'INCORRECT_USAGE':1,'PROCESS_ERROR':2,'PLOTTING_ERROR':3,'UNKNOWN':4}

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