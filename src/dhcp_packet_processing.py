import pyshark
import sys
import datetime
import subprocess

ERROR_CODES={'INCORRECT_USAGE':1,'PROCESS_ERROR':2,'PLOTTING_ERROR':3,
'UNSUPPORTED_PLATFORM':4,'UNKNOWN':5,'INPUT_ERROR':6}
DHCP_PACKET_TYPES={'01':'discover','02':'offer','03':'request','04':'decline'
,'05':'acknowledgement','06':'negative acknowledgement','07':'release'}
global cur_platform #hold information about current operating system

def get_current_platform(): #identify current operating system
    if sys.platform.startswith('linux'):
        return 'linux'
    elif sys.platform.startswith('win32'):
        return 'windows'
        print('Unsupported Platform!')
    else:
        exit(ERROR_CODES['UNSUPPORTED_PLATFORM'])

def generate_file_name():
    return 'live_packet_capture_'+datetime.datetime.now().strftime("%d_%m_%Y %H:%M:%S")+".pcap"

# def live_port_scan_pyshark(): #scan packets in real time using pyshark
#     live_cap_fname=generate_file_name()
#     captured_packets= pyshark.LiveCapture(output_file=live_cap_fname)
#     print("Starting packet capture....")
#     captured_packets.sniff(timeout=30)
#     if cur_platform=='linux': 
#         proc_var=subprocess.Popen(args=['sh', '../scripts/dhcp_reset.sh'])
#     else:
#         proc_var=subprocess.Popen(args=['..\scripts\dhcp_reset.bat'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
#     return live_cap_fname

def live_port_scan_tshark(): #scan packets in real time with tshark
    live_cap_fname=generate_file_name()
    print("Starting live packet capture process....")
    if cur_platform=='linux':
        cmd="sh ../scripts/dhcp_reset.sh"
        tshark_cmd="tshark -Y 'dhcp'"
        capture_proc=subprocess.Popen(args=['tshark','-a','duration:30','-w', live_cap_fname],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        proc_var=subprocess.Popen(args=['sh', '../scripts/dhcp_reset.sh'])
        capture_proc.wait()
    else:
        cmd="..\scripts\dhcp_reset.bat"
        tshark_cmd="tshark -Y 'dhcp'"
        capture_proc=subprocess.Popen(args=['tshark','-i','Ethernet','-a','duration:30','-w', live_cap_fname],stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,shell=True)
        proc_var=subprocess.Popen(args=['..\scripts\dhcp_reset.bat'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        capture_proc.wait()
    return live_cap_fname


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

def packet_read(packet_file):
    cap=pyshark.FileCapture(input_file=packet_file)
    dhcp_packets=[]
    plot_data=[]
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
            dhcp_packet_type=DHCP_PACKET_TYPES[pkt.dhcp.option_value]
            if(str(pkt['ip'].dst)=='255.255.255.255'):
                transmission_type="broadcast"
            else:
                transmission_type="unicast"
            print(dir(pkt))
            pkt_dt_time_ob=datetime.datetime.fromtimestamp(int(float(pkt.sniff_timestamp)))
            #plot_data.append([dhcp_packet_type,pkt.dhcp.)
    cap.close()

if __name__=="__main__":
    print("DHCP Packet Analyser") 
    if len(sys.argv)==2:
        print("Running in file scan mode....")
        print("Incorrect usage! Correct usage is: python <script_name>.py <pcap_file>")
        sys.exit(ERROR_CODES['INCORRECT_USAGE'])
    else: #default option
        print("Running in live scan mode")
        cur_platform=get_current_platform()
        live_cap_file=live_port_scan_tshark()  
        packet_read(live_cap_file)