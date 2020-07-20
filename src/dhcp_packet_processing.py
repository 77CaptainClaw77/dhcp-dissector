import pyshark
import sys
import datetime
import subprocess
import matplotlib.pyplot as plt
import re
import pygal
from jinja2 import Environment,FileSystemLoader
import webbrowser
import os

class pkt_info:
    def __init__(self,**kwargs):
        for var_name,var_value in kwargs.items():
            setattr(self,var_name,var_value)
    def __str__(self):
        return "\n\nPacket Type: "+self.dhcp_packet_type+"\nPacket Source Address: "+self.source_address+"\nPacket Destination Address: "+self.destination_address+"\nPacket Transmission Type: "+self.transmission_type+"\nPacket Sniff Time: "+self.sniff_time.strftime("%m/%d/%Y, %H:%M:%S")
    def get_class_vars(self):
        return {'Packet Type':self.dhcp_packet_type,"Packet Source Address":self.source_address,"Packet Destination Address":self.destination_address,"Packet Transmission Type":self.transmission_type,"\nPacket Sniff Time: ":self.sniff_time.strftime("%m/%d/%Y, %H:%M:%S")}

ERROR_CODES={'INCORRECT_USAGE':1,'PROCESS_ERROR':2,'PLOTTING_ERROR':3,'UNSUPPORTED_PLATFORM':4,'UNKNOWN':5,'INPUT_ERROR':6}
DHCP_PACKET_TYPES={'01':'Discover','02':'Offer','03':'Request','04':'Decline','05':'Acknowledgement','06':'Negative Acknowledgement','07':'Release'}
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
def generate_analysis_file_name():
    return 'analysis_file_'+datetime.datetime.now().strftime("%d_%m_%Y %H:%M:%S")+".html"

def live_port_scan_tshark(capture_interface): #scan packets in real time with tshark
    live_cap_fname=generate_file_name()
    print("Starting live packet capture process....")
    if cur_platform=='linux':
        cmd="sh ../scripts/dhcp_reset.sh"
        tshark_cmd="tshark -Y 'dhcp'"
        capture_proc=subprocess.Popen(args=['tshark','-i',capture_interface,'-a','duration:30','-w', live_cap_fname],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        proc_var=subprocess.Popen(args=['sh', '../scripts/dhcp_reset.sh'])
        capture_proc.wait()
    else:
        cmd="..\scripts\dhcp_reset.bat"
        tshark_cmd="tshark -Y 'dhcp'"
        capture_proc=subprocess.Popen(args=['tshark','-i',capture_interface,'-a','duration:30','-w', live_cap_fname],stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,shell=True)
        proc_var=subprocess.Popen(args=['..\scripts\dhcp_reset.bat'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        capture_proc.wait()
    return live_cap_fname


def scan_pcap_file(fname): #scan a file
    pass

def analyse_packet(pkt): #extract data about packet
    pass

def plot(dhcp_packets,fname):
    try:
        stat_proc=None
        if cur_platform=='linux':
            stat_proc=subprocess.Popen(['tshark', '-nr', fname, '-qz','io,phs'], stdout=subprocess.PIPE) 
        else:
            stat_proc=subprocess.Popen(['tshark', '-nr', fname, '-qz','io,phs'], stdout=subprocess.PIPE,shell=True) 
        stat_data=stat_proc.communicate()[0].decode('utf-8').replace('=','')
        stat_proc.wait()
        prot_hierarchy={}
        for s in stat_data.split("\n"):
            if s.find("frames:")!=-1:
                l=s.strip().split()
                prot_hierarchy[l[0]]=int((l[1].split(":"))[1])
        chart=pygal.Pie(width=1500,height=1500,print_values=True)
        chart.title="Protocol Hierarchy"
        for k in prot_hierarchy.keys():
            chart.add(k,prot_hierarchy[k])
        chart_data=chart.render()
        stat_data=stat_data.replace(" ","&nbsp")
        return [chart_data,stat_data.replace("\n","<br>")]
    except Exception as e:
        print(e)
        sys.exit(ERROR_CODES['PLOTTING_ERROR'])

def packet_read(packet_file):
    cap=pyshark.FileCapture(input_file=packet_file)
    dhcp_lease_time=0
    dhcp_packets=[]
    plot_data=[]
    for pkt in cap:
        if 'DHCP' in pkt:
            dhcp_packets.append(pkt_info(destination_address=pkt['ip'].dst,source_address=pkt.ip.src,
            sniff_time=datetime.datetime.fromtimestamp(int(float(pkt.sniff_timestamp))),
            packet_length=pkt.length,dhcp_packet_type=DHCP_PACKET_TYPES[pkt.dhcp.option_value],
            direction="client to server" if pkt.dhcp.type=='1' else "server to client",
            transmission_type="broadcast" if str(pkt['ip'].dst)=="255.255.255.255" else "unicast")) 
            if 'option_ip_address_lease_time' in dir(pkt['dhcp']):
                dhcp_lease_time=pkt['dhcp'].option_ip_address_lease_time
    dhcp_stats_proc=None
    dhcp_raw_data_proc=None
    if cur_platform=='linux':
        dhcp_stats_proc=subprocess.Popen(args=['tshark','-nr',packet_file,'-qz','dhcp,stat'],stdout=subprocess.PIPE)
        dhcp_raw_data_proc=subprocess.Popen(args=['tshark','-nr',packet_file,'-Y','dhcp'],stdout=subprocess.PIPE)
    else:
        dhcp_stats_proc=subprocess.Popen(args=['tshark','-nr',packet_file,'-qz','dhcp,stat'],stdout=subprocess.PIPE,shell=True)
        dhcp_raw_data_proc=subprocess.Popen(args=['tshark','-nr',packet_file,'-Y','dhcp'],stdout=subprocess.PIPE,shell=True)
    dhcp_stats=dhcp_stats_proc.communicate()[0].decode('utf-8').replace("\n","<br>")
    dhcp_stats=(dhcp_stats.replace(" ","&nbsp")).replace('=','')
    dhcp_stats_proc.wait()
    dhcp_raw_data=dhcp_raw_data_proc.communicate()[0].decode('utf-8').replace("\n","<br>")
    dhcp_raw_data=(dhcp_raw_data.replace(" ","&nbsp")).replace('=','')
    dhcp_raw_data_proc.wait()
    analysis_file=generate_analysis_file_name()
    env=Environment(loader=FileSystemLoader('templates'))
    template_file=env.get_template('analysis_file_template.html')
    stats=plot(dhcp_packets,packet_file)
    output=template_file.render(title=analysis_file,chart_data=stats[0],packet_statistics=stats[1],dhcp_packet_data=[p.get_class_vars() for p in dhcp_packets],dhcp_packet_stats=dhcp_stats,dhcp_raw_data=dhcp_raw_data)
    fpath=""
    with open(analysis_file,mode='w') as f:
            f.write(output)
            fpath=os.path.realpath(f.name)
    webbrowser.open('file://'+fpath)
    cap.close()

if __name__=="__main__":
    print("DHCP Packet Analyser") 
    cur_platform=get_current_platform()
    if len(sys.argv)>=2:
        if len(sys.argv)==2:
            print("Running in file scan mode....")
            packet_read(sys.argv[1])
        else: 
            print("Incorrect usage! Correct usage is: python <script_name>.py <pcap_file>")
            sys.exit(ERROR_CODES['INCORRECT_USAGE'])
    else: #default option
        get_interfaces=None
        if cur_platform=="linux":
            get_interfaces=subprocess.Popen(['tshark','-D'],stdout=subprocess.PIPE)
        else:
            get_interfaces=subprocess.Popen(['tshark','-D'],stdout=subprocess.PIPE,shell=True)
        get_interfaces.wait()
        interface_list=get_interfaces.communicate()[0].decode().split('\n')
        interfaces={}
        for it in interface_list:
            if not it: continue
            try:
                s=it.split(' ')
                interfaces[int(s[0][:-1])]=s[1]
            except:
                print("INPUT ERROR!")
                print(it)
        for k in interfaces.keys():
            print(str(k)+'. '+interfaces[k])
        print("Select the number of the desired interface:",end=' ')
        capture_interface=interfaces[int(input())]
        print("Running in live scan mode")
        live_cap_file=live_port_scan_tshark(capture_interface)  
        packet_read(live_cap_file)