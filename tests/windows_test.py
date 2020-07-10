import subprocess
import shlex
import threading
import os
import pyshark

cmd="..\scripts\dhcp_reset.bat"
tshark_cmd="tshark -Y 'dhcp'"
#print(shlex.split(cmd))
#print(shlex.split(tshark_cmd))
capture_proc=subprocess.Popen(args=['tshark','-i','Ethernet','-a','duration:30','-w', 'windows_test_output.pcap']
,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
proc_var=subprocess.Popen(args=['..\scripts\dhcp_reset.bat'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
capture_proc.wait()
cap=pyshark.FileCapture(input_file='windows_test_output.pcap')
for p in cap:
    if 'DHCP' in p: 
        print(p['dhcp'])
cap.close()
