import subprocess
import shlex
import threading
import os
import pyshark

cmd="sh ../scripts/dhcp_reset.sh"
tshark_cmd="tshark -Y 'dhcp'"
#print(shlex.split(cmd))
#print(shlex.split(tshark_cmd))
capture_proc=subprocess.Popen(args=['tshark','-a','duration:30','-w', 'linux_test_output.pcap'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
proc_var=subprocess.Popen(args=['sh', '../scripts/dhcp_reset.sh'])
capture_proc.wait()
cap=pyshark.FileCapture(input_file='linux_test_output.pcap')
for p in cap:
    if 'DHCP' in p: 
        print(p['dhcp'])
cap.close()

#proc_var=subprocess.run(['ls','-la'],stdout=subprocess.PIPE,text=True)
# print(proc_var.stdout)

