# tls-analyzer
Read from a file pcap, extract flows and give information about host-protocol distribution and more detailed information about tls traffic.

## Requirements:
  >[nfstream](https://github.com/nfstream/nfstream) *: 'a Python framework providing fast, flexible, and expressive data structures designed to make working with online or offline network data both easy and intuitive.'*  
  
## Installing requirements:  
  Use your current version of pip to install nfstream
  > pip3 install nfstream
  
## Description:
  For each host prints:  
    The amout of traffic it generated  
    The amout of traffic generated for each protocol detected  
### tls statystics:  
  It prints each flow line by line in descending order by the amount of traffic.  
  For each flow, it detects what kind of traffic is over the TLS protocol (e.g TLS.stackoverflow , TLS.tesla , TLS.chess ) by checking if the requested server name is inside top10k.txt (top10k most visited sites), and validates SNIs for existance by resolving the hostname.

## Usage:  
  This is a command line tool, it takes only one parameter and has to be a file pcap .  
  
  You can generate a pcap file by using a networking tool like wireshark (grafical), or by command line with tcpdump.  
  To capture a session with tcpdump:  
  Indentify your network interface typing in terminal ifconfig (linux) or ipconfig (windows);  
  Once you know what network interface you are using, let's say it's name is 'mon0' :  
  > * start capture:  tcpdump -i mon0 -w pcap_files/traffic.pcap
  > * end capture: CTLR-C  
  
  Note that tcpdump requires sudo privileges to run, so you may run it as super user.

  When you got the pcap file you can run the program
  > python3 tls_printer.py pcap_files/traffic.pcap
  
  For saving the output for further read  
  > python3 tls_printer.py pcap_files/traffic.pcap >> report.txt  
  
  TODO: add better format to save the output file (e.g csv )
  
## Examples:
  
    
  
  
  
