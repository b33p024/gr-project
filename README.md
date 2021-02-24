# tls-analyzer
Read from a file pcap, extract flows and give information about host-protocol distribution and more detailed information about tls traffic.

## Requirements:
  >[nfstream](https://github.com/nfstream/nfstream)
  
## Description:
  For each host prints:  
    The amout of traffic it generated  
    The amout of traffic generated for each protocol detected  
### tls statystics:  
    Prints each flow line by line in descending order by the amout of traffic.  
    For each flow detect what kind of traffic is over the TLS protocol (e.g TLS.stackoverflow , TLS.tesla , TLS.chess ) by checking if the requested server name is inside top10k.txt (top10k most visited sites).
    SNI validation and authentication.
    
    
  
  
  
