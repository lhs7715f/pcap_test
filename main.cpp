#include <pcap.h>
#include <stdio.h>

void dump(const u_char* p, int len){
  printf("Ethernet Header src mac: ");
  for(int i=6; i<12; i++)
    printf("%02x ", p[i]);
  
  printf("\n");
  
  printf("Ethernet Header dst mac: ");
  for(int i=0; i<6; i++)
    printf("%02x ", p[i]);
  
  printf("\n");
  
  if(p[12]==0x08 && p[13]==0x00)
  {
    printf("IP Header src ip: ");
    for(int i=26; i<29; i++)
      printf("%d.", p[i]);
    printf("%d", p[29]);
    
    printf("\n");
    
    printf("IP Header dst ip: ");
    
    for(int i=30; i<33; i++)
      printf("%d. ", p[i]);
    printf("%d", p[33]);

    printf("\n");
    
    if(p[23]==0x06) 
    {
      const u_char* t=p + (p[14]%16)*4 + 14;
      
      printf("TCP Header src port: "); 
      printf("%d ", t[0]*256 + t[1]);
      
      printf("\n");
      
      printf("TCP Header dst port: "); 
      printf("%d ", t[2]*256 + t[3]);  
      
      printf("\n");
      
      const u_char* d=t+(t[12]/16)*4;
      
      if(p[16]*256+p[17] - (p[14]%16)*4 - (t[12]/16)*4 > 32)
      {
        printf("Payload:\n");
        
        for(int i=0; i<16; i++)
          printf("%02x ", d[i]);
        
        printf("\n");
        
        for(int i=0; i<16; i++)
          printf("%02x ", d[i+16]);
      }
      else
      {
        printf("Payload:\n");
        for(int i=0; i<p[16]*256+p[17] - (p[14]%16)*4 - (t[12]/16)*4; i++)
          printf("%02x ", d[i]);
      }
    }
    else
      return;
  }
  else
    return;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    dump(packet, header->caplen);
  }

  pcap_close(handle);
  return 0;
}