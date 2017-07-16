#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

#define ETHERTYPE_IP 0x0800

#define IPTYPE_ICMP 0x01
#define IPTYPE_TCP 0x06
#define IPTYPE_UDP 0x11

typedef struct my_ether_header 
{
	u_char ether_dmac[6];
	u_char ether_smac[6];
	u_short ether_type;
}my_eth;

typedef my_eth*  my_peth;

typedef struct my_ip_header
{
	u_char ip_v:4;	//version
	u_char ip_hl:4;	//header length
	u_char ip_tos;	//type of service
	short ip_len;	//total length
	u_short ip_id;	//identification
	short ip_ip_off;	//fragment offset field
	u_char ip_ttl;		//time to live
	u_char ip_p;		//protocol -> next tcp protocol
	u_short ip_sum;	//checksum
	struct in_addr ip_src, ip_dst; //source ip; destination ip
}my_ip;

typedef my_ip* my_pip;

typedef struct my_tcp_header
{
	u_short tcp_sport;
	u_short tcp_dport;
	u_char tcp_x2:4;
	u_char tcp_off:4;

	u_char tcp_flags;

	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
}my_tcp;

typedef my_tcp* my_ptcp;


//Data print function
void Print_Ether_Info(my_peth ehdr_pointer);
void Print_extra_data(u_char *str, int len);




int main(int argc, char *argv[])
{
	pcap_t *handle;		/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int pcap_ret = 0;
	
	int data_len = 0; // caplen - sizeof(eth) - sizeof(ip) - sizeof(tcp) = data len

	my_peth ehdr_pointer = NULL;
	my_pip iphdr_pointer = NULL;
	my_ptcp tcphdr_pointer = NULL;
	u_char *data_pointer = NULL;

	int i = 50;

	short eth_type = 0;
	char ip_type = 0;

	if(argc != 2)
	{
		printf("usage  : %s device_name\n", argv[0]);
		return 2;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* Grab a packet */
	printf("=====We will capture 50 packets\n====");
	printf("====Now Start...====\n");
	printf("====You should start Web browser====\n");


	for(i=1;i<=50;i++)
	{
	       pcap_ret = pcap_next_ex(handle, &header, &packet);
		/* Print its length */
	       if(pcap_ret == 1) /* Sucessfully read packet*/
	       {
		       printf("\n\n\n\n=====%d th packet captured!!====\n\n", i);
		       printf("Packet len : %d\n\n", header->caplen);

		       ehdr_pointer = (my_peth)packet;
		    
		       printf("===Ether Part Start===\n\n");

		
		       //Ethernet part 
		       Print_Ether_Info(ehdr_pointer);

		      eth_type = ntohs(ehdr_pointer->ether_type);

		      if(eth_type == ETHERTYPE_IP) //if next protocol is IP protocol 
		      {
			      //IP part
			      printf("====It is IP Packet====\n\n");

			      iphdr_pointer = (my_pip)(packet + sizeof(my_eth));

			      printf("Source IP : %s\n", inet_ntoa(iphdr_pointer->ip_src));
			      printf("Destination IP : %s\n", inet_ntoa(iphdr_pointer->ip_dst)); //convert struct in_addr to IP address string
			      printf("Protocol Type : %0x\n\n", iphdr_pointer->ip_p);

			      ip_type = iphdr_pointer->ip_p;

			      if(ip_type == IPTYPE_TCP)// if next protocol is TCP
			      {
				      //TCP Part
				      printf("=====It is TCP packet Also!====\n\n");

				      tcphdr_pointer = (my_ptcp)(packet+ sizeof(my_ip) + sizeof(my_eth));

				      printf("Source Port : %d\n", ntohs(tcphdr_pointer->tcp_sport));
				      printf("Destination Port : %d\n\n", ntohs(tcphdr_pointer->tcp_dport));

				      //Print Extra Data
				      data_pointer = packet + sizeof(my_eth) + sizeof(my_ip) + sizeof(my_tcp);
				      data_len = header->caplen - sizeof(my_eth) - sizeof(my_ip) - sizeof(my_tcp);

				      Print_extra_data(data_pointer, data_len);

			      }

		      }
		      printf("====End of %d th packet!!!====\n\n\n\n", i);
       		       /* And close the session */
	       }
	       else if(pcap_ret == 0)
	       {
		       printf("packet buffer timeout expired\n");
		       continue;
	       }
	       else if(pcap_ret == -1)
	       {
		       printf("error occured while reading the packet\n");
		       return -1;
	       }
	       else if(pcap_ret == -2)
	       {
		       printf("read from savefile and no more read savefile\n");
		       return -2;
	       }

	}
	pcap_close(handle);
	return(0);
}


void Print_Ether_Info(my_peth ehdr_pointer)
{
	printf("dest mac =  %02x:%02x:%02x - %02x:%02x:%02x\n", ehdr_pointer->ether_dmac[0], ehdr_pointer->ether_dmac[1], ehdr_pointer->ether_dmac[2], ehdr_pointer->ether_dmac[3], ehdr_pointer->ether_dmac[4], ehdr_pointer->ether_dmac[5]);
	printf("src mac = %02x:%02x:%02x - %02x:%02x:%02x\n", ehdr_pointer->ether_smac[0], ehdr_pointer->ether_smac[1], ehdr_pointer->ether_smac[2], ehdr_pointer->ether_smac[3], ehdr_pointer->ether_smac[4], ehdr_pointer->ether_smac[5]);
	printf("next protocol type : %04x\n\n", ntohs(ehdr_pointer->ether_type));
}

void Print_extra_data(u_char *str, int len)
{
	int i = len;
	int roop = i / 16;
	int rem = i % 16;
	int cur = 0;

	while(cur < roop)
	{
		for(i=0;i<16;i++)
			printf("%02x ", str[cur * 16 + i]);

		printf("\n");

		cur++;
	}

	for(i=0;i<rem;i++)
		printf("%02x ", str[cur * 16 + i]);

	printf("\n");

}


