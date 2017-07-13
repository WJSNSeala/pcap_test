pcap_test : pcap_test.c
	gcc -o pcap_test -lpcap pcap_test.c

clean:
	rm pcap_test
