all:  
	gcc mypcap.c p3.c -o p3

test: 
	./p3       test1_input.pcap     student_test1_output.pcap      arp.dat
	diff  -s   test1_output.pcap    student_test1_output.pcap      

clean:
	rm -f p3   student_test1_output.pcap 
