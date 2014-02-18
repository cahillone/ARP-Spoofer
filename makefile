##### Makefile #####

# Chad Cahill
# eece 555
# Fall 2013

arp_responder: arp_responder.c
	gcc arp_responder.c -Wall -o arp_responder -lpcap -g
clean:
	rm arp_responder

###################
