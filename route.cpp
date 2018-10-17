/**
 * Project 2: Virtual Router
 * Owen Dunn and Reuben Wattenhofer
 * A virtual network with five hosts and two routers is first created. 
 * This code is then run from both routers.
 * Part 1: ARP and ICMP protocols
 * 
 * compile: g++ -std=c++0x route.cpp -o r (from outside of mininet, then send r)
 * -having trouble installing c++ compilers on mininet
 */

#include <sys/socket.h> 
#include <sys/select.h> // select()
#include <sys/ioctl.h>  // get source mac addr
#include <arpa/inet.h>  // htons(), ...
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <net/if.h> 
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string>
#include <string.h>  // strcmp (might want to use cpp version)
#include <unistd.h>
#include <iostream> 
#include <map>
//#include <vector>


using namespace std;

struct ouricmp {  // 64 bytes
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;
    u_int16_t sequence;
};
struct ouricmpts {  // 128 bytes
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;
    u_int16_t sequence;
    u_int64_t timestamp;
};

int main(int argc, char** argv) {
  int packet_socket;
  fd_set sockets;  // everything interact with gets a fd, starts an empty set?
  FD_ZERO(&sockets);

  //map() port number=mac
	//interface name = port number
	map <int, char*>  port2mac;
	map <char*, int>  name2port;


  //get list of interface addresses. This is a linked list. Next
  //pointer is in ifa_next, interface name is in ifa_name, address is
  //in ifa_addr. You will have multiple entries in the list with the
  //same name, if the same interface has multiple addresses. This is
  //common since most interfaces will have a MAC, IPv4, and IPv6
  //address. You can use the names to match up which IPv4 address goes
  //with which MAC address.
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr) == -1){
    perror("getifaddrs");
    return 1;
  }
  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {
    //Check if this is a packet address, there will be one per
    //interface.  There are IPv4 and IPv6 as well, but we don't care
    //about those for the purpose of enumerating interfaces. We can
    //use the AF_INET addresses in this list for example to get a list
    //of our own IP addresses
    if(tmp->ifa_addr->sa_family == AF_PACKET) {
      printf("Interface: %s\n",tmp->ifa_name);
      //create a packet socket on interface r?-eth1
      // eth0 to eth3 on table: allow any of these interfaces
      if(!strncmp(&(tmp->ifa_name[3]),"eth0",4)  ||
         !strncmp(&(tmp->ifa_name[3]),"eth1",4)  ||
         !strncmp(&(tmp->ifa_name[3]),"eth2",4)  ||
         !strncmp(&(tmp->ifa_name[3]),"eth3",4) ) {  
        // Get MAC addr
        // ifa_addr is "network addr" = mac?
		//for (int k = 0; k < 14; k++) {

			char* mac = new char[6];
			for (int k = 10; k <= 15; k++) {
				mac[k-10] = tmp->ifa_addr->sa_data[k];
			}
			/*
			printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned char) tmp->ifa_addr->sa_data[10],
			(unsigned char) tmp->ifa_addr->sa_data[11],
			(unsigned char) tmp->ifa_addr->sa_data[12],
			(unsigned char) tmp->ifa_addr->sa_data[13],
			(unsigned char) tmp->ifa_addr->sa_data[14],
			(unsigned char) tmp->ifa_addr->sa_data[15]
			);*/
			printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned char) mac[0],
			(unsigned char) mac[1],
			(unsigned char) mac[2],
			(unsigned char) mac[3],
			(unsigned char) mac[4],
			(unsigned char) mac[5]
			);
			//printf("%x", tmp->ifa_addr->sa_data[k]);
			//if (k % 2 == 0 && k > 0) cout << ":";
			//printf("%i", tmp->ifa_addr->sa_data[k]);
        	//cout << tmp->ifa_addr->sa_data[k];
		//}
		//cout << endl;

        printf("Creating Socket on interface %s\n",tmp->ifa_name);
        //create a packet socket
        //AF_PACKET makes it a packet socket
        //SOCK_RAW makes it so we get the entire packet
        //could also use SOCK_DGRAM to cut off link layer header
        //ETH_P_ALL indicates we want all (upper layer) protocols
        //we could specify just a specific one
        packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

		port2mac.insert(pair<int, char*>(packet_socket, mac));

        if(packet_socket<0) {
          perror("socket");
          return 2;
        }
        //Bind the socket to the address, so we only get packets
        //recieved on this specific interface. For packet sockets, the
        //address structure is a struct sockaddr_ll (see the man page
        //for "packet"), but of course bind takes a struct sockaddr.
        //Here, we can use the sockaddr we got from getifaddrs (which
        //we could convert to sockaddr_ll if we needed to)
        if(bind(packet_socket, tmp->ifa_addr, 
          sizeof(struct sockaddr_ll)) == -1) {
          perror("bind");
        }

        // listen to connections from clients, give a backlog number of up to 
	    // 10 clients to accept at once, rejects all further clients
        listen(packet_socket, 10);  // needed? TODO
        // adds the fd to the set pointed to (can do with any fd)
        FD_SET(packet_socket, &sockets); 
      }
    }
  }

	map<int, char*>::iterator p;
	//p = port2mac.begin();
	//cout << p->second << endl;
	/*		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned char) p->second[0],
			(unsigned char) p->second[1],
			(unsigned char) p->second[2],
			(unsigned char) p->second[3],
			(unsigned char) p->second[4],
			(unsigned char) p->second[5]
			);*/
  

  //loop and recieve packets. We are only looking at one interface,
  //for the project you will probably want to look at more (to do so,
  //a good way is to have one socket per interface and use select to
  //see which ones have data)
  printf("Ready to recieve now\n");
  while(1) {
    fd_set tmp_set = sockets;
    // args: highest num of fd set, fd to check if can read from them, 
    // check for err conds, timeout conds,
    // it modifies the parameter passed: holds only that have data to read  
    // takes fd set and checks sockets if are readable
    int fd_read_n = select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
    char buf[5000];  // how much room needed? (1500 data, all headers)
    struct sockaddr_ll recvaddr;
    socklen_t recvaddrlen = sizeof(struct sockaddr_ll);

    // Read all packet sockets with data.
    if (fd_read_n > 0) {  // if have at leaset one socket to read
        for(int i=0; i<FD_SETSIZE; i++) {
            if(FD_ISSET(i, &tmp_set)) {
                //we can use recv, since the addresses are in the packet, but we
                //use recvfrom because it gives us an easy way to determine if
                //this packet is incoming or outgoing (when using ETH_P_ALL, we
                //see packets in both directions. Only outgoing can be seen when
                //using a packet socket with some specific protocol)
                int bytes_n = recvfrom(i, buf, 5000, 0,
                    (struct sockaddr*)&recvaddr, &recvaddrlen);
                //ignore outgoing packets (we can't disable some from being sent
                //by the OS automatically, for example ICMP port unreachable
                //messages, so we will just ignore them here)
                if(recvaddr.sll_pkttype == PACKET_OUTGOING)
                    continue;
                //start processing all others
                printf("Got a %d byte packet\n", bytes_n);

                // TODO Process the packet and reply to any requests.

                // Parse the ether header. Other header present depends on 
                // what is found in the ether header.
                struct ether_header* pehdr;  // 14 bytes
                struct iphdr* piphdr;  // starts after ether hdr (size = )
                struct ouricmp* icmphdr;  // starts after ether hdr (size = )
                struct ouricmpts* tsicmphdr;  // starts after ether hdr (size = )
                struct ether_arp* peahdr;  // starts after ether hdr (size = )
                if (bytes_n > 0) {
                    pehdr = (struct ether_header *) buf; 
                    // only getting arp packets with ping r1/r2 (something wrong?)
                    switch (ntohs(pehdr->ether_type)) {  // endian conversion
                    case 0x0800:  // ICMP embedded within
                        {
                        cout << "IPv4 packet found" << endl;  
                        piphdr = (struct iphdr*) (buf+ETHER_HDR_LEN);
                        icmphdr = (struct ouricmp*) (buf+ETHER_HDR_LEN+sizeof(struct iphdr));
                        tsicmphdr = (struct ouricmpts*) (buf+ETHER_HDR_LEN+sizeof(struct iphdr));
                        // Check for ICMP here (within)
                        // cout << "ICMP packet found" << endl;
                        // Create packet to send back: TODO
                        uint8_t packet[bytes_n];
                        struct ether_header* ehdr_reply = (struct ether_header*) packet;
                        //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                        struct iphdr* iphdr_reply = (struct iphdr*) (packet+ETHER_HDR_LEN);
                        struct ouricmp* icmphdr_reply = (struct ouricmp*) (packet+ETHER_HDR_LEN+sizeof(struct iphdr));
                        struct ouricmpts* tsicmphdr_reply = (struct ouricmpts*) (packet+ETHER_HDR_LEN+sizeof(struct iphdr));

                        // int timestamp = 0;
                        int dataSize;
                        // if (icmphdr->type == 8) {
                        //     printf("timestamp\n");
                        //     // timestamp = 8;
                        //     dataSize = bytes_n - (ETHER_HDR_LEN + sizeof(struct iphdr) + sizeof(struct ouricmpts));
                        //     tsicmphdr_reply->type = tsicmphdr->type;
                        //     tsicmphdr_reply->code = tsicmphdr->code;
                        //     tsicmphdr_reply->checksum = tsicmphdr->checksum;
                        //     tsicmphdr_reply->id = tsicmphdr->id;
                        //     tsicmphdr_reply->sequence = tsicmphdr->sequence;
                        //     tsicmphdr_reply->timestamp = tsicmphdr->timestamp;
                        // } else {
                            dataSize = bytes_n - (ETHER_HDR_LEN + sizeof(struct iphdr) + sizeof(struct ouricmp));
                            icmphdr_reply->type = htons(8);
                            icmphdr_reply->code = icmphdr->code;
                            icmphdr_reply->checksum = icmphdr->checksum;
                            icmphdr_reply->id = icmphdr->id;
                            icmphdr_reply->sequence = icmphdr->sequence;
                        // }

                        //char data[dataSize];
						/*
                        for (int k = bytes_n - dataSize; k < bytes_n; k++) {
                            data[k-bytes_n] = buf[k];
                        }
						*/
                        //memcpy(data, buf + [bytes_n - dataSize], dataSize);
                        memcpy(packet + (ETHER_HDR_LEN+sizeof(struct iphdr)) + sizeof(struct ouricmp), buf + bytes_n - dataSize, dataSize);

                        //ethernet header
                        ehdr_reply->ether_type = pehdr->ether_type;
                        memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                        memcpy(ehdr_reply->ether_shost, pehdr->ether_dhost, ETH_ALEN);
                        //ip header                        
// #if __BYTE_ORDER == __LITTLE_ENDIAN
//     unsigned int ihl:4;
//     unsigned int version:4;
// #elif __BYTE_ORDER == __BIG_ENDIAN
//     unsigned int version:4;
//     unsigned int ihl:4;
// #else
// # error	"Please fix <bits/endian.h>"
// #endif
//     uint8_t tos;
//     uint16_t tot_len;
//     uint16_t id;
//     uint16_t frag_off;
//     uint8_t ttl;
//     uint8_t protocol;
//     uint16_t check;
//     uint32_t saddr;
//     uint32_t daddr;
                        iphdr_reply->ihl = piphdr->ihl;
                        iphdr_reply->version = piphdr->version;
                        iphdr_reply->tos = piphdr->tos;
                        iphdr_reply->tot_len = piphdr->tot_len;
                        iphdr_reply->id = piphdr->id;
                        iphdr_reply->frag_off = piphdr->frag_off;
                        iphdr_reply->ttl = piphdr->ttl;
                        iphdr_reply->protocol = piphdr->protocol;
                        iphdr_reply->check = piphdr->check;
                        iphdr_reply->saddr = piphdr->daddr;
                        iphdr_reply->daddr = piphdr->saddr;
                        //icmp header
    // u_int8_t type;
    // u_int8_t code;
    // u_int16_t checksum;
    // u_int16_t id;
    // u_int16_t sequence;
                       send(i, packet, bytes_n, 0);
                       }

                       break;

                    case 0x0806:
                        cout << "ARP packet found" << endl;
                        // Retrieve arp header: 
                        peahdr = (struct ether_arp*) (buf + ETHER_HDR_LEN);
                        // Check if request:
                        cout << "op: " << ntohs(peahdr->arp_op) << endl;
                        if (ntohs(peahdr->arp_op) == 1) {
                            cout << "ARP request made" << endl;
                            // Create packet to send back: TODO
                            uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
                            struct ether_header* ehdr_reply = (struct ether_header*) packet;
                            //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                            struct ether_arp* eahdr_reply = (struct ether_arp*) (packet+ETHER_HDR_LEN);
                            //ehdr_reply.ether_dhost = 
//   uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
//   uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
//   uint16_t ether_type;		        /* packet type ID field	*/
                            ehdr_reply->ether_type = pehdr->ether_type;
                            memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                            
							/*
                            // Get the source's MAC addr
                            char buf[1024];
                            int success = 0;
                            struct ifreq ifr;
                            struct ifconf ifc;
                            ifc.ifc_len = sizeof(buf);
                            ifc.ifc_buf = buf;
                            if (ioctl(i, SIOCGIFCONF, &ifc) == -1) {
                                perror("MAC address");
                                return 3;
                            }
                            struct ifreq* it = ifc.ifc_req;
                            const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

                            for (; it != end; ++it) {
                                strcpy(ifr.ifr_name, it->ifr_name);
                                if (ioctl(i, SIOCGIFFLAGS, &ifr) == 0) {
                                    if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                                        if (ioctl(i, SIOCGIFHWADDR, &ifr) == 0) {
                                            success = 1;
                                            break;
                                        }
                                    }
                                }
                                else { 
                                    perror("Retrieving MAC from socket");
                                    return 4;
                                }
                            }
                            unsigned char mac_address[6];
                            if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
                            cout << "MAC addr of interface found: " 
                                << ether_ntoa((const ether_addr*)mac_address) << endl;
                            memcpy(ehdr_reply->ether_shost, mac_address, ETH_ALEN);
                             */
                            // Send packet to ??? table lookup?
                            //struct arphdr
    //unsigned short int ar_op;		/* ARP opcode (command).  */
    // unsigned short int ar_hrd;		/* Format of hardware address.  */
    // unsigned short int ar_pro;		/* Format of protocol address.  */
    // unsigned char ar_hln;		/* Length of hardware address.  */
    // unsigned char ar_pln;		/* Length of protocol address.  */

// #define	arp_hrd	ea_hdr.ar_hrd
// #define	arp_pro	ea_hdr.ar_pro
// #define	arp_hln	ea_hdr.ar_hln
// #define	arp_pln	ea_hdr.ar_pln
// #define	arp_op	ea_hdr.ar_op

                            eahdr_reply->arp_op = htons(2);
                            eahdr_reply->arp_hrd = peahdr->arp_hrd;
                            eahdr_reply->arp_pro = peahdr->arp_pro;
                            eahdr_reply->arp_hln = peahdr->arp_hln;
                            eahdr_reply->arp_pln = peahdr->arp_pln;
                            //struct ether_arp

     // uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	// uint8_t arp_spa[4];		/* sender protocol address */
	// uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
	// uint8_t arp_tpa[4];		/* target protocol address */
                            uint8_t fakeMac[6] = {1,1,1,1,1,1};
							char* t = port2mac[i];
                            uint8_t macAddress[6] = {
									(uint8_t) t[0],
									(uint8_t) t[1],
									(uint8_t) t[2],
									(uint8_t) t[3],
									(uint8_t) t[4],
									(uint8_t) t[5],
								};
							
                            memcpy(eahdr_reply->arp_sha, macAddress, ETH_ALEN);
                            memcpy(eahdr_reply->arp_spa, peahdr->arp_tpa, 4);
                            memcpy(eahdr_reply->arp_tha, peahdr->arp_sha, ETH_ALEN);
                            memcpy(eahdr_reply->arp_tpa, peahdr->arp_spa, 4);

// ether_dhost
// ether_shost
                            // sizeof(*packet)
                            send(i, packet, sizeof(struct ether_header) + sizeof(struct ether_arp), 0);
                        }
                        // cout << "sending packet\n";
                        // send(i, "asdfasdf", 9, 0);

                        break;
                    
                    default:
                        cout << "Other packet type found: " <<  
                        ntohs(pehdr->ether_type) << endl;    
                    }
                }
                
            }
        }
    }
    


    //what else to do is up to you, you can send packets with send,
    //just like we used for TCP sockets (or you can use sendto, but it
    //is not necessary, since the headers, including all addresses,
    //need to be in the buffer you are sending)
  }

  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);
  //exit
  return 0;
}
