/**
 * Project 2: Virtual Router
 * Owen Dunn and Reuben Wattenhofer
 * 10/29/18
 * CIS 457
 * 
 * A virtual network with five hosts and two routers is first created. 
 * This code is then run from both routers.
 * Part 1: ARP and ICMP protocols
 * Part 2: Packet forwarding
 * Part 3: IP Checksum, TTL update, ICMP error messages
 * 
 * compile: g++ route.cpp -o r (from outside of mininet, then send r)
 * compile: g++ -static-libstdc++ route.cpp -o r (from outside of mininet, then send r)
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
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string>
#include <string.h>  // strcmp (might want to use cpp version)
#include <unistd.h>
#include <iostream> 
#include <map>
#include <string.h>
#include <vector>  // not sure if works on system
//#include <sstream> // for int to char* conversions (stringstream)
#include <math.h> //for power
#include <algorithm>  // std::find
#include <iterator>

using namespace std;

struct ouricmp {  // 64 bytes
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;  // id and
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

struct packetStorage {
    char* packet;
    int bytes;
};

uint16_t cksum(uint16_t *buf, int count);
uint16_t ip_checksum(void* vdata, size_t length);

int main(int argc, char** argv) {
    int packet_socket;
    fd_set sockets;  // everything interact with gets a fd, starts an empty set?
    FD_ZERO(&sockets);

    //map() port number=mac
    //interface name = port number
    map <int, char*>  port2mac;
    // map <int, uint32_t>  port2mac;
    // map <char*, int>  name2port;
    map <string, int>  name2port;
    // map <string, string>  name2ip;
    map <string, char*>  name2ip;
    // map <char*, char*> name2ip; // for router's own ip addresses
    map <vector<uint8_t>, vector<packetStorage*>> packets; //dest ip addr = packet

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
    // for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {
    //     printf("*\nInterface: %s\n",tmp->ifa_name);
    //     printf("ifa_addr: %0x\n", tmp->ifa_addr->sa_data);
    //     printf("ifa_netmask: %0x\n", tmp->ifa_netmask->sa_data);
    // }
    for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {
        //Check if this is a packet address, there will be one per
        //interface.  There are IPv4 and IPv6 as well, but we don't care
        //about those for the purpose of enumerating interfaces. We can
        //use the AF_INET addresses in this list for example to get a list
        //of our own IP addresses
        if(tmp->ifa_addr->sa_family == AF_PACKET) {  // AF_PACKET for mac addr
            printf("**\nInterface: %s\n",tmp->ifa_name);
            //create a packet socket on interface r?-eth1
            // eth0 to eth3 on table: allow any of these interfaces
            if(!strncmp(&(tmp->ifa_name[3]),"eth0",4)  ||
                !strncmp(&(tmp->ifa_name[3]),"eth1",4)  ||
                !strncmp(&(tmp->ifa_name[3]),"eth2",4)  ||
                !strncmp(&(tmp->ifa_name[3]),"eth3",4) ) {  
                // Get MAC addr
                // ifa_addr is "network addr" = mac?
                //for (int k = 0; k < 14; k++) {
                
                // Doc says is has 14 bytes only! ????
                char* mac = new char[6];
                for (int k = 10; k <= 15; k++) {  // bits 10 - 15 are mac addr
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

                printf("Creating Socket on interface %s\n",tmp->ifa_name);
                //create a packet socket
                //AF_PACKET makes it a packet socket
                //SOCK_RAW makes it so we get the entire packet
                //could also use SOCK_DGRAM to cut off link layer header
                //ETH_P_ALL indicates we want all (upper layer) protocols
                //we could specify just a specific one
                packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

                port2mac.insert(pair<int, char*>(packet_socket, mac));

                //update name2port
                char* t = new char[8];  // char(8) assigns 1 char value 8
                strcpy(t, tmp->ifa_name);
                t[7] = '\0';
                string s(t);
                // name2port.insert(pair<char*, int>(t, packet_socket));
                name2port.insert(pair<string, int>(s, packet_socket));
                //if(!strncmp(tmp->ifa_name,"r1-eth0",7 ) ) {
                    cout << "name2port key: " << t << " value: " << packet_socket << endl;
                //}

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

        else if(tmp->ifa_addr->sa_family == AF_INET) {  // need to know ip addr for arp request
            printf("--\nIP Interface: %s\n",tmp->ifa_name);
            //create a packet socket on interface r?-eth1
            // eth0 to eth3 on table: allow any of these interfaces
            if(!strncmp(&(tmp->ifa_name[3]),"eth0",4)  ||
                !strncmp(&(tmp->ifa_name[3]),"eth1",4)  ||
                !strncmp(&(tmp->ifa_name[3]),"eth2",4)  ||
                !strncmp(&(tmp->ifa_name[3]),"eth3",4) )
                {  
                // Get MAC addr
                // ifa_addr is "network addr" = mac?
                //for (int k = 0; k < 14; k++) {

                char* mac = new char[4];
                for (int k = 2; k <= 5; k++) {  // bits 2 to 5 are ip addr
                    mac[k-2] = tmp->ifa_addr->sa_data[k];
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

                // printf("%i.%i.%i.%i\n",
                    // (unsigned char) mac[0],
                    // (unsigned char) mac[1],
                    // (unsigned char) mac[2],
                    // (unsigned char) mac[3]
                    // );
                    // printf("%s\n",mc);

                //printf("%x", tmp->ifa_addr->sa_data[k]);
                //if (k % 2 == 0 && k > 0) cout << ":";
                //printf("%i", tmp->ifa_addr->sa_data[k]);
                //cout << tmp->ifa_addr->sa_data[k];
                //}
                //cout << endl;
                //char chase[14];
                // string ma(&(chase[0]), 4);
                
                //strcpy(chase, tmp->ifa_addr->sa_data);
                // cout << "chase: " << chase << endl;
                // cout << "addr: " << tmp->ifa_addr->sa_data << endl;
                //string ma(&(tmp->ifa_addr->sa_data[2]),4);
                //update name2ip
                char* t = new char[8];  // char(8) assigns 1 char value 8
                strcpy(t, tmp->ifa_name);
                t[7] = '\0';
                string s(t);

                //string sip = ma;
                // cout << "value: " << sip << endl;
                // name2port.insert(pair<char*, int>(t, packet_socket));
                //name2ip.insert(pair<string, string>(s, sip));
                name2ip[s] = mac;

                //if(!strncmp(tmp->ifa_name,"r1-eth0",7 ) ) {
                    // cout << "name2ip key: " << s << " value: " << name2ip[s] << endl;
                //}
                printf("name2ip\n%i.%i.%i.%i\n",
                    (unsigned char) name2ip[s][0],
                    (unsigned char) name2ip[s][1],
                    (unsigned char) name2ip[s][2],
                    (unsigned char) name2ip[s][3]
                    );
            }
        }        
    }
    
    // http://www.cplusplus.com/forum/beginner/123379/
    // iterate C++98 style
    {
        typedef std::map< string, int >::iterator outer_iterator ;
        cout << "       name2port map:\n";
        for( outer_iterator outer = name2port.begin() ; outer != name2port.end() ; ++outer )
        {
            std::cout << "      " << outer->first << ' ' ;
            std::cout << outer->second << '\n' ;
        }
    }
    // {
    //     typedef std::map< string, char*>::iterator outer_iterator ;
    //     cout << "       name2ip map:\n";
    //     for( outer_iterator outer = name2ip.begin() ; outer != name2ip.end() ; ++outer )
    //     {
    //         std::cout << "      " << outer->first << ' ' ;
    //         std::cout << outer->second << '\n' ;
    //     }
    // }

    // Parse router table information:
    map<string, int>::iterator itr;
    // Display the first element in m.
    itr = name2port.begin();
    char* t = (char*) itr->first.c_str();
    char fileName[13] = "  -table.txt";
    fileName[0] = t[0];
    fileName[1] = t[1];
    cout << "filename: " << fileName << endl;
    // Create 3 maps for getting table values from network bits (array form).
    // net in binary host order, 32 bits
    map <uint32_t, uint32_t> net2hop;  // hop ip addr, "-" value if none
    map <uint32_t, char*> net2if;   // interface
    map <uint32_t, uint8_t> net2length;  // net bits
    //vector <uint8_t> lengths;  // all network lengths
    // Parse table and store mapping types needed.
    // open file
    FILE *file_pointer; 
    file_pointer = fopen(fileName, "r");
    // Read table into string (works up to 4 GB)
    char* buffer = 0;
    long length;
    if (file_pointer)
    {
        fseek(file_pointer, 0, SEEK_END);
        length = ftell(file_pointer);
        fseek(file_pointer, 0, SEEK_SET);
        buffer = (char*)malloc(length + 1);  // must cast return in c++
        if(buffer)
        {
            fread(buffer, 1, length, file_pointer);
        }
        fclose(file_pointer);
        buffer[length]='\0';
    }
    char data[length+1];  // to allow strtok to modify string
    for(int z=0; z<length+1; z++) data[z] = buffer[z];
    free(buffer);
    // Now parse the string of table
    char* netaddr = new char[16]; 
    char* hopaddr = new char[16]; 
    char* ifc = new char[8];  // interface
    uint8_t bitLength;
    uint32_t b_netaddr;  // binary net address in host order
    uint32_t b_hopaddr;
    char str[INET_ADDRSTRLEN];
    cout << "parsing table" << endl;
    char* token = strtok(data, " /\n\0");
    while(token != NULL) // loop works for specific table format only
    { 
        strcpy(netaddr, token);
        printf("%s ", netaddr); 
        inet_pton(AF_INET, netaddr, &b_netaddr);  // string to net address
        //inet_ntop(AF_INET, &b_netaddr, str, INET_ADDRSTRLEN);
        //printf("made: %s ", str);
        //printf("%d ", sizeof(unsigned short int));  // 2 bytes only
        b_netaddr = (uint32_t)ntohl(b_netaddr);  // host order
        token = strtok(NULL, " /\n\0");  // get net length
        bitLength = (uint8_t)atoi(token);
        // if(std::find(lengths.begin(), lengths.end(), bitLength) != lengths.end()) {
        //     lengths.push_back(bitLength);
        // }
        printf("net addr: %#X ", b_netaddr);
        net2length[b_netaddr] = bitLength;
        printf("%d ", net2length[b_netaddr]); 
        //printf("%d ", (uint8_t)atoi(token));
        token = strtok(NULL, " /\n\0");  // hop addr
        strcpy(hopaddr, token);
        if (hopaddr[0] == '-'){
            b_hopaddr = 0;
        }else{
            inet_pton(AF_INET, hopaddr, &b_hopaddr); 
            b_hopaddr = (uint32_t)ntohl(b_hopaddr); 
        }
        net2hop[b_netaddr] = b_hopaddr;
        printf("%s ", token); 
        printf("hop addr: %#X ", b_hopaddr);
        token = strtok(NULL, " /\n\0");  // interface
        strcpy(ifc, token);
        ifc[7] = '\0';
        printf("%s\n", ifc);
        net2if[b_netaddr] = ifc;
        token = strtok(NULL, " /\n\0"); // get net addr (null after last row)
        // allocate mem for next net and hop addr, interface
        //netaddr = new char[16];  
        //hopaddr = new char[16];
        ifc = new char[8]; 
    } 
    cout << "table parsed" << endl;

	map<int, char*>::iterator p;
	//p = port2mac.begin();
	//cout << p->second << endl;
    /*printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
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
    if (fd_read_n > 0) {  // if have at least one socket to read
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
                printf("--------\nGot a %d byte packet\n", bytes_n);

                // Parse the ether header. Other header present depends on 
                // what is found in the ether header.
                struct ether_header* pehdr;  // 14 bytes
                struct iphdr* piphdr;  // starts after ether hdr (size = )
                struct ouricmp* icmphdr;  // starts after ether hdr (size = )
                struct ouricmpts* tsicmphdr;  // starts after ether hdr (size = )
                struct ether_arp* peahdr;  // starts after ether hdr (size = )
                if (bytes_n > 0) {
                    pehdr = (struct ether_header *) buf; // capture ethernet header
                    switch (ntohs(pehdr->ether_type)) {  // endian conversion (16 bits)
                    case ETHERTYPE_IP:  
                    {
                        cout << "IPv4 packet found" << endl;  
                        piphdr = (struct iphdr*) (buf+ETHER_HDR_LEN);  // capture ip hdr
                        printf("IP protocol: %u\n", piphdr->protocol);
                        
                        // Verify IP checksum: might need 2 more chunks (32 bits for options and padding)
                        // -need to change to host order before calc?
                        uint16_t check = 0, packet_check = piphdr->check;  // network order
                        piphdr->check = (uint16_t)0;  // set to 0 before calc?
                        printf("Packet checksum: %0x\n", ntohs(packet_check));
                        check = ip_checksum(piphdr, sizeof(struct iphdr));  // returns net order
                        printf("Calculated checksum: %0x\n", ntohs(check));
                        piphdr->check = check;
                        if (check == packet_check) {
                            printf("Checksum valid, keeping packet\n");
                        } else {
                            printf("Checksum invalid, dropping packet\n");
                            continue;
                        }

                        // Decrement TTL (not checked until arp reply received)
                        // Send ICMP error if packet time out, discard packet.
                        printf("TTL value: %i\n", piphdr->ttl);
                        int sendICMP3 = 0;
                        if (piphdr->ttl <= 1) {
                            cout << "Time out on packet" << endl;                  
                        }
                        // No problems, decrement
                        else {
                            printf("size of ipheader is %i\n", sizeof(struct iphdr));
                            // Decrement ttl
                            piphdr->ttl -= (uint8_t)1;  // 8 bits (cast to prevent 32 bit length?)
                            printf("New TTL value: %i\n", piphdr->ttl);
                            piphdr->check = (uint16_t)0; //zero out the field for checksum calc
                            // Recalculate and assign checksum
                            check = ip_checksum(piphdr, sizeof(struct iphdr));  // returns net order
                            piphdr->check = check;
                            printf("Protocol value: %i\n", piphdr->protocol);
                        }

                        switch (piphdr->protocol)  // part of IP
                        {
                        case 0x06:  // TCP (all of part 2 packet forwarding?)
                        {
                             cout << "   TCP packet Received" << endl;
//                             // Forward packet to dest:
//                             // Look up dest addr from table to get ip 
//                             // addr of next hop. Prefixes all 16 or 24 bits. 
//                             // Max of one match possible.
//                             uint32_t daddr = (uint32_t)ntohl(piphdr->daddr);  // 32 bits
//                             uint32_t hopaddr, hopaddrnet;
//                             int portNum;
//                             std::map<uint32_t, uint32_t>::iterator it;
//                             printf("    Dest ip addr: %#X\n", daddr);
//                             //struct in_addr struct_dest;
//                             //struct_dest.sin_addr.s_addr =  piphdr->daddr;
//                             printf("    or %s\n", inet_ntoa(*(struct in_addr*)&(piphdr->daddr)));
//                             if ((it=net2hop.find(daddr & 0xffff0000)) != net2hop.end() ) {  // 16 bit netlength
//                                 hopaddr = net2hop[daddr & 0xffff0000];
//                                 char* interface = net2if[daddr & 0xffff0000];
//                                 cout << "   interface: " << interface << endl;
//                                 string s(interface);
//                                 portNum = name2port[s];
//                                 cout << "   port: " << portNum << endl;
//                                 cout << "   Hop IP addr found in table." << endl;
//                                 hopaddrnet = (uint32_t)htonl(hopaddr);
//                                 printf("    hop addr: %s\n", inet_ntoa(*(struct in_addr*)&hopaddrnet));
//                             } else if ((it=net2hop.find(daddr & 0xffffff00)) != net2hop.end() ) {  // 24 bit netlength
//                                 hopaddr = net2hop[daddr & 0xffffff00];
//                                 char* interface = net2if[daddr & 0xffffff00];
//                                 cout << "   interface: " << interface << endl;
//                                 string s(interface);
//                                 portNum = name2port[s];
//                                 cout << "   port: " << portNum << endl;
//                                 cout << "   Hop IP addr found in table." << endl;
//                                 hopaddrnet = (uint32_t)htonl(hopaddr);
//                                 printf("    hop addr: %s\n", inet_ntoa(*(struct in_addr*)&hopaddrnet));
//                             } else {
//                                 // TODO NO MATCH: PART 3 ACTION HERE
//                                 cout << "   No match found in table." << endl;
//                                 break;
//                             }
 
//                             // TODO Use ARP to get dest MAC addr: (request hop addr for its MAC addr)
							
//                             if (hopaddr == 0)  // no hop for this network
// 							{

// 							} else {

// 							}
//                             cout << "       Using ARP to get MAC addr for hop" << endl;
                                
//                         // send ARP request
//                             uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
//                             struct ether_header* ehdr_reply = (struct ether_header*) packet;
//                             //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
//                             struct ether_arp* eahdr_reply = (struct ether_arp*) (packet+ETHER_HDR_LEN);
//                             //ehdr_reply.ether_dhost = 

//                             ehdr_reply->ether_type = htons(0x0806); //ARP
//                             // memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
//                             uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
//                             memcpy(ehdr_reply->ether_dhost, broadcast, ETH_ALEN);
//                             // ehdr_reply->ether_dhost = ; //broadcast

//                             eahdr_reply->arp_op = htons(1);// ARP request
//                             eahdr_reply->arp_hrd = htons(1);// ethernet //peahdr->arp_hrd;
//                             eahdr_reply->arp_pro = htons(0x0800);// IP //peahdr->arp_pro;
//                             eahdr_reply->arp_hln = htons(6);// //peahdr->arp_hln;
//                             eahdr_reply->arp_pln = htons(4);// //peahdr->arp_pln;

// 							char* t = port2mac[portNum];
//                             uint8_t macAddress[6] = {
// 									(uint8_t) t[0],
// 									(uint8_t) t[1],
// 									(uint8_t) t[2],
// 									(uint8_t) t[3],
// 									(uint8_t) t[4],
// 									(uint8_t) t[5],
// 								};
//                             memcpy(ehdr_reply->ether_shost, macAddress, ETH_ALEN);
							
//                             memcpy(eahdr_reply->arp_sha, macAddress, ETH_ALEN);
//                             memcpy(eahdr_reply->arp_spa, peahdr->arp_tpa, 4);
//                             memcpy(eahdr_reply->arp_tha, peahdr->arp_sha, ETH_ALEN);
//                             memcpy(eahdr_reply->arp_tpa, peahdr->arp_spa, 4);

//                             // sizeof(*packet)
//                             send(portNum, packet, sizeof(struct ether_header) + 
//                                 sizeof(struct ether_arp), 0);
							
//                             break;
                        }
// Currently falls through to handle forwarding of IP packets of all types in icmp case code
// - bytes read variable allows this to work?
// - if have dif hdrs at the same mem distance from ether hdr it shouldn't work
                        case 0x01:  // ICMP
                        { 
                            if (piphdr->protocol == 1) {
                                cout << "   ICMP request made" << endl;
                            }
                            // http://www.cplusplus.com/forum/beginner/123379/
                            // iterate C++98 style
                            {
                                typedef std::map< string, int >::iterator outer_iterator ;
                                cout << "       name2port map:\n";
                                for( outer_iterator outer = name2port.begin() ; outer != name2port.end() ; ++outer )
                                {
                                    std::cout << "      " << outer->first << ' ' ;
                                    std::cout << outer->second << '\n' ;
                                }
                            }

                            // Forward packet to dest:
                            // Look up dest addr from table to get ip 
                            // addr of next hop. Prefixes all 16 or 24 bits. 
                            // Max of one match possible.
                            uint32_t daddr = (uint32_t)ntohl(piphdr->daddr);  // 32 bits
                            uint32_t hopaddr, hopaddrnet;
                            int portNum;
                            std::map<uint32_t, uint32_t>::iterator it;
                            char* sipv4; //router ipv4
                            printf("    Dest ip addr: %#X\n", daddr);
                            //struct in_addr struct_dest;
                            //struct_dest.sin_addr.s_addr =  piphdr->daddr;
                            printf("    or %s\n", inet_ntoa(*(struct in_addr*)&(piphdr->daddr)));
                            if ((it=net2hop.find(daddr & 0xffffff00)) != net2hop.end() ) {  // 16 bit netlength
                                hopaddr = net2hop[daddr & 0xffffff00];
                                char* interface = net2if[daddr & 0xffffff00];
                                cout << "   interface (1): " << interface << endl;
                                string s(interface);
                                portNum = name2port[s];
                                sipv4 = name2ip[s];
                                cout << "   port: " << portNum << endl;
                                cout << "   Hop IP addr found in table." << endl;
                                hopaddrnet = (uint32_t)htonl(hopaddr);
                                printf("    hop addr: %s\n", inet_ntoa(*(struct in_addr*)&hopaddrnet));

                            } else if ((it=net2hop.find(daddr & 0xffff0000)) != net2hop.end() ) {  // 24 bit netlength
                                hopaddr = net2hop[daddr & 0xffff0000];
                                char* interface = net2if[daddr & 0xffff0000];
                                cout << "   interface (2): " << interface << endl;
                                string s(interface);
                                portNum = name2port[s];
                                sipv4 = name2ip[s];
                                cout << "   port: " << portNum << endl;
                                cout << "   Hop IP addr found in table." << endl;
                                hopaddrnet = (uint32_t)htonl(hopaddr);
                                printf("    hop addr: %s\n", inet_ntoa(*(struct in_addr*)&hopaddrnet));
                            } else {  // ICMP 3 message takes priority
                                // TODO NO MATCH: PART 3 ACTION HERE
                                cout << "   TCP/ICMP: No match found in table." << endl;
                                cout << "Sending ICMP Destination Unreachable packet." << endl;



                                break;
                            }
                            
                            if (hopaddr == 0)  // no hop for this network, go to final dest
							{
                                hopaddr = piphdr->daddr;
							} else {
                                hopaddr = (uint32_t)htonl(hopaddr); //flip it
                            }
							
                            //contruct hop address as an octet array x.x.x.x
                            // char* str = inet_ntoa(*(struct in_addr*)&(piphdr->daddr));
                            // uint32_t backwards = htons(hopaddr);
                            char* str = inet_ntoa(*(struct in_addr*)&(hopaddr));
                            char* pch;
                            char* dipv4 = new char[4];
                            int index = 0;
                            // printf ("Splitting string \"%s\" into tokens:\n",str);
                            pch = strtok (str, ".");
                            dipv4[index++] = atoi(pch);
                            // Get all 4 ipv4 address portions in an array
                            for (int k = 1; k < 4; k++) {
                                // printf("%s\n",pch);
                                pch = strtok (NULL, ".");
                                dipv4[index++] = atoi(pch);
                            }

                            // Store packet for later forwarding
                            struct packetStorage* pckt = new (struct packetStorage);  // new packetStorage(); to zero init

                            // write bytes read from buffer to packet
                            // pckt->packet = buf;
                            pckt->packet = new char[bytes_n];  // allocate packet mem
                            // for (int k = 0; k < bytes_n; k++) {
                                memcpy(pckt->packet, buf, bytes_n);  // copy packet to structure
                            // }
                            pckt->bytes = bytes_n;  // total bytes of the packet
                            vector<uint8_t> v;
                            v.push_back(dipv4[0]);
                            v.push_back(dipv4[1]);
                            v.push_back(dipv4[2]);
                            v.push_back(dipv4[3]);

                            cout << "       dest network address: " ;  //<< dipv4 <<endl;
                            printf("%i.%i.%i.%i\n",(unsigned int)v[0],
                                                    (unsigned int)v[1],
                                                    (unsigned int)v[2],
                                                    (unsigned int)v[3]);

                            // packets[(uint8_t*) dipv4].push_back(pckt);
                            // Add packet to packet map.
                            // returns vector of pointers to packet structures for given ipv4 addr
                            packets[v].push_back(pckt);  // add packet to packets map for given ipv4 addr

                            printf("        size of packets[v]: %i\n", packets[v].size());
                            if (packets[v].size() > 0) {  // if have >= 1 packet for given ipv4 addr
                                // printf("        packet: %0x\n", packets[v].back()->packet);
                                // struct iphdr* a = (struct iphdr*) (packets[v].back()->packet+ETHER_HDR_LEN);
                                // printf("        packet type: %i\n", a->protocol);
                                // printf("        size of packets[v]: %i\n", packets[v].size());
                                printf("        packet: %0x\n", packets[v].back()->packet);  // returns ref to last element of vector
                                // struct iphdr* a = (struct iphdr*) (packet->packet+ETHER_HDR_LEN);
                                struct ether_header* a = (struct ether_header*) (packets[v].back()->packet);
                                // printf("        packet type: %0x\n", a->protocol);
                                printf("        packet type: %0x\n", ntohs(a->ether_type));
                                printf("        original packet type: %0x\n", ntohs(pehdr->ether_type));
                                printf("        packet size: %i\n", packets[v].back()->bytes);
                            }

                            printf("    router ip %i.%i.%i.%i\n",
                                (unsigned char) sipv4[0],
                                (unsigned char) sipv4[1],
                                (unsigned char) sipv4[2],
                                (unsigned char) sipv4[3]
                                );

                            // Use ARP to get dest MAC addr: (request hop addr for its MAC addr)
                            // add the packet to the map
                            cout << "       TCP/ICMP: Using ARP to get MAC addr for forward" << endl;
                            ///////////////////////////////////////////////////
                            // Send ARP request
                            // Create ARP request packet and then send: TODO make into function
                            // - used to get next address in forward path
                            //////////////////////////////////////////////////////
                            uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
                            struct ether_header* ehdr_reply = (struct ether_header*) packet;
                            //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                            struct ether_arp* eahdr_reply = (struct ether_arp*) (packet+ETHER_HDR_LEN);
                            //ehdr_reply.ether_dhost = 

                            ehdr_reply->ether_type = htons(0x0806); // ARP
                            // memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                            uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};  // all 1s for broadcast
                            memcpy(ehdr_reply->ether_dhost, broadcast, ETH_ALEN);
                            // ehdr_reply->ether_dhost = ;  // broadcast
                            eahdr_reply->arp_op = htons(1);  // ARP request
                            eahdr_reply->arp_hrd = htons(1);  // ethernet //peahdr->arp_hrd;
                            eahdr_reply->arp_pro = htons(0x0800);  // IP //peahdr->arp_pro;
                            eahdr_reply->arp_hln = 6;  // peahdr->arp_hln;
                            eahdr_reply->arp_pln = 4;  // peahdr->arp_pln;

							char* t = port2mac[portNum];
                            uint8_t macAddress[6] = {
									(uint8_t) t[0],
									(uint8_t) t[1],
									(uint8_t) t[2],
									(uint8_t) t[3],
									(uint8_t) t[4],
									(uint8_t) t[5],
								};

                            cout << "       Source MAC: ";
                            printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                                (unsigned char) macAddress[0],
                                (unsigned char) macAddress[1],
                                (unsigned char) macAddress[2],
                                (unsigned char) macAddress[3],
                                (unsigned char) macAddress[4],
                                (unsigned char) macAddress[5]
                                );

                            memcpy(ehdr_reply->ether_shost, macAddress, ETH_ALEN);

                            // struct in_addr* in = (struct in_addr*)piphdr->daddr;
                            // cout << "       : " << in->s_addr << endl;
                            //char* dipv4 = new char(5);
                            //inet_ntop(AF_INET, &(piphdr->daddr), dipv4, 4);
                            //dipv4[4] = '\0';

                            memcpy(eahdr_reply->arp_sha, macAddress, ETH_ALEN);
                            memcpy(eahdr_reply->arp_spa, sipv4, 4);
                            memcpy(eahdr_reply->arp_tha, broadcast, ETH_ALEN);
                            memcpy(eahdr_reply->arp_tpa, dipv4, 4);
                            // sizeof(*packet)
                            // Send created ARP request packet.
                            send(portNum, packet, sizeof(struct ether_header) + 
                                sizeof(struct ether_arp), 0);

                            //-------------
                            //TODO: figure out how to respond to icmp requests sent to router (Part 1)!!!!!!!
                            // is this working now? All below commented not needed? Delete if so
                            //-------------

                            // icmphdr = 
                            //     (struct ouricmp*) (buf+ETHER_HDR_LEN+sizeof(struct iphdr));
                            // tsicmphdr = (struct ouricmpts*) (buf+ETHER_HDR_LEN+sizeof(struct iphdr));
                            // // Check for ICMP here (within)
                            // // cout << "ICMP packet found" << endl;
                            // // Create packet to send back: TODO
                            // uint8_t packet[bytes_n];
                            // struct ether_header* ehdr_reply = (struct ether_header*) packet;
                            // //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                            // struct iphdr* iphdr_reply = 
                            //     (struct iphdr*) (packet+ETHER_HDR_LEN);
                            // struct ouricmp* icmphdr_reply = 
                            //     (struct ouricmp*) (packet+ETHER_HDR_LEN+sizeof(struct iphdr));
                            // struct ouricmpts* tsicmphdr_reply = 
                            //     (struct ouricmpts*) (packet+ETHER_HDR_LEN+sizeof(struct iphdr));

                            // // int timestamp = 0;
                            // int dataSize;
                            // // if (icmphdr->type == 8) {
                            // //     printf("timestamp\n");
                            // //     // timestamp = 8;
                            // //     dataSize = bytes_n - (ETHER_HDR_LEN + sizeof(struct iphdr) + sizeof(struct ouricmpts));
                            // //     tsicmphdr_reply->type = tsicmphdr->type;
                            // //     tsicmphdr_reply->code = tsicmphdr->code;
                            // //     tsicmphdr_reply->checksum = tsicmphdr->checksum;
                            // //     tsicmphdr_reply->id = tsicmphdr->id;
                            // //     tsicmphdr_reply->sequence = tsicmphdr->sequence;
                            // //     tsicmphdr_reply->timestamp = tsicmphdr->timestamp;
                            // // } else {
                            // dataSize = bytes_n - 
                            //     (ETHER_HDR_LEN + 
                            //     sizeof(struct iphdr) + sizeof(struct ouricmp));
                            // icmphdr_reply->type = htons(8);
                            // icmphdr_reply->code = icmphdr->code;
                            // icmphdr_reply->checksum = icmphdr->checksum;
                            // icmphdr_reply->id = icmphdr->id;
                            // icmphdr_reply->sequence = icmphdr->sequence;
                            // // }

                            // //char data[dataSize];
                            // /*
                            // for (int k = bytes_n - dataSize; k < bytes_n; k++) {
                            //     data[k-bytes_n] = buf[k];
                            // }
                            // */
                            // //memcpy(data, buf + [bytes_n - dataSize], dataSize);
                            // memcpy(packet + 
                            //     (ETHER_HDR_LEN+sizeof(struct iphdr)) + 
                            //     sizeof(struct ouricmp), 
                            //     buf + bytes_n - dataSize, 
                            //     dataSize);

                            // //ethernet header
                            // ehdr_reply->ether_type = pehdr->ether_type;
                            // memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                            // memcpy(ehdr_reply->ether_shost, pehdr->ether_dhost, ETH_ALEN);

                            // iphdr_reply->ihl = piphdr->ihl;
                            // iphdr_reply->version = piphdr->version;
                            // iphdr_reply->tos = piphdr->tos;
                            // iphdr_reply->tot_len = piphdr->tot_len;
                            // iphdr_reply->id = piphdr->id;
                            // iphdr_reply->frag_off = piphdr->frag_off;
                            // iphdr_reply->ttl = piphdr->ttl;
                            // iphdr_reply->protocol = piphdr->protocol;
                            // iphdr_reply->check = piphdr->check;
                            // iphdr_reply->saddr = piphdr->daddr;
                            // iphdr_reply->daddr = piphdr->saddr;

                            // send(i, packet, bytes_n, 0);

                            break;
                        }  // endof icmp protocol case
                        }  // end of ip protocol switch

                        break;
                    } //endof ethertypeip
                    
                    case ETHERTYPE_ARP:  // ARP
                    {
                        cout << "ARP packet found" << endl;
                        // Retrieve arp header:
                        peahdr = (struct ether_arp*) (buf + ETHER_HDR_LEN);
                        // Check if request:
                        cout << "op: " << ntohs(peahdr->arp_op) << endl;  // 16-bits
                        if (ntohs(peahdr->arp_op) == 1) {  // REQUEST
                            cout << "ARP request made" << endl;
                            // TODO create fcn for creation of arp packets
                            // Create packet to send back
                            uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
                            struct ether_header* ehdr_reply = (struct ether_header*) packet;
                            //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                            struct ether_arp* eahdr_reply = (struct ether_arp*) (packet+ETHER_HDR_LEN);
                            //ehdr_reply.ether_dhost = 

                            ehdr_reply->ether_type = pehdr->ether_type;
                            memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                            
							/*
                            // Get the source's MAC addr (should be able to get from map made earlier?)
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
                            //struct arphdr
                            eahdr_reply->arp_op = htons(2);
                            eahdr_reply->arp_hrd = peahdr->arp_hrd;
                            eahdr_reply->arp_pro = peahdr->arp_pro;
                            eahdr_reply->arp_hln = peahdr->arp_hln;
                            eahdr_reply->arp_pln = peahdr->arp_pln;
							char* t = port2mac[i];
                            uint8_t macAddress[6] = {
									(uint8_t) t[0],
									(uint8_t) t[1],
									(uint8_t) t[2],
									(uint8_t) t[3],
									(uint8_t) t[4],
									(uint8_t) t[5],
								};
                            memcpy(ehdr_reply->ether_shost, macAddress, ETH_ALEN);
                            memcpy(eahdr_reply->arp_sha, macAddress, ETH_ALEN);
                            memcpy(eahdr_reply->arp_spa, peahdr->arp_tpa, 4);
                            memcpy(eahdr_reply->arp_tha, peahdr->arp_sha, ETH_ALEN);
                            memcpy(eahdr_reply->arp_tpa, peahdr->arp_spa, 4);

                            // sizeof(*packet)
                            // Send ARP reply packet to request sender mac address.
                            send(i, packet, sizeof(struct ether_header) + 
                                sizeof(struct ether_arp), 0);
                        // END OF ARP REQUEST

                        //---------------------------------------------------------------------
                        } else if (ntohs(peahdr->arp_op) == 2) {  // REPLY (OP = 16 bits)
                        //---------------------------------------------------------------------
                            // Parse MAC address and send packet with new ethernet header
                            cout << "ARP reply received" << endl;
                            // dest ip addr = packet
                            // send ARP request
                            packetStorage* packet;
                            vector<uint8_t> v;
                            // get ipv4 addr of source, used as dest in sending packets
                            v.push_back(peahdr->arp_spa[0]);  
                            v.push_back(peahdr->arp_spa[1]);
                            v.push_back(peahdr->arp_spa[2]);
                            v.push_back(peahdr->arp_spa[3]);

                            cout << "       dest network address: " ; //<< dipv4 <<endl;
                            printf("%i.%i.%i.%i\n",(unsigned int)v[0],
                                                    (unsigned int)v[1],
                                                    (unsigned int)v[2],
                                                    (unsigned int)v[3]);

                            // Repeat until all packets for source addr are sent to it.
                            while (packets[v].size() > 0) {  // get packet from map (if any)
                                packet = packets[v].back();
                                if (packet == NULL) {
                                    printf("null packet\n");
                                    //packets[v].pop_back(); 
                                    // continue;  // TODO use continue here? (remove null packet first)
                                }
                                printf("        size of packets[v]: %i\n", packets[v].size());
                                printf("        packet: %0x\n", packet->packet);
                                // Get headers from stored packet.
                                struct ether_header* packet_ehdr = (struct ether_header*) (packet->packet);
                                // a->ether_type = htons(0x800);
                                // printf("        packet type: %0x\n", a->protocol);
                                printf("        packet type: %0x\n", ntohs(packet_ehdr->ether_type));
                                printf("        packet size: %i\n", packet->bytes);
                                struct iphdr* packet_iphdr = (struct iphdr*) ((packet->packet)+ETHER_HDR_LEN);
                                int sendPacket = 1;
                                if (packet_iphdr->ttl <= 1) {
                                    cout << "Time out on packet" << endl;  
                                    sendPacket = 0;                
                                }
                                
                                // TODO should you do this after sending? mem addr likely still avail though
                                packets[v].pop_back(); // delete last packet info for dest ipv4 addr  

                                // struct ether_arp* eahdr_reply = (struct ether_arp*) (packet+ETHER_HDR_LEN);
                                //ehdr_reply.ether_dhost = 
                                // ehdr_reply->ether_type = htons(0x0806); //ARP
                                // uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
                                
                                ////////////////////////////////////////
                                // memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                                // memcpy(ehdr_reply->ether_shost, pehdr->ether_dhost, ETH_ALEN);
                                memcpy(packet_ehdr->ether_dhost, peahdr->arp_sha, ETH_ALEN);
                                memcpy(packet_ehdr->ether_shost, peahdr->arp_tha, ETH_ALEN);
                                ///////////////////////////////////////   
                                                             
                                // ehdr_reply->ether_dhost = ; //broadcast
                                // eahdr_reply->arp_op = htons(1);// ARP request
                                // eahdr_reply->arp_hrd = htons(1);// ethernet //peahdr->arp_hrd;
                                // eahdr_reply->arp_pro = htons(0x0800);// IP //peahdr->arp_pro;
                                // eahdr_reply->arp_hln = 6;// //peahdr->arp_hln;
                                // eahdr_reply->arp_pln = 4;// //peahdr->arp_pln;

                                // char* t = port2mac[i];
                                // uint8_t macAddress[6] = {
                                //         (uint8_t) t[0],
                                //         (uint8_t) t[1],
                                //         (uint8_t) t[2],
                                //         (uint8_t) t[3],
                                //         (uint8_t) t[4],
                                //         (uint8_t) t[5],
                                //     };

                                // cout << "       Source MAC: ";
                                // printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                                    // (unsigned char) macAddress[0],
                                    // (unsigned char) macAddress[1],
                                    // (unsigned char) macAddress[2],
                                    // (unsigned char) macAddress[3],
                                    // (unsigned char) macAddress[4],
                                    // (unsigned char) macAddress[5]
                                    // );

                                // memcpy(ehdr_reply->ether_shost, macAddress, ETH_ALEN);

                                // struct in_addr* in = (struct in_addr*)piphdr->daddr;
                                // cout << "       : " << in->s_addr << endl;
                                //char* dipv4 = new char(5);
                                //inet_ntop(AF_INET, &(piphdr->daddr), dipv4, 4);
                                //dipv4[4] = '\0';

                                // memcpy(eahdr_reply->arp_sha, macAddress, ETH_ALEN);
                                // memcpy(eahdr_reply->arp_spa, sipv4, 4);
                                // memcpy(eahdr_reply->arp_tha, broadcast, ETH_ALEN);
                                // memcpy(eahdr_reply->arp_tpa, dipv4, 4);

                                // sizeof(*packet)
                                
                                // Don't send the packet if it's supposed to be dead
                                //sendPacket = 1;  // TODO remove this when working
                                if (sendPacket) {
                                    cout << "   Sending packet to dest" << endl;
                                    send(i, packet->packet, packet->bytes, 0);  
                                }
                                // If packet is dead, create and send error message.
                                else {
                                    //8 is 8 bytes of original packet
                                    cout << "Packet discarded, sending ICMP Time Exceeded packet" 
                                        << endl;
                                    //http://www.networksorcery.com/enp/protocol/icmp/msg11.htm#Type
                                    int packet_size = ETHER_HDR_LEN + 2*sizeof(struct iphdr) + 
                                        sizeof(struct ouricmp) + 8;  // bytes size
                                    // icmphdr = 
                                    //     (struct ouricmp*) (buf+ETHER_HDR_LEN+sizeof(struct iphdr));
                                    // tsicmphdr = 
                                    //     (struct ouricmpts*) (buf+ETHER_HDR_LEN+sizeof(struct iphdr));
                                    // Check for ICMP here (within)
                                    // cout << "ICMP packet found" << endl;
                                    // Create ICMP time exceeded packet and send.
                                    uint8_t packetICMP[packet_size];
                                    struct ether_header* ehdr_reply = (struct ether_header*) packetICMP;
                                    //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                                    struct iphdr* iphdr_reply = 
                                        (struct iphdr*) (packetICMP+ETHER_HDR_LEN);
                                    struct ouricmp* icmphdr_reply = 
                                        (struct ouricmp*) (packetICMP+ETHER_HDR_LEN+sizeof(struct iphdr));
                                    icmphdr_reply->type = (uint8_t)htons(11);  //8
                                    icmphdr_reply->code = (uint8_t)0;  //8
                                    // id and sequence fields are unused - set to 0
                                    icmphdr_reply->id = (uint16_t)0;
                                    icmphdr_reply->sequence = (uint16_t)0;
                                    icmphdr_reply->checksum = (uint16_t)0;

                                    //ethernet header
                                    ehdr_reply->ether_type = packet_ehdr->ether_type;
                                    memcpy(ehdr_reply->ether_shost, packet_ehdr->ether_dhost, ETH_ALEN);
                                    memcpy(ehdr_reply->ether_dhost, packet_ehdr->ether_shost, ETH_ALEN);

                                    // TODO -- confirm that copying IP values from original packet is ok
                                    // Maybe needs to be changed depending on error type??
                                    // I changed protocol to icmp from likely tcp
                                    iphdr_reply->ihl = packet_iphdr->ihl;
                                    iphdr_reply->version = packet_iphdr->version;
                                    iphdr_reply->tos = packet_iphdr->tos;
                                    iphdr_reply->tot_len = packet_iphdr->tot_len;
                                    iphdr_reply->id = packet_iphdr->id;
                                    iphdr_reply->frag_off = packet_iphdr->frag_off;
                                    iphdr_reply->ttl = (uint8_t)htons(64);  //ttl is 8 bits, chose 64 value
                                    iphdr_reply->protocol = (uint8_t)1; // ICMP packet_iphdr->protocol;
                                    iphdr_reply->saddr = packet_iphdr->daddr;
                                    iphdr_reply->daddr = packet_iphdr->saddr;
                                    iphdr_reply->check = ip_checksum(iphdr_reply, sizeof(iphdr));
                                    
                                    // TODO Append ip header and first 8 bytes of data to packet
                                    memcpy(icmphdr_reply+sizeof(ouricmp), iphdr_reply, sizeof(struct iphdr));
                                    //TODO: accessing right bytes? Should it be offset less or more?
                                    // TCP header? is it between ip and data?
                                    memcpy(packetICMP + packet_size - 8, 
                                        (packet->packet) + ETHER_HDR_LEN + sizeof(struct iphdr), 
                                        8);

                                    // TODO Calculate ICMP 11 checksum: for icmp header to end of packet
                                    icmphdr_reply->checksum = ip_checksum(icmphdr_reply, 
                                        sizeof(struct ouricmp) + sizeof(struct iphdr) + 8);

                                    send(i, packetICMP, packet_size, 0);
                                }  // endof icmp 11
                            }  // end of while to send matching packets after ARP reply

                        } else {
                            cout << "Other ARP packet type received (Opcode not 1 or 2)" 
                                << endl;
                        }
                        break;
                    }

                    default:
                        cout << "Other packet type found: " <<  
                            ntohs(pehdr->ether_type) << endl;  // 16 bits
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
    // TODO free key/value pairs from all maps
    // delete [] netaddr  // free mem
    free(buffer);
    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}

/**
 * This function calculates the checksum. The count is the number of 16 
 * bit sections.
 */
uint16_t cksum(uint16_t *buf, int count)
{
    uint64_t sum = 0;
    while (count--)
    {
        sum += ntohs(*buf++);
        //sum += *buf++;
        if (sum & 0xFFFF0000)
        {
            /* carry occurred,
            so wrap around */
            sum &= 0xFFFF;
            sum++;
        }
    }

    return (uint16_t)(sum & 0xFFFF);
}

/**
 * This function calculates the ip checksum. Pass in network byte order with the
 * checksum field already zeroed. This handles padding to fit 16 byte multiples.
 * http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
 * Params: pointer to ip header (use network order), number of bytes in ip header (20)
 * Return: ip checksum in network byte order.
 */
uint16_t ip_checksum(void* vdata, size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);  // bitwise not
}
