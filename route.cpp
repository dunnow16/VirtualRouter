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
 * Part 3:
 * 
 * compile: g++ route.cpp -o r (from outside of mininet, then send r)
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

struct packetStorage {
    char* packet;
    int bytes;
    uint32_t daddr;
};

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

// struct ifaddrs {
//     struct ifaddrs *  ifa_next;
//     char *            ifa_name;
//     u_int             ifa_flags;
//     struct sockaddr * ifa_addr;
//     struct sockaddr * ifa_netmask;
//     struct sockaddr * ifa_dstaddr;
//     void *            ifa_data;
// };
//   struct sockaddr {
//         ushort  sa_family;
//         char    sa_data[14];
// };
    //have the list, loop over the list
    for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {
        printf("*\nInterface: %s\n",tmp->ifa_name);
        printf("ifa_addr: %0x\n", tmp->ifa_addr->sa_data);
        printf("ifa_netmask: %0x\n", tmp->ifa_netmask->sa_data);
    }
    for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next) {
        //Check if this is a packet address, there will be one per
        //interface.  There are IPv4 and IPv6 as well, but we don't care
        //about those for the purpose of enumerating interfaces. We can
        //use the AF_INET addresses in this list for example to get a list
        //of our own IP addresses
        if(tmp->ifa_addr->sa_family == AF_PACKET) {
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

        else if(tmp->ifa_addr->sa_family == AF_INET) {
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
                for (int k = 2; k <= 5; k++) {
                    mac[k-2] = tmp->ifa_addr->sa_data[k];
                }

                    // char* mac = new char[5];
                    // string mc(&(tmp->ifa_addr->sa_data[2]), 4);

                    // mac[4] = '\0';
                    // for (int k = 2; k <= 5; k++) {
                    //     mac[k-2] = tmp->ifa_addr->sa_data[k];
                    // }

                    // for (int k = 0; k <= 15; k++) {
                    // printf("%i ", tmp->ifa_addr->sa_data[k]);
                    // }
                    //cout << endl;
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
                char chase[14];
                // string ma(&(chase[0]), 4);
                
                strcpy(chase, tmp->ifa_addr->sa_data);
                // cout << "chase: " << chase << endl;
                // cout << "addr: " << tmp->ifa_addr->sa_data << endl;
                string ma(&(tmp->ifa_addr->sa_data[2]),4);
                //update name2ip
                char* t = new char[8];  // char(8) assigns 1 char value 8
                strcpy(t, tmp->ifa_name);
                t[7] = '\0';
                string s(t);

                string sip = ma;
                // cout << "value: " << sip << endl;
                // name2port.insert(pair<char*, int>(t, packet_socket));
                //name2ip.insert(pair<string, string>(s, sip));
                name2ip[s] = mac;

                //if(!strncmp(tmp->ifa_name,"r1-eth0",7 ) ) {
                    // cout << "name2ip key: " << s << " value: " << name2ip[s] << endl;
                //}
                    printf("%i.%i.%i.%i\n",
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
    // TODO might just store an array of length and compare all those
    // lengths to find a match
    // Parse table and store mapping.
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
                printf("--------\nGot a %d byte packet\n", bytes_n);

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
                    switch (ntohs(pehdr->ether_type)) {  // endian conversion (16 bits)
                    case ETHERTYPE_IP:  
                    {
                        cout << "IPv4 packet found" << endl;  
                        piphdr = (struct iphdr*) (buf+ETHER_HDR_LEN);
                        printf("ip protocol: %u\n", piphdr->protocol);
                        // FILE *fptr;
                        // fptr = fopen(fileName, "rb");
                        // if (fptr == NULL)
                        // {
                        //     printf("Cannot open file \n");
                        // data[0] = '\0';
                        //     exit(0);
                        // }
                        // char* pchar = (char *) &(piphdr->saddr);
                        // for (int k = 0; k < 7; k++) cout << pchar[k];

                        // uint32_t t = 0;
                        // for (int k = 0; k < 7; k++) t += port2mac[i][k] * pow(256, k);
                        // char pchar[7] = "";

                        //itoa(piphdr->saddr,pchar,7);
                        // sprintf(pchar, "%d", piphdr->saddr);

                        //suint32_t:%02x:%02x:%02x:%02x:%02x\n",piphdr->saddr);
                        //suint32_t:%02x:%02x:%02x:%02x:%02x\n",piphdr->saddr);
                        //iuint32_tac[i] );
                        // uint32_t
                        //  std::string s = std::to_string(piphdr-stringstream strs;
                        // strs << piphdr->saddr;
                        // string temp_str = strs.str();
                        // const char* pchar = temp_str.c_str();>saddr);
                        //             char const *pchar = s.c_str();  //use char const* as target type
                        
                        // if (!strncmp(port2mac[i], (const char*) pehdr->ether_dhost, 6)) {
                        
                        //if (t == pehdr->ether_dhost) {
                            // cout << "identical" << endl;
                            // cout << port2mac[i] << endl << (const char*) pehdr->ether_dhost << endl;
                        // } else {
                            // char network[200];
                            // char ipaddress[200];
                            // char interface[200];
                            
                            // // Read the first row of the table.
                            // // fscanf(file_pointer, "%s.%s.%s.%s/%s %s %s\n", blah);                            
                            // fscanf(file_pointer, "%s %s %s",
                            // network,
                            // ipaddress,
                            // interface
                            // );
                            // cout << network << " " << ipaddress << " " << interface << endl;

                            // // Parse the table.
                            // int* net = new int(5);
                            // int index = 0;
                            // int counter = 0;
                            // int trailing = 0;
                            // char temp[4];
                            // while (index < 6) {
                            //     if (network[counter] == '.' || network[counter] == '/'  ) {
                            //         for (int k = trailing; k < counter; k++) {
                            //             temp[k-trailing] = network[k];                                        
                            //         }
                            //         temp[counter-trailing] = '\0';
                            //         cout << temp << endl;


                            //         counter++;
                            //         trailing = counter;

                            //         net[index]= (char) atoi(temp);
                            //         //net[inuint32_t] =  atoi("255");
                            //         //cout <uint32_ttoi("255");
                            //         index++;
                            //     } else {
                            //         counter++;
                            //     }

                            // }
                            // //net[5] = '\0';
                            // //net[0] = 255;
                            // cout << "net: " << net[0] << endl;
                            // cout << "net: " << net[1] << endl;
                            // cout << "net: " << net[2] << endl;
                            // cout << "net: " << net[3] << endl;
                            // cout << "net: " << net[4] << endl;

                            // //compare network to piphdr->daddr
                            // uint32_t tt = 0;
                            // int prefix = net[4]/8;
                            // for (int k = 0; k < prefix; k++) tt += net[k] * pow(256, 3-k);

                            // long val = (long) (((int) piphdr->daddr / pow(256,4-prefix)) * pow(256,4-prefix));
                            // cout << "dest val: " << val << endl;
                            // cout << "file network val: " << tt << endl;
                            
                            // cout << "char*: " << pchar << endl << "uint32: " << pehdr->ether_dhost << endl <<
                            // "port2mac at " << i << ": " << port2mac[i] << endl << 
                            // "port2mac int at " << i << ": " << t << endl;
                        switch (piphdr->protocol)  // part of IP
                        {
                        case 0x06:  // TCP (all of part 2 packet forwarding?)
                        {
                            cout << "   TCP packet Received" << endl;
                            // Forward packet to dest:
                            // Look up dest addr from table to get ip 
                            // addr of next hop. Prefixes all 16 or 24 bits. 
                            // Max of one match possible.
                            uint32_t daddr = (uint32_t)ntohl(piphdr->daddr);  // 32 bits
                            uint32_t hopaddr, hopaddrnet;
                            int portNum;
                            std::map<uint32_t, uint32_t>::iterator it;
                            printf("    Dest ip addr: %#X\n", daddr);
                            //struct in_addr struct_dest;
                            //struct_dest.sin_addr.s_addr =  piphdr->daddr;
                            printf("    or %s\n", inet_ntoa(*(struct in_addr*)&(piphdr->daddr)));
                            if ((it=net2hop.find(daddr & 0xffff0000)) != net2hop.end() ) {  // 16 bit netlength
                                hopaddr = net2hop[daddr & 0xffff0000];
                                char* interface = net2if[daddr & 0xffff0000];
                                cout << "   interface: " << interface << endl;
                                string s(interface);
                                portNum = name2port[s];
                                cout << "   port: " << portNum << endl;
                                cout << "   Hop IP addr found in table." << endl;
                                hopaddrnet = (uint32_t)htonl(hopaddr);
                                printf("    hop addr: %s\n", inet_ntoa(*(struct in_addr*)&hopaddrnet));
                            } else if ((it=net2hop.find(daddr & 0xffffff00)) != net2hop.end() ) {  // 24 bit netlength
                                hopaddr = net2hop[daddr & 0xffffff00];
                                char* interface = net2if[daddr & 0xffffff00];
                                cout << "   interface: " << interface << endl;
                                string s(interface);
                                portNum = name2port[s];
                                cout << "   port: " << portNum << endl;
                                cout << "   Hop IP addr found in table." << endl;
                                hopaddrnet = (uint32_t)htonl(hopaddr);
                                printf("    hop addr: %s\n", inet_ntoa(*(struct in_addr*)&hopaddrnet));
                            } else {
                                // TODO NO MATCH: PART 3 ACTION HERE
                                cout << "   No match found in table." << endl;
                                break;
                            }
 

                            // TODO Use ARP to get dest MAC addr: (request hop addr for its MAC addr)
							
                            if (hopaddr == 0)  // no hop for this network
							{

							} else {

							}
                            cout << "       Using ARP to get MAC addr for hop" << endl;
                                
    // map <uint32_t, uint32_t> net2hop;  // hop ip addr, "-" value if none
    // map <uint32_t, char*> net2if;   // interface
    // map <uint32_t, uint8_t> net2length;  // net bits

                        // send ARP request
                            uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
                            struct ether_header* ehdr_reply = (struct ether_header*) packet;
                            //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                            struct ether_arp* eahdr_reply = (struct ether_arp*) (packet+ETHER_HDR_LEN);
                            //ehdr_reply.ether_dhost = 
//   uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
//   uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
//   uint16_t ether_type;		        /* packet type ID field	*/
                            ehdr_reply->ether_type = htons(0x0806); //ARP
                            // memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                            uint8_t broadcast[6] = {0,0,0,0,0,0};
                            memcpy(ehdr_reply->ether_dhost, broadcast, ETH_ALEN);
                            // ehdr_reply->ether_dhost = ; //broadcast

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

                            eahdr_reply->arp_op = htons(1);// ARP request
                            eahdr_reply->arp_hrd = htons(1);// ethernet //peahdr->arp_hrd;
                            eahdr_reply->arp_pro = htons(0x0800);// IP //peahdr->arp_pro;
                            eahdr_reply->arp_hln = htons(6);// //peahdr->arp_hln;
                            eahdr_reply->arp_pln = htons(4);// //peahdr->arp_pln;
                            //struct ether_arp

     // uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	// uint8_t arp_spa[4];		/* sender protocol address */
	// uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
	// uint8_t arp_tpa[4];		/* target protocol address */

							char* t = port2mac[portNum];
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

                            // ether_dhost
                            // ether_shost
                            // sizeof(*packet)
                            send(portNum, packet, sizeof(struct ether_header) + 
                                sizeof(struct ether_arp), 0);
							
								
							







                            break;
                        }

                        case 0x01:  // ICMP
                        {  
                            cout << "   ICMP request made" << endl;
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
                            } else {
                                // TODO NO MATCH: PART 3 ACTION HERE
                                cout << "   No match found in table." << endl;
                                break;
                            }
                            printf("    router ip %i.%i.%i.%i\n",
                            (unsigned char) sipv4[0],
                            (unsigned char) sipv4[1],
                            (unsigned char) sipv4[2],
                            (unsigned char) sipv4[3]
                            );
                            // TODO Use ARP to get dest MAC addr: (request hop addr for its MAC addr)
							
                            if (hopaddr == 0)  // no hop for this network
							{

							} else {

							}
                            cout << "       Using ARP to get MAC addr for hop" << endl;
                                
    // map <uint32_t, uint32_t> net2hop;  // hop ip addr, "-" value if none
    // map <uint32_t, char*> net2if;   // interface
    // map <uint32_t, uint8_t> net2length;  // net bits

// struct iphdr {
// #if defined(__LITTLE_ENDIAN_BITFIELD)
// 	__u8	ihl:4,
// 		version:4;
// #elif defined (__BIG_ENDIAN_BITFIELD)
// 	__u8	version:4,
//   		ihl:4;
// #else
// #error	"Please fix <asm/byteorder.h>"
// #endif
// 	__u8	tos;
// 	__u16	tot_len;
// 	__u16	id;
// 	__u16	frag_off;
// 	__u8	ttl;
// 	__u8	protocol;
// 	__u16	check;
// 	__u32	saddr;
// 	__u32	daddr;
// 	/*The options start here. */
// };
                        // send ARP request
                            uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
                            struct ether_header* ehdr_reply = (struct ether_header*) packet;
                            //struct aphdr* eahdr_reply = (struct aphdr*) (packet+ETHER_HDR_LEN);
                            struct ether_arp* eahdr_reply = (struct ether_arp*) (packet+ETHER_HDR_LEN);
                            //ehdr_reply.ether_dhost = 
//   uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
//   uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
//   uint16_t ether_type;		        /* packet type ID field	*/
                            ehdr_reply->ether_type = htons(0x0806); //ARP
                            // memcpy(ehdr_reply->ether_dhost, pehdr->ether_shost, ETH_ALEN);
                            uint8_t broadcast[6] = {0,0,0,0,0,0};
                            memcpy(ehdr_reply->ether_dhost, broadcast, ETH_ALEN);
                            // ehdr_reply->ether_dhost = ; //broadcast

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

                            eahdr_reply->arp_op = htons(1);// ARP request
                            eahdr_reply->arp_hrd = htons(1);// ethernet //peahdr->arp_hrd;
                            eahdr_reply->arp_pro = htons(0x0800);// IP //peahdr->arp_pro;
                            eahdr_reply->arp_hln = 6;// //peahdr->arp_hln;
                            eahdr_reply->arp_pln = 4;// //peahdr->arp_pln;
                            //struct ether_arp

     // uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	// uint8_t arp_spa[4];		/* sender protocol address */
	// uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
	// uint8_t arp_tpa[4];		/* target protocol address */

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

//http://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/i/inet_ntop.html

                            char* str = inet_ntoa(*(struct in_addr*)&(piphdr->daddr));

                            char * pch;
                            char* dipv4 = new char(4);
                            int index = 0;
                            // printf ("Splitting string \"%s\" into tokens:\n",str);
                            pch = strtok (str,".");
                            dipv4[index++] = atoi(pch);
                            for (int k = 1; k < 4; k++) {
                                // printf("%s\n",pch);
                                pch = strtok (NULL, ".");
                                dipv4[index++] = atoi(pch);
                            }

                            // struct in_addr* in = (struct in_addr*)piphdr->daddr;
                            // cout << "       : " << in->s_addr << endl;
                            //char* dipv4 = new char(5);
                            //inet_ntop(AF_INET, &(piphdr->daddr), dipv4, 4);
                            //dipv4[4] = '\0';
                            cout << "       dest network address: " ;//<< dipv4 <<endl;
                             printf("%i.%i.%i.%i\n",(unsigned int)dipv4[0],
                                                     (unsigned int)dipv4[1],
                                                     (unsigned int)dipv4[2],
                                                     (unsigned int)dipv4[3]);

                            memcpy(eahdr_reply->arp_sha, macAddress, ETH_ALEN);
                            memcpy(eahdr_reply->arp_spa, sipv4, 4);
                            memcpy(eahdr_reply->arp_tha, broadcast, ETH_ALEN);
                            memcpy(eahdr_reply->arp_tpa, dipv4, 4);

                            // ether_dhost
                            // ether_shost
                            // sizeof(*packet)
                            send(portNum, packet, sizeof(struct ether_header) + 
                                sizeof(struct ether_arp), 0);

                        //-------------
                        //TODO: figure out how to respond to icmp requests sent to router (Part 1)!!!!!!!
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
                            // //ip header                        
                            // // #if __BYTE_ORDER == __LITTLE_ENDIAN
                            // //     unsigned int ihl:4;
                            // //     unsigned int version:4;
                            // // #elif __BYTE_ORDER == __BIG_ENDIAN
                            // //     unsigned int version:4;
                            // //     unsigned int ihl:4;
                            // // #else
                            // // # error	"Please fix <bits/endian.h>"
                            // // #endif
                            // //     uint8_t tos;
                            // //     uint16_t tot_len;
                            // //     uint16_t id;
                            // //     uint16_t frag_off;
                            // //     uint8_t ttl;
                            // //     uint8_t protocol;
                            // //     uint16_t check;
                            // //     uint32_t saddr;
                            // //     uint32_t daddr;
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
                            // //icmp header
                            // // u_int8_t type;
                            // // u_int8_t code;
                            // // u_int16_t checksum;
                            // // u_int16_t id;
                            // // u_int16_t sequence;
                            // send(i, packet, bytes_n, 0);
                            break;
                        }
                        }
                        break;
                    } //endof ethertypeip
                    
                    case ETHERTYPE_ARP:  // ARP
                    {
                        cout << "ARP packet found" << endl;
                        // Retrieve arp header: 
                        peahdr = (struct ether_arp*) (buf + ETHER_HDR_LEN);
                        // Check if request:
                        cout << "op: " << ntohs(peahdr->arp_op) << endl;  // 16-bits
                        if (ntohs(peahdr->arp_op) == 1) {
                            cout << "ARP request made" << endl;
                            // Create packet to send back
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
                            // uint8_t fakeMac[6] = {1,1,1,1,1,1};
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

                            // ether_dhost
                            // ether_shost
                            // sizeof(*packet)
                            send(i, packet, sizeof(struct ether_header) + 
                                sizeof(struct ether_arp), 0);
                        } else if (ntohs(peahdr->arp_op) == 2) {  // reply (16 bits)
                            // TODO Parse MAC address and send packet with new ethernet header
                            cout << "ARP reply received" << endl;





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
