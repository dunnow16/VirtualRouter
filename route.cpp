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
#include <arpa/inet.h>  // htons()
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/select.h> // select()
#include <string>
#include <string.h>  // strcmp (might want to use cpp version)
#include <iostream> 

using namespace std;


int main(){
  int packet_socket;
  fd_set sockets;  // everything interact with gets a fd, starts an empty set?
  FD_ZERO(&sockets);

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
    if(tmp->ifa_addr->sa_family==AF_PACKET) {
      printf("Interface: %s\n",tmp->ifa_name);
      //create a packet socket on interface r?-eth1
      // eth0 to eth3 on table: allow any of these interfaces
      if(!strncmp(&(tmp->ifa_name[3]),"eth0",4)  ||
         !strncmp(&(tmp->ifa_name[3]),"eth1",4)  ||
         !strncmp(&(tmp->ifa_name[3]),"eth2",4)  ||
         !strncmp(&(tmp->ifa_name[3]),"eth3",4) ) {  
        printf("Creating Socket on interface %s\n",tmp->ifa_name);
        //create a packet socket
        //AF_PACKET makes it a packet socket
        //SOCK_RAW makes it so we get the entire packet
        //could also use SOCK_DGRAM to cut off link layer header
        //ETH_P_ALL indicates we want all (upper layer) protocols
        //we could specify just a specific one
        packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
    char buf[2000];  // how much room needed? (1500 data, all headers)
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
                int bytes_n = recvfrom(i, buf, 2000, 0,
                    (struct sockaddr*)&recvaddr, &recvaddrlen);
                //ignore outgoing packets (we can't disable some from being sent
                //by the OS automatically, for example ICMP port unreachable
                //messages, so we will just ignore them here)
                if(recvaddr.sll_pkttype == PACKET_OUTGOING)
                    continue;
                //start processing all others
                printf("Got a %d byte packet on %s\n", bytes_n, );
                // TODO Process the packet and reply to any requests.



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
