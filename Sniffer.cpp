//
//  Sniffer.cpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#include "Sniffer.hpp"

Sniffer::Sniffer(const string input_file,const string output_file, const bool d):  _input_directory(input_file), _output_file(output_file){
    get_input_files();
    statistics = new Statistics();
    _dissect=d;
    
    puts("\n\nSniffer - default constructor");
}
Sniffer::Sniffer(const pcap_dumper_t * _dumpfile, const pcap_t * _descr, const char * _dev){
    get_input_files();
    statistics = new Statistics();
    
}
Sniffer::~Sniffer(){
    if (_dumpfile!=NULL) {
        pcap_dump_flush(_dumpfile);
        pcap_dump_close(_dumpfile);
        _dumpfile=NULL;
    }
    if (_descr!=NULL) {
        pcap_close(_descr);
        _descr=NULL;
    }
    if (statistics!=NULL) {
        delete statistics;
    }
}

void Sniffer::start(){
    bool done = false;
    if (_files.empty()) {
        open_device_live_capture();

        open_save_dump_file(_output_file.c_str());
        done = false;
        while(!done){
            try{
                packet_processing();
            }catch (No_More_Packets2 e1){
                done = true;
            }catch (Timeout_Expired2 e2){
                cout << "Timeout: " << e2.what() << "\n";
                done = true;
            }catch (Packet_Reading_Error2 e3){
                cout << "Failed: " << e3.what() << "\n";
                done = true;
            }
        }
    }else{
        for (int i = 0; i<_files.size(); ++i) {
            printf(" %d * %s\n", i+1, _files.at(i).c_str());
            open_device_offline_capture(_files.at(i));
            open_save_dump_file(_output_file.c_str());
            done = false;
            while(!done){
                try{
                    packet_processing();
                }catch (No_More_Packets2 e1){
                    done = true;
                }catch (Timeout_Expired2 e2){
                    cout << "Timeout: " << e2.what() << "\n";
                    done = true;
                }catch (Packet_Reading_Error2 e3){
                    cout << "Failed: " << e3.what() << "\n";
                    done = true;
                }
            }
        }
    }
    //statistics->check_sample_time_throughout();
    statistics->print_stats();
}
void Sniffer::lookup_for_device(){
    char * errbuf = NULL;
    //find the default device on which to capture
    char * dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        const std::string error_string = errbuf;
        throw runtime_error("Error: pcap_open_device_live_capture() failed:" + error_string);
    }
    _dev = dev;

    cout << "Device: " << _dev << endl;

}

void Sniffer::open_device_live_capture(){
    /*
     pcap_open_live() is used to obtain a packet capture handle to look at packets on the network. device is a string that specifies the network device to open; on Linux systems with 2.2 or later kernels, a device argument of "any" or NULL can be used to capture packets from all interfaces.
     
     
     open the device for Sniffering.
     pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms, char *ebuf)
     snaplen - maximum size of packets to capture in bytes
     promisc - set card in promiscuous mode? that causes the controller to pass all traffic it receives to the central processing unit (CPU) rather than passing only the frames that the controller is intended to receive
     to_ms   - time to wait for packets in miliseconds before read times out
     errbuf  - if something happens, place error string here
     Note if you change "prmisc" param to anything other than zero, you will get all packets your device sees, whether they are intendeed for you or
     not!! Be sure you know the rules of the network you are running on before you set your card in promiscuous mode!!
     */
    char * errbuf = NULL;
    lookup_for_device();

    pcap_t * descr = pcap_open_live(_dev, 1600, 1, 10000, errbuf);

    if (descr == nullptr) {
        const string error_string = errbuf;
        throw runtime_error("Error: pcap_open_device_live_capture() failed:" + error_string);
    }
    _descr = descr;
    //return descr;
}
void Sniffer::open_device_offline_capture(const string input_file){
    
    cout << "Offline capture" << endl;
    char * errbuf = NULL;
    pcap_t * descr = pcap_open_offline(input_file.c_str(), errbuf);
    
    if (descr == nullptr) {
        const string error_string = errbuf;
        throw runtime_error("Error: pcap_offline_capture() failed:" + error_string);
    }
    _descr = descr;
    //return descr;
}
void Sniffer::open_save_dump_file(const char *fname){
    /* Open the dump save file
     pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
     pcap_dump_open() is called to open a ''savefile'' for writing. fname specifies the name of the file to open. The file will have the same format as those used by tcpdump(1) and tcpslice(1). The name "-" in a synonym for stdout.
     Returns
     A pointer to a pcap_dumper_t structure to use in subsequent pcap_dump() and pcap_dump_close() calls is returned on success. NULL is returned on failure. If NULL is returned, pcap_geterr(p) can be used to get the error text.
     */
    char * errbuf = NULL;
    pcap_dumper_t * dumpfile = pcap_dump_open(_descr, fname);
    if (dumpfile == NULL) {
        const string error_string = errbuf;
        throw runtime_error("Error: pcap_open_save_dump_file() failed:" + error_string);
    }
    _dumpfile = dumpfile;
    //return dumpfile;
}
void Sniffer::select_packet(u_char *packetData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    pcap_dump(packetData, pkthdr, packet);
    statistics->increment_packet_Selected(pkthdr);
}

void Sniffer::packet_processing (){//int cnt, pcap_handler callback, u_char *packet){
    /*
     start packet processing loop
     int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *packet);
     pcap_loop() processes packets from a live capture or ``savefile'' until cnt packets are processed, the end of the ``savefile'' is reached when reading from a ``savefile'', pcap_breakloop() is called, or an error occurs. It does not return when live read timeouts occur. A value of -1 or 0 for cnt is equivalent to infinity, so that packets are processed until another ending condition occurs.
     Returns
     pcap_loop() returns 0 if cnt is exhausted, -1 if an error occurs, or -2 if the loop terminated due to a call to pcap_breakloop() before any packets were processed. It does not return when live read timeouts occur; instead, it attempts to read more packets.
     */
    /*if (pcap_loop(_descr, cnt, callback, packet) < 0) {
     throw runtime_error("Error: pcap_packet_processing () failed:");
     }
     printf("\ndone...\n\n**************************\nTotal Packets %d\nTCP Packets %d\nUDP Packets %d \nICMP Packets %d\n\
     **************************\n\n",_packetCount, _tcpPacketCount,_udpPacketCount,_icmpPacketCount);
     pcap_dump_close(_dumpfile);
     */
    
    const struct pcap_pkthdr *pkthdr;   // = new struct pcap_pkthdr;
    const u_char *packet;               // = new u_char;
    
    int iRes;
    
    iRes = pcap_next_ex(_descr, const_cast<struct pcap_pkthdr **>(&pkthdr), &packet);
    switch (iRes){
        case 0:
            printf("Timeout_Expired");
            throw Timeout_Expired2();
        case -1:{
            std::string error_msg = pcap_geterr(_descr);
            printf("Packet_Reading_Error");
            throw Packet_Reading_Error2(error_msg);
        }
        case -2:
            printf("No_More_Packets");
            throw No_More_Packets2();
    }
    statistics->increment_packet_Count(pkthdr);
    select_packet((u_char *) _dumpfile,pkthdr, packet);
    //statistics->teste(pkthdr);
    if (_dissect) {
        dissect_packet(pkthdr, packet);
    }
    
}

void Sniffer::dissect_packet( const struct pcap_pkthdr *pkthdr, const u_char *packet){
    const struct ether_header* ethernetHeader;
    ethernetHeader = (struct ether_header*)packet;
    // Do a couple of checks to see what packet type we have..
    switch (ntohs (ethernetHeader->ether_type)) {
        case ETHERTYPE_PUP:
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            break;
        case ETHERTYPE_IP:
            const struct ip* ipHeader;
            ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
            if ((ipHeader->ip_p) == IPPROTO_TCP){
                //tcp_packet(packet);
                //new TCP(pkthdr, packet, statistics->get_packet_Count());
            }else if ((ipHeader->ip_p) == IPPROTO_UDP){
                //udp_packet(packet);
                //new UDP(pkthdr, packet,statistics->get_packet_Count());
                //return new UDPPacket(pkt_header, pkt_data);
            }else if ((ipHeader->ip_p) == IPPROTO_ICMP){
                //new ICMP(pkthdr, packet, statistics->get_packet_Count());
            }else{
                printf("IPPacket");
                //return new IPPacket(pkt_header, pkt_data);
            }
            break;
        case ETHERTYPE_ARP:
            puts("ARP");
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            break;
        case ETHERTYPE_REVARP:
            puts("REVERSE ARP");
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            break;
        case ETHERTYPE_VLAN:
            puts("VLAN");
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            break;
        case ETHERTYPE_IPV6:
            puts("IPV6");
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            const struct ip6_hdr * ipv6Header;
            ipv6Header =(struct ip6_hdr*)(packet + sizeof(struct ether_header));
            break;
        case ETHERTYPE_PAE:
            puts("PAE");
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            break;
        case ETHERTYPE_RSN_PREAUTH:
            puts("AUTH");
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            break;
        case ETHERTYPE_LOOPBACK:
            puts("LOOPBACK");
            printf("\tEthernet type %x not IP\n", ntohs(ethernetHeader->ether_type));
            break;
        default:
            
            break;
    }
    
}
inline void Sniffer::printData(const u_int stop, const u_char* data){
    for (u_int i = 0; i < stop; i++) {
        printf("%.2x ",data[i]);
    }
    printf("\n");
}

void Sniffer::get_input_files(){
    if (_input_directory.empty()) {
        return;
    }
    /*
     DIR *dp;
    struct dirent *ep;
    string s = ".pcap";
    string d;
    string h= "./";
    string f= h +_input_directory;
    dp = opendir (f.c_str());
    if (dp != NULL){
        while ((ep = readdir (dp))){
            d = ep->d_name;
            if (d.find(s) != std::string::npos) {
                _files.push_back(_input_directory + d);
            }
        }
        (void) closedir (dp);
    }
    else
        perror ("Couldn't open the directory");
    */
    _files.push_back(_input_directory );//+ "sigcomm08_eth_2008-08-17_13-43_23_2008-08-17_13-43_41.pcap");
    
    
}
/*  Class statics need to be visible to the linker by defining them in the cpp as follow    */
//long long int  Sniffer::_packet_Count = 0;



