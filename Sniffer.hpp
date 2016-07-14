//
//  Sniffer.hpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#ifndef Sniffer_hpp
#define Sniffer_hpp

#include <stdio.h>
#include <iostream>
#include <sys/time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>  //Provides declarations for ip header
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <random>
#include <stdexcept>//exceptions
#include <list>
#include <utility>
#include <array>
#include <list>
#include <string>

#include <sys/types.h>
#include <dirent.h>




#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>




#include "Exceptions.h"

/*
#include "Packet.h"
#include "Ethernet.h"
#include "IP.h"
#include "TCP.h"
#include "ICMP.h"
#include "UDP.h"
*/

#include "Statistics.hpp"
#include "Strata.hpp"

#include "uthash.h"


using namespace std;
/*
struct Bucket{
    long long int _id;
    struct pcap_pkthdr pkthdr;
    u_char *_packet;
    UT_hash_handle hh;         // makes this structure hashable
    Bucket(const struct pcap_pkthdr *p, const u_char *packet){}
};
static struct Bucket *packets = NULL;
static struct Bucket *strata = NULL;
*/

class Sniffer {
private:
    Sniffer();
    
public:
    /*  Arguments   */
    
    const string _input_directory;
    vector<string> _files ;
    const string _output_file;
    short int _dissect;
    
    /*  Statistics  */
    Statistics *statistics;
    /*  Pcap    */
    
    pcap_t * _descr;
    pcap_dumper_t * _dumpfile;
    char * _dev; //device
    
    Sniffer(const string input_file,const string output_file, const bool d);
    Sniffer(const pcap_dumper_t * _dumpfile, const pcap_t * _descr, const char * _dev);
    ~Sniffer();
    
    void get_input_files();
    
    inline pcap_dumper_t * get_dumpfile(){return _dumpfile;}
    inline pcap_t * get_descr(){return _descr;}
    
    void lookup_for_device();                                                                                   // grab a device to peak into...
    void open_device_live_capture();
    void open_device_offline_capture(const string input_file);
    void open_save_dump_file(const char *fname);                                                                // open the dump file
    void packet_processing ();                                                                                  //int cnt, pcap_handler callback, u_char *packet);
    //void packetHandler(u_char *packetData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
    
    virtual void select_packet(u_char *packetData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    void dissect_packet( const struct pcap_pkthdr *pkthdr, const u_char *packet);
    inline void printData(const u_int stop, const u_char* data);
    virtual void start();
    
    
    /*  Hash Table  */
    /*
    inline void add_Packet_Hash_Table( long long int _id, const struct pcap_pkthdr * pkthdr,const  u_char* packet) {
        struct Bucket *s;
        HASH_FIND_INT(packets, &_id, s);  // id already in the hash?
        if (s==NULL) {
            //s = (struct Bucket*)malloc(sizeof(struct Bucket));
            s = new Bucket(pkthdr, packet);
            bpf_u_int32 length = pkthdr->len;
            s->_packet = new u_char[length];
            
            s->pkthdr.caplen=pkthdr->caplen;
            s->pkthdr.len=pkthdr->len;
            s->pkthdr.ts=pkthdr->ts;;
            memcpy(s->_packet, packet, length);
            s->_packet[length]='\0';
            s->_id = _id;
            HASH_ADD_INT(packets, _id, s );  // id: name of key field
            cout << "ADD TO HASH TABLE " << pkthdr->len << endl;
        }
    }
    inline struct Bucket *find_Packet_Hash_Table(long long int _id) {
        struct Bucket *s;
        HASH_FIND_INT( packets, &_id, s );  // s: output pointer
        return s;
    }
    
    inline void delete_Packet_Hash_Table(struct Bucket *packet) {
        HASH_DEL( packets, packet);  // packet: pointer to deletee
        free(packet);
    }
    
    inline void delete_all_from_Hash_Table() {
        struct Bucket *current_packet, *tmp;
        HASH_ITER(hh, packets, current_packet, tmp) {
            HASH_DEL(packets,current_packet);  // delete it (packets advances to next)
            free(current_packet);            // free it
        }
    }
    inline void print_Hash_Table() {
        struct Bucket *s;
        for(s=packets; s != NULL; s=(struct Bucket*)(s->hh.next)) {
            printf("\n**************************Packet**************************\n");
            printf("\t %lli, %d bytes, %s",s->_id,s->pkthdr.len,ctime((const time_t*)&(s->pkthdr).ts.tv_sec));
            printf("**********************************************************\n");
        }
    }
    inline double get_reference_parameter() {
        struct Bucket *s;
        int size_Hash_table = size_Hash_Table();
        int sum_packet_length = 0;
        for(s=packets; s != NULL; s=(struct Bucket*)(s->hh.next)) {
            sum_packet_length += s->pkthdr.len;
            //cout << "sum_packet_length " << sum_packet_length << endl;

        }
        return ((double)sum_packet_length / (double)size_Hash_table);
    }
    inline int size_Hash_Table() {
        int size = 0;
        struct Bucket *s;
        for(s=packets; s != NULL; s=(struct Bucket*)(s->hh.next)) {
            ++size;
        }
        return size;
    }
    inline double reference_Parameter_Hash_Table() {
        double reference_Parameter = 0;
        int size = 0;
        struct Bucket *s;
        for(s=packets; s != NULL; s=(struct Bucket*)(s->hh.next)) {
            reference_Parameter += s->pkthdr.len;
            ++size;
        }
        return (reference_Parameter/size);
    }
*/
    /*  Conversion  */
    
    inline int64_t timeval_to_usec( const struct timeval* tv ){
        return( (int64_t)tv->tv_sec  * 1000000 + tv->tv_usec);
    }
    
};
#endif /* Sniffer_hpp */
