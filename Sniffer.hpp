/**
 @file Sniffer.hpp
 @Author Ricardo Oliveira
 @date 2016
 */


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



/**
 @brief Sniffer class
 
 more elaborated class description
 
 @todo
 */


class Sniffer {
private:
    Sniffer();
    
public:
    /*  Arguments   */
    //! Search directory for saved capture files
    const string _input_directory;
    //! Saved capture files
    vector<string> _files ;
    //! Output capture file
    const string _output_file;
    //! Verbose
    short int _dissect;
    
    /*  Statistics  */
    //! Olds any statistiscal information from the traffic captured
    Statistics *statistics;
    
    /*  Pcap    */
    pcap_t * _descr;
    pcap_dumper_t * _dumpfile;
    //! Capture device
    char * _dev;
    
    //! Constructor
    Sniffer(const string input_file,const string output_file, const bool verbose);
    //! Constructor
    Sniffer(const pcap_dumper_t * _dumpfile, const pcap_t * _descr, const char * _dev);
    //! Destructor
    ~Sniffer();
    
    //! Get all input files from input directory
    void get_input_files();
    
    //! \return libpcap savefile descriptor
    inline pcap_dumper_t * get_dumpfile(){return _dumpfile;}

    inline pcap_t * get_descr(){return _descr;}
    //! Find the default device on which to capture traffic
    void lookup_for_device();
    //! Open a device for capturing
    void open_device_live_capture();
    //! Open a saved capture file for reading
    void open_device_offline_capture(const string input_file);
    //! Open a file to which to write packets
    void open_save_dump_file(const char *fname);
    //! Packet processing loop
    void packet_processing ();
    //! Choose whether to write or discard a packet to a capture file
    virtual void select_packet(u_char *packetData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    //! Dissect packet
    void dissect_packet( const struct pcap_pkthdr *pkthdr, const u_char *packet);
    //! Print payload data
    inline void printData(const u_int stop, const u_char* data);
    
    virtual void start();
    
    /*  Conversion  */
    //! Conversion from sec to usec
    inline int64_t timeval_to_usec( const struct timeval* tv )
    {
        return( (int64_t)tv->tv_sec  * 1000000 + tv->tv_usec);
    }
};
#endif /* Sniffer_hpp */
