//
//  Statistics.hpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#ifndef Statistics_hpp
#define Statistics_hpp
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
#include <fstream>

class Statistics {
    
private:
    
    /*  Statistical Parameters    */
    /*  Overhead    */
    long long int _packet_Count;                    //packets captured
    long long int _total_data_Volume;               //sum of all packets captured
    long long int _data_Volume;                     //sum of all packets collected with each sampling technique
    long long int _nr_of_Samples;                   //total number of samples
    long long int _packet_Selected;                 //packets selectd with each sampling technique
    
    /*  Throughput Estimation   */
    
    struct timeval _init_capture_time;
    struct timeval _current_sample_time;
    int64_t _stop;

    //struct timeval _final_capture_time;
    std::vector<int> _t_data_volume;               //volume of data transferred per unit of time

    std::vector<long long int> _throughput_total;               //volume of data transferred per unit of time
    std::vector<long long int> _throughput_sample;               //volume of data transferred per unit of time
    int64_t aux_current_time;
    
    long long int _aux_throughput_total;
    long long int _aux_throughput_sample;
    //long long int _last_sample_sec_total;
    //long long int _last_sample_sec_sample;
    

    
public:
    Statistics();
    ~Statistics();
    
    
    void real_time_throughput(const struct pcap_pkthdr * pkthdr);
    void sample_time_throughput(const struct pcap_pkthdr * pkthdr);
    //void check_sample_time_throughout();
    float get_peak_to_average_ratio(std::vector<long long int> *_throughput);
    double get_pearson_correlation();
    double get_coefficient_of_variation();
    double get_relative_error();
    void teste(const struct pcap_pkthdr * pkthdr);
    
    void increment_packet_Count(const struct pcap_pkthdr * pkthdr);
    void increment_nr_sample();

    long long int get_packet_Count();
    void increment_packet_Selected(const struct pcap_pkthdr * pkthdr);
    long long int get_number_Packets_Selected();
    long long int get_appropriate_sample_size(const double mean, const double std_deviation, const double accuracy);
    double get_standard_deviation();
    double get_mean();
    int64_t get_init_capture_time();
    void print_stats();
    void write_stats();
    
    
    int appropriate_sample_size(double accuracy);
};
#endif /* Statistics_hpp */
