//
//  Systematic_Sampling__Count_Based.hpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#ifndef Systematic_Sampling__Count_Based_hpp
#define Systematic_Sampling__Count_Based_hpp

#include "Sniffer.hpp"



class Systematic_Sampling__Count_Based : protected Sniffer{
private:
    int _offset;
    int _interval;
    long long int _start_sample;
    long long int _end_sample;
    long long int _sample_size;

    
    Systematic_Sampling__Count_Based();
public:
    Systematic_Sampling__Count_Based(const string input_file, const string output_file, const bool d, const int sample_size);
    Systematic_Sampling__Count_Based(const string input_file, const string output_file, const bool d, const int interval, const int sample_size);
    ~Systematic_Sampling__Count_Based();// destructor
    void select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
#endif /* Systematic_Sampling__Count_Based_hpp */
