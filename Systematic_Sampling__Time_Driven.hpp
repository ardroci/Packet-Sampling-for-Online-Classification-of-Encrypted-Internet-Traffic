//
//  Systematic_Sampling__Time_Driven.hpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#ifndef Systematic_Sampling__Time_Driven_hpp
#define Systematic_Sampling__Time_Driven_hpp

#include "Sniffer.hpp"

using namespace std;

class Systematic_Sampling__Time_Driven : protected Sniffer{
private:
    double _offset;
    int64_t _interval;
    int64_t _start_sample;
    int64_t _end_sample;
    int64_t _sample_size;
    
    Systematic_Sampling__Time_Driven ();
public:
    Systematic_Sampling__Time_Driven (const string input_file, const string output_file, const bool d, const long long int sample_size);
    Systematic_Sampling__Time_Driven(const string input_file,const string output_file, const bool d, const int64_t interval, const long long int sample_size);
    ~Systematic_Sampling__Time_Driven ();// destructor
    void select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
#endif /* Systematic_Sampling__Time_Driven_hpp */
