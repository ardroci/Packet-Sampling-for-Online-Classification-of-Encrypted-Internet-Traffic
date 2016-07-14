//
//  Simple_Random_Sampling.hpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#ifndef Simple_Random_Sampling_hpp
#define Simple_Random_Sampling_hpp


#include "Sniffer.hpp"

class Simple_Random : protected Sniffer{
private:
    vector<long long int> _sampling_time;
    int _sampling_rate;          //sampling rate
    //int _number_of_trials;   //the t distribution parameter (number of trials)
    //double _p_true;          //the p distribution parameter (probability of a trial generating true)
    long long int _nr_samples;
    long long int _next_sample;
    
    
public:
    Simple_Random(const string input_file,const string output_file, const bool d);
    Simple_Random(const string input_file,const string output_file, const bool d, const int sampling_rate, const int nr_samples);
    ~Simple_Random();// destructor
    
    void when_will_next_sample_will_occur();
    void uniform_distribution_random_number_generation(const int sampling_rate);
    virtual void select_packet(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet);
};
#endif /* Simple_Random_Sampling_hpp */
