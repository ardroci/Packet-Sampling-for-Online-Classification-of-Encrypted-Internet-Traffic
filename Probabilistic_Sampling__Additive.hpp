//
//  Probabilistic_Sampling__Additive.hpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#ifndef Probabilistic_Sampling__Additive_hpp
#define Probabilistic_Sampling__Additive_hpp

#include "Sniffer.hpp"


class Random_Aditive__Count_Based : public Sniffer{
private:
    vector<long long int> _sampling_time;
    long long int _next_sample;
    int _nr_samples;
    int _average_sampling_rate;
public:
    Random_Aditive__Count_Based(const string input_file, const string output_file, const bool d);
    Random_Aditive__Count_Based(const string input_file, const string output_file, const bool d, const int nr_samples, const int average_sampling_rate);
    ~Random_Aditive__Count_Based();// destructor
    
    void when_next_sample_will_occur();//how many unsucessful trials before frist success in a sequence of trials
    
    void geometric_distribution_random_number_generation(const int nr_samples, const int average_sampling_rate);
    void select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
#endif /* Probabilistic_Sampling__Additive_hpp */
