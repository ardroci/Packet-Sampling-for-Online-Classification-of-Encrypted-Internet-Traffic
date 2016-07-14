//
//  Probabilistic_Sampling__Additive.cpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#include "Probabilistic_Sampling__Additive.hpp"

Random_Aditive__Count_Based::Random_Aditive__Count_Based(const string input_file, const string output_file, const bool d) :Sniffer(input_file,output_file, d), _nr_samples(100),_average_sampling_rate(5){
    puts("Random_Aditive__Count_Based - default constructor");
    geometric_distribution_random_number_generation(_nr_samples, _average_sampling_rate);
    _next_sample = _sampling_time.front();
    _sampling_time.erase(_sampling_time.begin());
    Sniffer::start();
}

Random_Aditive__Count_Based::Random_Aditive__Count_Based(const string input_file, const string output_file, const bool d, const int nr_samples, const int average_sampling_rate/* on average each sampling will occur every x packets */):Sniffer(input_file, output_file,d), _nr_samples(nr_samples),_average_sampling_rate(average_sampling_rate){
    puts("Random_Aditive__Count_Based - constructor");
    geometric_distribution_random_number_generation(nr_samples, average_sampling_rate);
    _next_sample = _sampling_time.front();
    _sampling_time.erase(_sampling_time.begin());
    Sniffer::start();
}
Random_Aditive__Count_Based::~Random_Aditive__Count_Based(){
    // The destructor of std::vector will ensure any memory it allocated is freed.
    // As long as the T type of the vector<T> has proper C++ deallocation semantics all will be well.
}
void Random_Aditive__Count_Based::geometric_distribution_random_number_generation(const int nr_samples, const int average_sampling_rate /* on average each sampling will occur every x packets */){
    
    std::random_device rd;                                // Uses RDRND or /dev/urandom
    std::mt19937 gen(rd());                               // A Mersenne Twister pseudo-random generator of 32-bit numbers with a state size of 19937 bits.
    
    /*
     This distribution produces positive random integers where each value represents the number of unsuccessful trials before a first success in a sequence of trials, each with a probability of success equal to p.
     */
    std::geometric_distribution<int> distribution (1.0/_average_sampling_rate);
    //_sampling_time = new int [_nr_samples];
    int number = 0;
    long long int sum = statistics->get_packet_Count() ;
    for (int i=0; i<_nr_samples; ++i) {
        number = distribution(gen);
        if(number == 0){ //if number is 0 it means the next packet needs to be selected. because this is a cummulative selection process one increment the variable number.
            ++number;
        }
        _sampling_time.push_back(sum + number);
        sum += number;
        cout << sum << "; "<<endl;
    }
}


void Random_Aditive__Count_Based::when_next_sample_will_occur(){
    if(!_sampling_time.empty()){
        _next_sample = _sampling_time.front();
        _sampling_time.erase(_sampling_time.begin());
        statistics->increment_nr_sample();
    }else{
        geometric_distribution_random_number_generation(_nr_samples, _average_sampling_rate);
        _next_sample = _sampling_time.front();
        _sampling_time.erase(_sampling_time.begin());
        statistics->increment_nr_sample();
    }
}
void Random_Aditive__Count_Based::select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    if(_next_sample == statistics->get_packet_Count()){          //after filling all the buckets
        when_next_sample_will_occur();
        pcap_dump(userData, pkthdr, packet);    // save the packet on the dump file
        statistics->increment_packet_Selected(pkthdr);
    }
}