/**
 @file Simple_Random_Sampling.cpp
 @Author Ricardo Oliveira
 @date 2016
 */

#include "Simple_Random_Sampling.hpp"
using namespace std;

Simple_Random::Simple_Random(const string input_file,const string output_file, const bool d) :Sniffer(input_file,output_file, d),_sampling_rate(4), _nr_samples(100)
{
    puts("Simple_Random_Sampling - default constructor");
    uniform_distribution_random_number_generation(_sampling_rate);
    when_will_next_sample_will_occur();
    Sniffer::start();
}
Simple_Random::Simple_Random(const string input_file, const string output_file, const bool d, const int sampling_rate, const int nr_samples):Sniffer(input_file, output_file, d),_sampling_rate(sampling_rate), _nr_samples(nr_samples)
{
    puts("Simple_Random_Sampling - constructor");
    _nr_samples = nr_samples;
    uniform_distribution_random_number_generation(_sampling_rate);
    when_will_next_sample_will_occur();
    Sniffer::start();
}

Simple_Random::~Simple_Random()
{
    // The destructor of std::vector will ensure any memory it allocated is freed.
    // As long as the T type of the vector<T> has proper C++ deallocation semantics all will be well.
}
void Simple_Random::uniform_distribution_random_number_generation(const int sampling_rate){
    
    std::random_device rd;    // Uses RDRND or /dev/urandom
    std::mt19937 gen(rd());   // A Mersenne Twister pseudo-random generator of 32-bit numbers with a state size of 19937 bits.
   
    /*
     Produces random integer values i, uniformly distributed on the closed interval [a, b], that is, distributed according to the discrete probability function:
     P(i|a,b) = 1/(b − a + 1)
     */
    std::uniform_int_distribution<> distribution(0, (2*sampling_rate-2));
    
    int number = 0;
    long long int sum = statistics->get_packet_Count() ;
    for (int i=0; i<_nr_samples; ++i) {
        number = distribution(gen);
        if(number == 0){ //if number is 0 it means the next packet needs to be selected. because this is a cummulative selection process one increment the variable number.
            ++number;
        }
        sum += number;
        _sampling_time.push_back(sum);
    }
    
}
void Simple_Random::when_will_next_sample_will_occur(){
    if (!_sampling_time.empty()) {
        _next_sample = _sampling_time.front();
        _sampling_time.erase(_sampling_time.begin());
    }else{
        uniform_distribution_random_number_generation(_sampling_rate);
        _next_sample = _sampling_time.front();
        _sampling_time.erase(_sampling_time.begin());
    }
}
void Simple_Random::select_packet(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet)
{
    if(statistics->get_packet_Count() == _next_sample){
        pcap_dump(userData, pkthdr, packet);
        statistics->increment_packet_Selected(pkthdr);
        when_will_next_sample_will_occur();
    }
}
