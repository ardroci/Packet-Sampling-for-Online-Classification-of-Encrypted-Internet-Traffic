/**
 @file Systematic_Sampling__Time_Driven.cpp
 @Author Ricardo Oliveira
 @date 2016
 */

#include "Systematic_Sampling__Time_Driven.hpp"
Systematic_Sampling__Time_Driven ::Systematic_Sampling__Time_Driven (const string input_file, const string output_file, const bool d, const long long int sample_size) : Sniffer(input_file, output_file, d), _interval(4*1000000), _sample_size(sample_size*1000000)
{
    puts("Systematic_Sampling - default constructor");
    Sniffer::start();
}

Systematic_Sampling__Time_Driven::Systematic_Sampling__Time_Driven (const string input_file, const string output_file, const bool d, const int64_t interval, const long long int sample_size) : Sniffer(input_file,output_file, d), _interval(interval*1000000), _sample_size(sample_size*1000000)
{
    puts("Systematic_Sampling - constructor");
    Sniffer::start();
}

Systematic_Sampling__Time_Driven ::~Systematic_Sampling__Time_Driven ()
{
}
void Systematic_Sampling__Time_Driven::select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    int64_t time = timeval_to_usec(&pkthdr->ts);
    if(statistics->get_packet_Count() == 1){
        _start_sample = timeval_to_usec(&pkthdr->ts);
        _end_sample = _start_sample + _sample_size;
        statistics->increment_nr_sample();;
    }
    if(time < _start_sample){
        return;
    }
    if(time >= _start_sample && time < _end_sample){
        pcap_dump(userData, pkthdr, packet);
        statistics->increment_packet_Selected(pkthdr);
    }
    else{
        _start_sample =  _end_sample + (_interval );
        _end_sample = _start_sample + (_sample_size);
        statistics->increment_nr_sample();;
    }
}