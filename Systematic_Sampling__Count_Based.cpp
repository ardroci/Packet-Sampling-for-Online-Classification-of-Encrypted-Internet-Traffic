/**
 @file Systematic_Sampling__Count_Based.cpp
 @Author Ricardo Oliveira
 @date 2016
 */

#include "Systematic_Sampling__Count_Based.hpp"
Systematic_Sampling__Count_Based::Systematic_Sampling__Count_Based(const string input_file,const string output_file, const bool verbose, const int sample_size): Sniffer(input_file, output_file, verbose), _interval(4), _sample_size(sample_size)
{
    puts("Systematic_Sampling - default constructor");
    _sample_size = 1;
    Sniffer::start();
}

Systematic_Sampling__Count_Based::Systematic_Sampling__Count_Based(const string input_file, const string output_file, const bool verbose, const int interval, const int sample_size) : Sniffer(input_file, output_file, verbose), _interval(interval), _sample_size(sample_size)
{
    puts("Systematic_Sampling - constructor");
    Sniffer::start();
}

Systematic_Sampling__Count_Based::~Systematic_Sampling__Count_Based()
{
}
void Systematic_Sampling__Count_Based::select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    long long int _aux_packet_count = statistics->get_packet_Count();
    if(_aux_packet_count % _interval==0){
        _start_sample = statistics->get_packet_Count();
        _end_sample =_start_sample + _sample_size;
        statistics->increment_nr_sample();
    }
    if((_aux_packet_count >= _start_sample) && (_aux_packet_count < _end_sample)){
        pcap_dump(userData, pkthdr, packet);
        //_data_Volume += pkthdr->caplen;         //sum of all packets collected with each sampling technique
        statistics->increment_packet_Selected(pkthdr);

    }
}