//
//  Systematic_Sampling__Time_Driven.cpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#include "Systematic_Sampling__Time_Driven.hpp"
Systematic_Sampling__Time_Driven ::Systematic_Sampling__Time_Driven (const string input_file, const string output_file, const bool d, const long long int sample_size) : Sniffer(input_file, output_file, d), _interval(4*1000000), _sample_size(sample_size*1000000){
    puts("Systematic_Sampling - default constructor");
    Sniffer::start();
}

Systematic_Sampling__Time_Driven::Systematic_Sampling__Time_Driven (const string input_file, const string output_file, const bool d, const int64_t interval, const long long int sample_size) : Sniffer(input_file,output_file, d), _interval(interval*1000000), _sample_size(sample_size*1000000) {
    puts("Systematic_Sampling - constructor");
    Sniffer::start();
}

Systematic_Sampling__Time_Driven ::~Systematic_Sampling__Time_Driven (){
}
void Systematic_Sampling__Time_Driven::select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    //puts("Systematic_Sampling");
    int64_t time = timeval_to_usec(&pkthdr->ts);
    //cout << "\t\t"<< time << endl;
    if(statistics->get_packet_Count() == 1){
        _start_sample = timeval_to_usec(&pkthdr->ts);
        _end_sample = _start_sample + _sample_size;
        //cout << "start" << _start_sample << "end" << _end_sample << endl;
        //_last  = _start + (_interval*1000000);
        statistics->increment_nr_sample();;
    }
    if(time < _start_sample){
        return;
    }
    if(time >= _start_sample && time < _end_sample){
        //cout << "sample "<< endl;
        pcap_dump(userData, pkthdr, packet);
        statistics->increment_packet_Selected(pkthdr);
    }
    else{
        _start_sample =  _end_sample + (_interval );
        _end_sample = _start_sample + (_sample_size);
        statistics->increment_nr_sample();;
    }
}