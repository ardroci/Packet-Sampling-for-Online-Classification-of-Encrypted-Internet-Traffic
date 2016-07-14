//
//  Multiadaptive_Sampling.cpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#include "Multiadaptive_Sampling.hpp"
using namespace std;

Multiadaptive_Sampling::Multiadaptive_Sampling(const string input_file, const string output_file, const bool d):Sniffer(input_file,output_file,d), _m_min(0.9),_m_max(1.1){
    puts("Multiadaptive_Sampling - default constructor");
    //_new_Sample_Complete = false;
    //_sample_init = 0;
    //_sample_size = 2;
    //_next_sample_size = 2;
    /*
     _min_next_sample_size = 500000;
    _max_next_sample_size = 2000000;
    
    _min_interval_between_samples = 500000;
    _max_interval_between_samples = 2000000;
    */
    /*
     FIRST CONFIG
     
     _min_next_sample_size = 10000;
     _max_next_sample_size = 50000;
     
     _min_interval_between_samples = 100000;
     _max_interval_between_samples = 500000;
     
     _window_size = 10;
     _current_interval_between_samples = 10000;
     _current_sample_size = 10000;
     */
    /*
     //SECOND CONFIG
     
     _min_next_sample_size = 10000;
    _max_next_sample_size = 500000;
    
    _min_interval_between_samples = 10000;
    _max_interval_between_samples = 500000;
    
    _window_size = 10;
    _current_interval_between_samples = 10000;
    _current_sample_size = 10000;
    */
    
    _min_next_sample_size = 10000;
    _max_next_sample_size = 500000;
    
    _min_interval_between_samples = 10000;
    _max_interval_between_samples = 500000;
    
    _window_size = 10;
    _current_interval_between_samples = 10000;
    _current_sample_size = 10000;
    
    //cout << "Min next sample_size:             " << _min_next_sample_size << endl;
    //cout << "Max next sample_size:             " << _max_next_sample_size << endl;
    //cout << "Min interval between samples:     " << _min_interval_between_samples << endl;
    //cout << "Max interval between samples:     " << _max_interval_between_samples << endl;
    //cout << "Current interval between samples: " << _current_interval_between_samples << endl;
    //cout << "Current sample size:              " << _current_sample_size << endl;
    //cout << "Window size:                      " << _window_size << endl;

    
    Sniffer::start();
}
Multiadaptive_Sampling::~Multiadaptive_Sampling(){
    
}
double Multiadaptive_Sampling::Predictor(){
    /*
     int64_t sum = 0.0;
     for (int i = 0; i<_lastest_reference_parameters.size()-1; ++i) {
     sum += abs( (_lastest_reference_parameters.at(i+1)-_lastest_reference_parameters.at(i)) / _intervals_between_samples.at(i));
     }
     double forecast_reference_parameter = _lastest_reference_parameters.back() + (_interval_between_samples/(_lastest_reference_parameters.size()-1)) * sum;
     return forecast_reference_parameter;
     */
    
    double forecast_reference_parameter = 0.0;
    u_long N = _lastest_reference_parameters.size()-1;
    ////cout << N << endl;
    
    double aux_0 = _lastest_reference_parameters.at(N);
    ////cout << "Aux 0       "<< aux_0<< endl;
    double aux_1 = (_intervals_between_samples.at(N)-_intervals_between_samples.at(N-1))/(N-1);
    ////cout << "Aux 1       "<< aux_1<< endl;
    double num = _lastest_reference_parameters.at(N)-_lastest_reference_parameters.at(0);
    double denom = _intervals_between_samples.at(N)-_intervals_between_samples.at(0);
    
    forecast_reference_parameter = aux_0 + abs(aux_1 * (num / denom));
    ////cout << "Numerador   "<< num<< endl;
    ////cout << "Denominador "<< denom<< endl;
    
    return forecast_reference_parameter;
}
int Multiadaptive_Sampling::new_sample(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet){
    int64_t current_packet_time = timeval_to_usec(&pkthdr->ts);
    
    if ((current_packet_time <= _stop_timer_to_sample ) && (current_packet_time >= _init_timer_to_sample) ) {
        ////cout << "Sampling... Packet Count " << statistics->get_packet_Count()<< endl;
        statistics->increment_packet_Selected(pkthdr);
        pcap_dump(userData, pkthdr, packet);
        ++_aux_packet_Count;
        _aux_packet_length_sum += pkthdr->len;
        return 1;
    }else if ((current_packet_time > _stop_timer_to_sample ) && (current_packet_time <= (_stop_timer_to_sample + _current_interval_between_samples))) {
        ////cout << "Dropped... Packet Count " << statistics->get_packet_Count()<< endl;
        return 0; // packet is in the time between samples
    }else if ((current_packet_time < _init_timer_to_sample ) ) {
        ////cout << "Dropped... Packet Count " << statistics->get_packet_Count()<< endl;
        return 0; // packet is in the time between samples
    }//else if(current_packet_time > (_stop_timer_to_sample + _current_interval_between_samples)){
        //return -2; // no packet was received between the sampling time and the sampling interval
                  // take some precautions
    
    //}
    statistics->increment_nr_sample();;
    return -1;
}
void Multiadaptive_Sampling::select_packet(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet){
    double reference_paramater = 0.0, k = 0.0;
    double m = 0.0;
    if(statistics->get_packet_Count()==1){
        _aux_packet_Count = 0;
        _aux_packet_length_sum = 0;
        X_p = 0.0;
        _init_timer_to_sample = statistics->get_init_capture_time();
        _stop_timer_to_sample = _init_timer_to_sample + _current_sample_size;
        
        //cout << "CHANGE VALUES FIRST" << endl;
        //cout << "INIT                     " << _init_timer_to_sample<< endl;
        //cout << "STOP                     " << _stop_timer_to_sample<< endl;
        //cout << "CURRENT Sample Size      " << _current_sample_size << endl;
        //cout << "CURRENT Interval between " << _current_interval_between_samples << endl;
        //cout << "***************************" << endl;
        
    }
    //Initial Setup
    if(_lastest_reference_parameters.size() != _window_size){
        ////cout << "current_packet_time "<< current_packet_time <<endl;
        ////cout << "_init_timer_to_sample " << _init_timer_to_sample << endl <<"_stop_timer_to_sample "<< _stop_timer_to_sample<< endl<<endl;
        int aux = new_sample(userData, pkthdr, packet);
        if (aux == -1){
            if (_aux_packet_length_sum == 0 || _aux_packet_Count == 0) {
                reference_paramater = 0.000001;
            }else{
                reference_paramater = _aux_packet_length_sum / _aux_packet_Count;
            }
            _init_timer_to_sample = _stop_timer_to_sample + _current_interval_between_samples;
            _stop_timer_to_sample = _init_timer_to_sample + _current_sample_size;
            _lastest_reference_parameters.push_back(reference_paramater);
            _intervals_between_samples.push_back(_init_timer_to_sample);
            
            
            //cout << "CHANGE  AT "<< ctime((const time_t*)&(pkthdr->ts))<<" VALUES CONFIG " << _aux_packet_Count<< endl;
            //nt64_t i = _init_timer_to_sample/1000000;
            //int64_t s = _stop_timer_to_sample/1000000;
            //cout << "INIT                     " << _init_timer_to_sample<< endl;
            //cout << "STOP                     " << _stop_timer_to_sample<< endl;
            //cout << "CURRENT Sample Size      " << _current_sample_size << endl;
            //cout << "CURRENT Interval between " << _current_interval_between_samples << endl;
            //cout << "***************************\n" << endl;
            
            
            _aux_packet_Count = 0;
            _aux_packet_length_sum = 0;
        }
    }else{
        ////cout << "END INITIAL SETUP"<< endl;
        X_p = Predictor();
        int aux = new_sample(userData, pkthdr, packet);
        if (aux == -1){
            if (_aux_packet_length_sum == 0 || _aux_packet_Count == 0) {
                reference_paramater = 0.000001;
                //cout <<"PROBLEM "<<endl;
            }else{
                reference_paramater = _aux_packet_length_sum / _aux_packet_Count;
            }
            m = 1;
            if (reference_paramater != 0) {
                m = (double)X_p / (double)reference_paramater;
            }
            //cout << "***************************" << endl;
            //cout << "X_p = "<< X_p << " reference_paramater " << reference_paramater<< " m = " << m << endl;
            ////cout << "_aux_packet_length_sum = " << _aux_packet_length_sum << "_aux_packet_Count= " << _aux_packet_Count<< endl;
            if (m < _m_min) { //underestimation
                puts("underestimation");
                _next_interval_between_samples = m * _current_interval_between_samples;
                _next_sample_size = m * _current_sample_size;
                ////cout << "_next_interval_between_samples "<< _next_interval_between_samples << endl;
                ////cout << "_next_sample_size"<< _next_sample_size << endl;
            }
            if (m >= _m_min && m <= _m_max) { //correct estimation
                puts("correct estimation");
                _next_interval_between_samples = _current_interval_between_samples;
                _next_sample_size = _current_sample_size;
            }
            if (m>_m_max) { //overestimation
                puts("overestimation");
                _next_interval_between_samples = 2 * _current_interval_between_samples;
                k = 0.15;
                _next_sample_size = (1 + k) * _current_sample_size;
            }
            
            //interval between samples thresholds
            if (_next_interval_between_samples < _min_interval_between_samples) {
                _next_interval_between_samples = _min_interval_between_samples;
            }
            if (_next_interval_between_samples > _max_interval_between_samples) {
                _next_interval_between_samples = _max_interval_between_samples;
            }
            //sampling size thresholds
            if (_next_sample_size < _min_next_sample_size) {
                _next_sample_size = _min_next_sample_size;
            }
            if (_next_sample_size > _max_next_sample_size) {
                _next_sample_size = _max_next_sample_size;
            }
            
            _current_interval_between_samples = _next_interval_between_samples;
            _current_sample_size = _next_sample_size;
            
            
            _init_timer_to_sample = _stop_timer_to_sample + _current_interval_between_samples;
            _stop_timer_to_sample = _init_timer_to_sample + _current_sample_size;
            _lastest_reference_parameters.erase(_lastest_reference_parameters.begin());
            _lastest_reference_parameters.push_back(reference_paramater);
            _intervals_between_samples.erase(_intervals_between_samples.begin());
            _intervals_between_samples.push_back(_init_timer_to_sample);
            
            //cout << "CHANGE  VALUES CONFIG " << statistics->get_packet_Count()<< endl;
            //int64_t i = _init_timer_to_sample/1000000;
            //int64_t s = _stop_timer_to_sample/1000000;
            //cout << "INIT                     " << _init_timer_to_sample<< endl;
            //cout << "STOP                     " << _stop_timer_to_sample<< endl;
            //cout << "CURRENT Sample Size      " << _current_sample_size << endl;
            //cout << "CURRENT Interval between " << _current_interval_between_samples << endl;
            //cout << "***************************" << endl;
            
            _aux_packet_Count = 0;
            _aux_packet_length_sum = 0;
            /*
             //cout << "_intervals_between_samples "<< endl;
             for (int i = 0; i< _intervals_between_samples.size(); ++i) {
             //cout << _intervals_between_samples.at(i)<< ";";
             }
             //cout << endl<< endl << "_lastest_reference_parameters\n";
             
             for (int i = 0; i< _lastest_reference_parameters.size(); ++i) {
             //cout << _lastest_reference_parameters.at(i)<< ";";
             }
             //cout << endl<< endl;
             */
        }
    }
}