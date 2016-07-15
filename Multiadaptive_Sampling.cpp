/**
 @file Multiadaptive_Sampling.cpp
 @Author Ricardo Oliveira
 @date 2016
 */

#include "Multiadaptive_Sampling.hpp"
using namespace std;

Multiadaptive_Sampling::Multiadaptive_Sampling(const string input_file, const string output_file, const bool d):Sniffer(input_file,output_file,d), _m_min(0.9),_m_max(1.1){
    puts("Multiadaptive_Sampling - default constructor");

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
    
    
    Sniffer::start();
}
Multiadaptive_Sampling::~Multiadaptive_Sampling(){
    
}
double Multiadaptive_Sampling::Predictor(){

    double forecast_reference_parameter = 0.0;
    u_long N = _lastest_reference_parameters.size()-1;
    
    double aux_0 = _lastest_reference_parameters.at(N);
    double aux_1 = (_intervals_between_samples.at(N)-_intervals_between_samples.at(N-1))/(N-1);
    double num = _lastest_reference_parameters.at(N)-_lastest_reference_parameters.at(0);
    double denom = _intervals_between_samples.at(N)-_intervals_between_samples.at(0);
    
    forecast_reference_parameter = aux_0 + abs(aux_1 * (num / denom));
    
    return forecast_reference_parameter;
}
int Multiadaptive_Sampling::new_sample(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet){
    int64_t current_packet_time = timeval_to_usec(&pkthdr->ts);
    
    if ((current_packet_time <= _stop_timer_to_sample ) && (current_packet_time >= _init_timer_to_sample) ) {
        //cout << "Sampling... Packet Count " << statistics->get_packet_Count()<< endl;
        statistics->increment_packet_Selected(pkthdr);
        pcap_dump(userData, pkthdr, packet);
        ++_aux_packet_Count;
        _aux_packet_length_sum += pkthdr->len;
        return 1;
    }else if ((current_packet_time > _stop_timer_to_sample ) && (current_packet_time <= (_stop_timer_to_sample + _current_interval_between_samples))) {
        //cout << "Dropped... Packet Count " << statistics->get_packet_Count()<< endl;
        return 0; // packet is in the time between samples
    }else if ((current_packet_time < _init_timer_to_sample ) ) {
        //cout << "Dropped... Packet Count " << statistics->get_packet_Count()<< endl;
        return 0; // packet is in the time between samples
    }
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

        
    }
    //Initial Setup
    if(_lastest_reference_parameters.size() != _window_size){

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
            
            _aux_packet_Count = 0;
            _aux_packet_length_sum = 0;
        }
    }else{
        //puts("END INITIAL SETUP");
        X_p = Predictor();
        int aux = new_sample(userData, pkthdr, packet);
        if (aux == -1){
            if (_aux_packet_length_sum == 0 || _aux_packet_Count == 0) {
                reference_paramater = 0.000001;
                //puts("PROBLEM ");
            }else{
                reference_paramater = _aux_packet_length_sum / _aux_packet_Count;
            }
            m = 1;
            if (reference_paramater != 0) {
                m = (double)X_p / (double)reference_paramater;
            }

            if (m < _m_min) { //underestimation
                _next_interval_between_samples = m * _current_interval_between_samples;
                _next_sample_size = m * _current_sample_size;
            }
            if (m >= _m_min && m <= _m_max) { //correct estimation
                _next_interval_between_samples = _current_interval_between_samples;
                _next_sample_size = _current_sample_size;
            }
            if (m>_m_max) { //overestimation
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
            
            _aux_packet_Count = 0;
            _aux_packet_length_sum = 0;
 
        }
    }
}