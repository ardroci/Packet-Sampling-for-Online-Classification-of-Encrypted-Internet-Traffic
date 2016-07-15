/**
 @file Multiadaptive_Sampling.hpp
 @Author Ricardo Oliveira
 @date 2016
 */
#ifndef Multiadaptive_Sampling_hpp
#define Multiadaptive_Sampling_hpp


#include "Sniffer.hpp"

/**
 @brief Multiadaptive class
 

 @todo
 */

class Multiadaptive_Sampling : public Sniffer{
private:
    const double _m_min;
    const double _m_max;
    //! The vector x holds the predicted value of the previous N samples, where x[N] is the most recent sample and x[0] is the oldest sample.
    vector<double> _lastest_reference_parameters;
    //! Records the time that each sample is taken and is shifted in the same manner as x, with the time at which Sample was taken replacing t[N]
    vector<int64_t> _intervals_between_samples;
    
    int _window_size;
    
    int64_t _current_interval_between_samples;
    long long int _current_sample_size;
    int64_t _stop_timer_to_sample;
    int64_t _init_timer_to_sample;
    
    
    
    long long int _aux_packet_Count;
    long double _aux_packet_length_sum;
    double X_p;
    
    
    int64_t _next_interval_between_samples;
    int64_t _min_interval_between_samples;
    int64_t _max_interval_between_samples;
    
    int64_t _next_sample_size;
    int64_t _min_next_sample_size;
    int64_t _max_next_sample_size;
    
    
    
    
public:
    Multiadaptive_Sampling(const string input_file, const string output_file, const bool d);
    ~Multiadaptive_Sampling();
    
    double Predictor();
    //! Choose whether to write or discard a packet to a capture file
    virtual void select_packet(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet);
    int new_sample(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet);
};

#endif /* Multiadaptive_Sampling_hpp */
