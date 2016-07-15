/**
 @file Probabilistic_Sampling__Additive.hpp
 @Author Ricardo Oliveira
 @date 2016
 */

#ifndef Probabilistic_Sampling__Additive_hpp
#define Probabilistic_Sampling__Additive_hpp

#include "Sniffer.hpp"

/**
 @brief Random Additive class
 
 Uses independent, randomly generated triggers in order to select packets.
 These triggers have a common statistical distribution (ex: Poisson distribution)
 
 @todo
 */

class Random_Aditive__Count_Based : public Sniffer{
private:
    
    vector<long long int> _sampling_time;
    //!  \brief Sets the beginning of the next sample
    long long int _next_sample;
    
    int _nr_samples;
    //! \brief On average each sampling will occur every x packets
    int _average_sampling_rate;
public:
    //! \brief  Constructor
    Random_Aditive__Count_Based(const string input_file, const string output_file, const bool d);
    //! \brief  Constructor
    Random_Aditive__Count_Based(const string input_file, const string output_file, const bool d, const int nr_samples, const int average_sampling_rate);
    //! \brief  Destructor
    ~Random_Aditive__Count_Based();
    //! \brief  Gets how many unsucessful trials before frist success in a sequence of trials
    void when_next_sample_will_occur();
    //! \brief Generate random numbers.
    //! This distribution produces positive random integers where each value represents the number of unsuccessful trials before a first success in a sequence of trials, each with a probability of success equal to p.
    void geometric_distribution_random_number_generation(const int nr_samples, const int average_sampling_rate);
    //! Choose whether to write or discard a packet to a capture file
    void select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
#endif /* Probabilistic_Sampling__Additive_hpp */
