/**
 @file Simple_Random_Sampling.hpp
 @Author Ricardo Oliveira
 @date 2016
 */

#ifndef Simple_Random_Sampling_hpp
#define Simple_Random_Sampling_hpp


#include "Sniffer.hpp"

/**
 @brief Simple Random class
 
 In random packet sampling the selection of packets is triggered in accordance to a random process. The unbiased estimation can be achieved, since each selection is an independent experiment.
 In this technique n samples are selected out of N packets, hence it is sometimes called n-out-of-N sampling. For this sampling schema each packet has an equal chance of being drawn.
 One way of achieving a simple random sample is to randomly generate n di↵erent numbers in the range of 1 to N and then choose all packets with a packet position equal to one of these n numbers. This procedure is repeated for every N packets. For this kind of sampling the sample size is fixed.

 
 @todo
 */

class Simple_Random : protected Sniffer{
private:
    vector<long long int> _sampling_time;
    //! Sampling rate
    int _sampling_rate;
    //int _number_of_trials;   //the t distribution parameter (number of trials)
    //double _p_true;          //the p distribution parameter (probability of a trial generating true)
    long long int _nr_samples;
    //!  \brief Sets the beginning of the next sample
    long long int _next_sample;
    
    
public:
    //! \brief Constructor
    Simple_Random(const string input_file,const string output_file, const bool d);
    //! \brief Constructor
    Simple_Random(const string input_file,const string output_file, const bool d, const int sampling_rate, const int nr_samples);
    //! @brief Destructor
    ~Simple_Random();
    
    void when_will_next_sample_will_occur();
    /** \brief Generate random numbers.
     Produces random integer values i, uniformly distributed on the closed interval [a, b], that is, distributed according to the discrete probability function:
     P(i|a,b) = 1/(b − a + 1)
     */
    void uniform_distribution_random_number_generation(const int sampling_rate);
    //! Choose whether to write or discard a packet to a capture file
    virtual void select_packet(u_char *userData,const struct pcap_pkthdr *pkthdr,const  u_char *packet);
};
#endif /* Simple_Random_Sampling_hpp */
