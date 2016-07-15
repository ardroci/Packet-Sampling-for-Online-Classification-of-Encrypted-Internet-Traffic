/**
 @file Systematic_Sampling__Count_Based.hpp
 @Author Ricardo Oliveira
 @date 2016
 */

#ifndef Systematic_Sampling__Count_Based_hpp
#define Systematic_Sampling__Count_Based_hpp

#include "Sniffer.hpp"

/**
 @brief Systematic Sampling Count Based class
 
 Systematic packet sampling involves the selection of packets according to a deterministic function.
 There are two ways to trigger the selection:
 count-based with the periodic selection of every k-th packet
 time-based driven, where a packet is selected every constant time interval.
 
 @todo
 */

class Systematic_Sampling__Count_Based : protected Sniffer{
private:
    //! @brief random offset
    //! Sets a random start to begin collecting traffic. It aims to get different results for each new experience, even with the same traffic
    int _offset;
    //!  @brief Sampling frequency
    int _interval;
    //!  @brief Sets the beginning of a new sample
    long long int _start_sample;
    //!  @brief Sets the end of the sample
    long long int _end_sample;
    //! @brief Sample size
    long long int _sample_size;

    //! @brief Constructor
    Systematic_Sampling__Count_Based();
public:
    //! @brief Constructor
    Systematic_Sampling__Count_Based(const string input_file, const string output_file, const bool verbose, const int sample_size);
    //! @brief Constructor
    Systematic_Sampling__Count_Based(const string input_file, const string output_file, const bool verbose, const int interval, const int sample_size);
    //!  @brief Destructor
    ~Systematic_Sampling__Count_Based();
    //! Choose whether to write or discard a packet to a capture file
    void select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
#endif /* Systematic_Sampling__Count_Based_hpp */
