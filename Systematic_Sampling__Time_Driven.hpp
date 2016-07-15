/**
 @file Systematic_Sampling__Time_Driven.hpp
 @Author Ricardo Oliveira
 @date 2016
 */
#ifndef Systematic_Sampling__Time_Driven_hpp
#define Systematic_Sampling__Time_Driven_hpp

#include "Sniffer.hpp"

using namespace std;

/**
 @brief Systematic Sampling Time Driven class
 
 Systematic packet sampling involves the selection of packets according to a deterministic function.
 There are two ways to trigger the selection:
 count-based with the periodic selection of every k-th packet
 time-based driven, where a packet is selected every constant time interval.
 
 @todo
 */

class Systematic_Sampling__Time_Driven : protected Sniffer{
private:
    //! @brief random offset
    //! Sets a random start to begin collecting traffic. It aims to get different results for each new experience, even with the same traffic
    double _offset;
    //!  @brief Sampling frequency
    int64_t _interval;
    //!  @brief Sets the beginning of a new sample
    int64_t _start_sample;
    //!  @brief Sets the end of the sample
    int64_t _end_sample;
    //! @brief Sample size
    int64_t _sample_size;
    
    //! @brief Constructor
    Systematic_Sampling__Time_Driven ();
public:
    //! @brief Constructor
    Systematic_Sampling__Time_Driven (const string input_file, const string output_file, const bool d, const long long int sample_size);
    //! @brief Constructor
    Systematic_Sampling__Time_Driven(const string input_file,const string output_file, const bool d, const int64_t interval, const long long int sample_size);
    //!  @brief Destructor
    ~Systematic_Sampling__Time_Driven ();
    //! Choose whether to write or discard a packet to a capture file
    void select_packet(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
#endif /* Systematic_Sampling__Time_Driven_hpp */
