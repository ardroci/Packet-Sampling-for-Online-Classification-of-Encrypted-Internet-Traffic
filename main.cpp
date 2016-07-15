/**
 @file main.cpp
 @Author Ricardo Oliveira
 @date 2016
 */

/***********************
 Systematic sampling
 ***********************
 Systematic packet sampling involves the selection of packets according to a deterministic function.
 There are two ways to trigger the selection:
 count-based with the periodic selection of every k-th packet
 time-based driven, where a packet is selected every constant time interval.
 */
/***********************
 Random Sampling
 ***********************
 In random packet sampling the selection of packets is triggered in accordance to a random process. The unbiased estimation can be achieved, since each selection is an independent experiment.
 */
/***********************
 Random additive sampling
 ***********************
 Uses independent, randomly generated triggers in order to select packets.
 These triggers have a common statistical distribution (ex: Poisson distribution)
 */
/***********************
 Simple Random Sampling
 ***********************
 In this technique n samples are selected out of N packets, hence it is sometimes called n-out-of-N sampling. For this sampling schema each packet has an equal chance of being drawn.
 One way of achieving a simple random sample is to randomly generate n di↵erent numbers in the range of 1 to N and then choose all packets with a packet position equal to one of these n numbers. This procedure is repeated for every N packets. For this kind of sampling the sample size is fixed.
 */
/***********************
 Probabilistic Sampling
 ***********************
 In probabilistic sampling samples are chosen in accordance to a pre-defined selection probability. The sample size can be di↵erent for consecutive intervals. For uniform probabilistic sampling each packet is selected independently with a fixed probability p. When a probability p depends on the input (i.e. packet content) then this is non-uniform probabilistic sampling. This non-uniform approach can be used to weight sampling probabilities in order to boost the chance of sampling packets that are rare but are deemed important
 */
/***********************
 Adaptive sampling
 ***********************
 */

/*
 Scheme       |   Input parameters     |     Functions
 ---------------+------------------------+-------------------
 systematic    |    packet position     |  packet counter
 count-based   |    Sampling pattern    |
 ---------------+------------------------+-------------------
 systematic    |      arrival time      |  clock or timer
 time-based    |     Sampling pattern   |
 ---------------+------------------------+-------------------
 random        |  packet position       |  packet counter,
 n-out-of-N    |  Sampling pattern      |  random numbers
               | (random number list)   |
 ---------------+------------------------+-------------------
 uniform       |        Sampling        |  random function
 probabilistic |      probability       |
 ---------------+------------------------+-------------------
 non-uniform   |e.g., packet position,  | selection function,
 probabilistic |  Packet Content(parts) |  probability calc.
 ---------------+------------------------+-------------------
 non-uniform   |e.g., flow state,       | selection function,
 flow-state    |  Packet Content(parts) |  probability calc.
 ---------------+------------------------+-------------------
 property      | Packet Content(parts)  |  filter function or
 match         | or router state        |  state discovery
 ---------------+------------------------+-------------------
 hash-based    |  Packet Content(parts) |  Hash Function
 ---------------+------------------------+-------------------
 */


#include <sstream>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include <getopt.h>
#include <sys/time.h>


#include "Systematic_Sampling__Time_Driven.hpp"
#include "Systematic_Sampling__Count_Based.hpp"
#include "Probabilistic_Sampling__Additive.hpp"
#include "Stratified_Random_Sampling.hpp"
#include "Simple_Random_Sampling.hpp"
#include "Multiadaptive_Sampling.hpp"
#include "Sniffer.hpp"

///this is the preferred way of signaling to the compiler to use large file support
#define _FILE_OFFSET_BITS   64

using namespace std;

const std::string currentTime() {
    cout << "here"<< endl;

    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);
    cout << "here"<< endl;
    return buf;
}

int main(int argc, char** argv) {
    int verbose_flag;
    string _input_file = "", _output_file;
    string _sampling_method;
    string _parameter = "4";
    int c;
    while (1)
    {
        static struct option long_options[] =
        {
            /* These options set a flag. */
            {"verbose", no_argument,       &verbose_flag, 1},
            {"brief",   no_argument,       &verbose_flag, 0},
            /* These options don’t set a flag.
             We distinguish them by their indices. */
            {"file",  required_argument, 0, 'f'},
            {"out",  required_argument, 0, 'o'},
            {"sniffer",     no_argument, 0, 'p'},
            {"systematic_count",     required_argument,       0, 's'},
            {"systematic_time",     required_argument,       0, 't'},

            {"simple_random",  required_argument,       0, 'r'},
            {"random_additive",  required_argument, 0, 'a'},
            {"stratified",  required_argument, 0, 'l'},
            {"multi_adaptive",    no_argument, 0, 'm'},
            {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;
        
        c = getopt_long (argc, argv, "f:o:ps:t:r:a:l:m",
                         long_options, &option_index);
        
        /* Detect the end of the options. */
        if (c == -1)
            break;
        
        switch (c)
        {
            case 0:
                /* If this option set a flag, do nothing else now. */
                if (long_options[option_index].flag != 0)
                    break;
                printf ("option %s", long_options[option_index].name);
                if (optarg)
                    printf (" with arg %s", optarg);
                printf ("\n");
                break;
            case 'f':
                _input_file = optarg;
                break;
            case 'o':
                _output_file = optarg;
                break;
            case 'p':
                _sampling_method = "sniffer";
                break;
            case 's':
                _sampling_method = "systematic count-based";
                _parameter = optarg;
                break;
            case 't':
                _sampling_method = "systematic time-driven";
                _parameter = optarg;
                break;
            case 'r':
                _sampling_method = "simple random";
                _parameter = optarg;
                break;
            case 'a':
                _sampling_method = "random additive";
                _parameter = optarg;
                break;
            case 'l':
                _sampling_method = "stratified";
                _parameter = optarg;
                break;
            case 'm':
                _sampling_method = "multi adaptive";
                break;
                
            case '?':
                /* getopt_long already printed an error message. */
                break;
                
            default:
                abort ();
        }
    }
    cout << "Sampling Method: " << _sampling_method<< endl;
    std::string::size_type sz;   // alias of size_t
    
    /* Instead of reporting ‘--verbose’
     and ‘--brief’ as they are encountered,
     we report the final status resulting from them. */
    if (verbose_flag)
        puts ("verbose flag is set");
    
    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
    {
        printf ("non-option ARGV-elements: ");
        while (optind < argc)
            printf ("%s ", argv[optind++]);
        putchar ('\n');
    }
    if(_output_file.empty()){
        _output_file = "../Resultados/";
    }
    if (_sampling_method.compare("sniffer") == 0) {
        Sniffer sniffer(_input_file,
                        _output_file+_sampling_method+"__"+_parameter+".pcap",
                        verbose_flag                       // dissect packet
                        );
        sniffer.start();

    }else if (_sampling_method.compare("systematic count-based") == 0) {
        printf("count-based interval %d", stoi (_parameter,&sz));
        Systematic_Sampling__Count_Based systematic(_input_file,
                                                    _output_file+_sampling_method+"__"+_parameter+".pcap",
                                                    verbose_flag,                // dissect packet
                                                    stoi (_parameter,&sz),       // count-based interval
                                                    1                            // sample_size
                                                    );
    }else if (_sampling_method.compare("systematic time-driven") == 0) {
        printf("time-driven interval %f", stof (_parameter,&sz));
        Systematic_Sampling__Time_Driven systematic(_input_file,
                                                    _output_file+_sampling_method+"__"+_parameter+".pcap",
                                                    verbose_flag,                      // dissect packet
                                                    stof (_parameter,&sz),             // time-driven interval
                                                    1                                  // sample_size
                                                    );
        
    }else if (_sampling_method.compare("simple random") == 0) {
        Simple_Random simple_random(_input_file,
                                    _output_file+_sampling_method+"__"+_parameter+".pcap",
                                    verbose_flag,                  // dissect packet
                                    stoi (_parameter,&sz),         // sampling_rate
                                    100
                                    );
    }else if (_sampling_method.compare("random additive") == 0) {
        Random_Aditive__Count_Based random_additive(_input_file,
                                                    _output_file+_sampling_method+"__"+_parameter+".pcap",
                                                    verbose_flag,             // dissect packet
                                                    100,                      // produce x random numbers at a time
                                                    stoi (_parameter,&sz)     // average_sampling_rate -> on average each sampling will occur every x packets
                                                    );
    }else if (_sampling_method.compare("stratified") == 0) {
        printf("sample size %d", stoi (_parameter,&sz));
        Stratified_Random_Sampling stratified(_input_file,
                                              _output_file+_sampling_method+"__"+_parameter+".pcap",
                                              verbose_flag ,                   // dissect packet
                                              stoi (_parameter,&sz)            // sample size
                                              );
    }else if (_sampling_method.compare("multi adaptive") == 0) {
        Multiadaptive_Sampling multiadaptive(_input_file,
                                             _output_file+_sampling_method+"__"+_parameter+".pcap",
                                             verbose_flag                    // dissect packet
                                             );
    }
    return 0;
}