Amostragem de Pacotes para Classificação Online de Tráfego Internet Cifrado
=======

What is it?
-----------


| Selection Scheme         | Trigger  |
| ------------------------ | -------- |
| Systematic Count-based   | position |
| Systematic Time-based    | time     |
| Simple Random            | position |
| Additive Random          | position |
| Multi-Adaptive           | time     |


Usage
-----------

Here goes the help:

```
Usage: ./sampling [options]


Options:
-h,--help   show this help message and exit
  General options:
    -v, --verbose       Verbose mode.
                        Default: brief
    -f FILE, --file FILE
                        Open a file with previous catpured traffic
    -o FILE, --output FILE
                        Save captured traffic to a pcap file.
    -p , --sniffer
                        No selection scheme is applied to the captured traffic.
    -s INTERVAL, --systematic_count INTERVAL
                        Sets the interval between samples to INTERVAL.
    -t INTERVAL, --systematic_time INTERVAL
                        Sets the interval between samples to INTERVAL ms.
    -r N, --simple_random N
                        Sets the interval between samples to
                        [0 , 2*sampling rate-2].
    -a N, --random_additive N
                        Specifies the average sampling rate.
                        On average each sampling will occur every N packets
    -m , --multi_adaptive
                        Default values: min next sample size = 10000 ms
                                        max next samplesize = 500000 ms
                                        min interval between samples = 10000 ms
                                        max interval between samples = 500000 ms
                                        window size = 10

```
### And a real test using multi-adaptive selection scheme
The network traffic used here was captured in a controlled environment and can be downloaded [here](http://download_trace_usado_nos_teste.com).

TODO
-----------