Amostragem de Pacotes para Classificação Online de Tráfego Internet Cifrado
=======

What is it?
-----------


| Selection Scheme         | Trigger  |
| ------------------------ | -------- |
| Systematic Count-based   | position |
| Systematic Time-based    | time     |
| Simple Random            | position |
| Additive Random Sampling | position |
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
                        Default: --brief
    -f FILE, --file FILE
                        something
    -o FILE, --output FILE
                        something
    -p , --sniffer
                        something
    -s INTERVAL, --systematic_count INTERVAL
                        Specifies the interval between samples
    -t INTERVAL, --systematic_time INTERVAL
                        Specifies the interval in ms between samples.
    -r RATE, --simple_random RATE
                        something
    -a RATE, --random_additive RATE
                        Specifies the average_sampling_rate.
                        On average each sampling will occur every RATE packets
    -m , --multi_adaptive
                        something

```
### And a real test using multi-adaptive selection scheme
The network traffic used here was captured in a controlled environment and can be downloaded [here](http://download_trace_usado_nos_teste.com).

TODO
-----------