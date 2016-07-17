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
    -f FILE, --file FILE
                        something
    -p , --sniffer
                        something
    -s FILE, --systematic_count FILE
                        something
    -t FILE, --systematic_time FILE
                        something
    -r FILE, --simple_random FILE
                        something
    -a FILE, --random_additive FILE
                        something
    -m , --multi_adaptive

```
### And a real test using multi-adaptive selection scheme
The network traffic used here was captured in a controlled environment and be downloaded [here](http://download_trace_usado_nos_teste.com).

TODO
-----------