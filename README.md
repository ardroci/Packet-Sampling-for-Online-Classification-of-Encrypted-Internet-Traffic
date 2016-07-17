Amostragem de Pacotes para Classificação Online de Tráfego Internet Cifrado
=======

What is it?
-----------


Colons can be used to align columns.

| Selection Scheme         | Trigger  |
| :----------------------: |:--------:|
| Systematic Count-based   | position |
| Systematic Time-based    | time     |
| Simple Random            | position |
| Additive Random Sampling | position |
| Multi-Adaptive           | time     |


Usage
-----------


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

Here goes the help:
### Another deeper heading
[link](http://download_trace_usado_nos_teste.com).

TODO
-----------