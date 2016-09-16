Packet Sampling for Online Classification of Encrypted Internet Traffic
=======

What is it?
-----------

The choice of a specific sampling strategy requires a broad and clear understanding of the capabilities and limitations of each technique and the specific behavior of the network on which it will be applied. Therefore, to properly consider a greater number of traffic scenarios and specific needs this tool provides a wider collection of packet sampling techniques, presented in the table.

| Selection Scheme         | Trigger  |
| ------------------------ | -------- |
| Systematic Count-based   | position |
| Systematic Time-based    | time     |
| Simple Random            | position |
| Additive Random          | position |
| Multi-Adaptive           | time     |

Usage
-----------

As simple as providing the selection scheme. Here goes the help:

```
user$ ./sampling --help

Packet sampling for online classification of encrypted internet traffic.
Ricardo Oliveira '16

Usage: ./sampling [options]

Options:
-h,--help   show this help message and exit

  General options:
    -v, --verbose       Verbose mode.
                        Default: brief
    -f FILE, --file FILE
                        Open a file with previous captured traffic.
    -o FILE, --output FILE
                        Specifies the directory where the captured
                        traffic is saved in a pcap file.
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
                        On average each sampling will occur every N packets.
    -m , --multi_adaptive
                        Default values: min next sample size = 10000 ms
                                        max next samplesize = 500000 ms
                                        min interval between samples = 10000 ms
                                        max interval between samples = 500000 ms
                                        window size = 10
```

### And a real test using multi-adaptive selection scheme
The network traffic used here was captured in a controlled environment and can be downloaded [here](http://download_trace_usado_nos_teste.com).

```
user$ ./sampling --file captured-traffic.pcap --output /user/home/Desktop/  --multi_adaptive

                Statistical Parameters

First Packet Fri Aug  5 18:48:03 2011
Last  Packet Fri Aug  5 19:06:19 2011
Elapsed Time 1095.917873 s

Overhead :
  Number of packets captured : 1890723
  Number of packets selected : 422516 (22.34680 %)
  Appropriate sample size :    32971

  Total Data Volume :          1393631968 Bytes
  Sampled Data Volume :        311384916 Bytes
  Number of Samples :          42535

Throughput Estimation:
  Total Throughput :           1271657 bytes/s
  Sampled Throughput :         284131 bytes/s
  Total Peak to average :      1.280
  Sampled Peak to average :    1.285
  Correlation :                0.999
  Relative Error :             0.001
  Mean :                       737
  Standard Deviation :         682.867

```

Usage
-----------

If you’re running on Linux, you probably already have GPG (GNU Privacy Guard) installed. If you’re on Windows or OS X, you’ll need to install the appropriate version for your platform.

  Markup : *  If you’re on a PC running Windows, download and install GPG4Win from [here](http://gpg4win.org/download.html). 
  Markup : *  If you’re on a Macintosh running OS X, download and install GPGTools from [here](https://gpgtools.org/). Since Windows does not have the native ability to calculate SHA1 checksums, you will also need a utility such as [Microsoft File Checksum Integrity Verifier](http://www.microsoft.com/en-us/download/details.aspx?id=11533) or [Hashtab](http://www.implbits.com/HashTab/HashTabWindows.aspx) to verify your download.

Once you’ve installed GPG, you’ll need to download and import a copy of the Kali Linux official key. Do this with the following command:
```
$ gpg --keyserver hkp://keys.gnupg.net --recv-key CE994164
```

Your output should look like this:

```
gpg: key CE994164: public key "Ricardo Costa Oliveira <rcoliveira314@gmail.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
```

<!--- 
TODO
-----------
--> 
