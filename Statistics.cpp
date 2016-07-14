//
//  Statistics.cpp
//  Projeto
//
//  Created by Ricardo Oliveira on 18/04/16.
//  Copyright © 2016 Ricardo Oliveira. All rights reserved.
//

#include "Statistics.hpp"
using namespace std;

Statistics::Statistics(){
    
    /*  Overhead    */
    _packet_Count = 0;                    //packets captured
    _total_data_Volume = 0;               //sum of all packets captured
    _data_Volume = 0;                     //sum of all packets collected with each sampling technique
    _nr_of_Samples = 0;                   //total number of samples
    _packet_Selected = 0;                 //packets selectd with each sampling technique
    aux_current_time = 0;
    _aux_throughput_total = 0;
    _aux_throughput_sample = 0;
    
}
Statistics::~Statistics(){
    
}
int64_t timeval_to_usec( const struct timeval* tv ){
    return( (int64_t)tv->tv_sec  * 1000000 + tv->tv_usec);
}


void Statistics::increment_packet_Count(const struct pcap_pkthdr * pkthdr){
    ++_packet_Count;
    if (_packet_Count == 1) {
        //puts("STATS 1");
        _init_capture_time.tv_sec = pkthdr->ts.tv_sec;
        _init_capture_time.tv_usec = pkthdr->ts.tv_usec;
        _stop = timeval_to_usec(&_init_capture_time);
    }
    _current_sample_time.tv_sec = pkthdr->ts.tv_sec;
    _current_sample_time.tv_usec = pkthdr->ts.tv_usec;
    
    /*  real time throughput*/
    _total_data_Volume += pkthdr->len;
    aux_current_time = timeval_to_usec(&_current_sample_time);
    
    /*ESTE SEGMENTO FAZ O MESMO QUE A FUNÇÂO TESTE*/
    if(aux_current_time > _stop){
        _throughput_total.push_back(_aux_throughput_total);
        _aux_throughput_total = pkthdr->len;
        _throughput_sample.push_back(_aux_throughput_sample);
        std::ofstream outfile;
        outfile.open("throughput.txt", std::ios_base::app);
        outfile << _aux_throughput_sample << " ";
        _aux_throughput_sample = pkthdr->len;
        _stop = aux_current_time + 60000000;
        
    }
    /*ATÉ AQUI*/
//  if(aux_current_time <= _stop){
    else{
        _aux_throughput_total += pkthdr->len;
    }
    _t_data_volume.push_back(pkthdr->len);
}
void Statistics::teste(const struct pcap_pkthdr * pkthdr){
    if(aux_current_time > _stop){
        _throughput_total.push_back(_aux_throughput_total);
        _aux_throughput_total = pkthdr->len;
        _throughput_sample.push_back(_aux_throughput_sample);
        std::ofstream outfile;
        outfile.open("example.txt", std::ios_base::app);
        outfile << _aux_throughput_sample << " ";
        _aux_throughput_sample = pkthdr->len;
        _stop = aux_current_time + 60000000;
    }
    
}
int64_t Statistics::get_init_capture_time(){
    return timeval_to_usec(&_init_capture_time);
    
}
void Statistics::increment_nr_sample(){
    ++_nr_of_Samples;                       //total number of samples

}
void Statistics::increment_packet_Selected(const struct pcap_pkthdr * pkthdr){
    ++_packet_Selected;                     //packets selectd with each sampling technique
    /*  real time throughput*/
    _data_Volume += pkthdr->len;
    if(aux_current_time <= _stop){
        _aux_throughput_sample += pkthdr->len;
    }
}

long long int Statistics::get_packet_Count(){
    return _packet_Count;
}
long long int Statistics::get_number_Packets_Selected(){
    return _packet_Selected;
}
const std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);
    return buf;
}
void Statistics::print_stats(){
    struct timeval aux;
    
    timersub(&_current_sample_time, &_init_capture_time, &aux);
    long long int throughput_total = _total_data_Volume*1000000/timeval_to_usec(&aux);
    long long int throughput_sampled = _data_Volume*1000000/timeval_to_usec(&aux);
    printf("\n\t\t\t\t%s\n",currentDateTime().c_str());
    printf("\t\t\t\tStatistical Parameters\n\n");
    
    printf("First Packet %s",ctime((const time_t*)&_init_capture_time.tv_sec));
    printf("Last  Packet %s",ctime((const time_t*)&_current_sample_time.tv_sec));
    printf("Elapsed Time %ld.%d s\n\n", aux.tv_sec, aux.tv_usec) ;
    
    /*  Overhead    */
    printf("Overhead :\n");
    printf("\tNumber of packets captured : %lld\n", _packet_Count);
    printf("\tNumber of packets selected : %lld (%.5f %c)\n",_packet_Selected, (_packet_Selected * 100.0 / _packet_Count), '%');
    printf("\tAppropriate sample size      %lld\n\n", get_appropriate_sample_size(get_mean(), get_standard_deviation(), 1) );

    printf("\tTotal Data Volume :          %lld Bytes\n", _total_data_Volume);
    printf("\tSampled Data Volume :        %lld Bytes\n", _data_Volume);
    printf("\tNumber of Samples:           %lld\n\n",_nr_of_Samples);
    /*  Throughput Estimation   */
    printf("Throughput Estimation:\n");
    printf("\tTotal Throughput :           %lld bytes/s\n",throughput_total);                           //volume of data transferred per unit of time
    printf("\tSampled Throughput :         %lld bytes/s\n",throughput_sampled);                         //volume of data transferred per unit of time
    printf("\tCoefficient of Variation :   %.3f\n", get_coefficient_of_variation());                    //helps to identify and characterize the traffic burstiness
    printf("\tTotal Peak to average :      %.3f\n", get_peak_to_average_ratio(&_throughput_total));     //ration between max and average throughput
    printf("\tSampled Peak to average :    %.3f\n", get_peak_to_average_ratio(&_throughput_sample));    //ration between max and average throughput
    printf("\tCorrelation :                %.3f\n", get_pearson_correlation());                         //correlation between the sampled traffic and total traffic
    printf("\tRelative Error :             %.3f\n", get_relative_error());
    
    printf("\tMean:                        %.3lld\n", (_total_data_Volume/_packet_Count));
    printf("\tStandard Deviation:          %.3f\n", get_standard_deviation());
    //cout << "SUM TOTAL INSTANT TROUGHPUT " << accumulate(_throughput_total.begin(), _throughput_total.end(), 0.0) << endl;
}

void Statistics::write_stats(){
    struct timeval aux;
    
    timersub(&_current_sample_time, &_init_capture_time, &aux);
    long long int throughput_total = _total_data_Volume*1000000/timeval_to_usec(&aux);
    long long int throughput_sampled = _data_Volume*1000000/timeval_to_usec(&aux);
    FILE* pFile;
    time_t t = time(0);   // get time now
    struct tm * now = localtime( & t );
    string filename = "/Users/ricardooliveira/Documents/Projeto/Projeto/Projeto/Resultados/"+currentDateTime()+".txt";
    pFile = fopen(filename.c_str(), "wb");
    //fwrite("\n\t\t\t\tStatistical Parameters\n\n", sizeof(char), sizeof("\n\t\t\t\tStatistical Parameters\n\n"), pFile);
    fprintf(pFile,"\n\t\t\t\tStatistical Parameters\n\n" );
    fprintf(pFile,"First Packet %s",ctime((const time_t*)&_init_capture_time.tv_sec));
    fprintf(pFile,"Last  Packet %s",ctime((const time_t*)&_current_sample_time.tv_sec));
    fprintf(pFile,"Elapsed Time %ld.%d s\n\n", aux.tv_sec, aux.tv_usec) ;
    
    /*  Overhead    */
    fprintf(pFile,"Overhead :\n");
    fprintf(pFile,"\tNumber of packets captured : %lld\n", _packet_Count);
    fprintf(pFile,"\tNumber of packets selected : %lld (%.5f %c)\n",_packet_Selected, (_packet_Selected * 100.0 / _packet_Count), '%');
    fprintf(pFile,"\tTotal Data Volume :          %lld Bytes\n", _total_data_Volume);
    fprintf(pFile,"\tSampled Data Volume :        %lld Bytes\n", _data_Volume);
    fprintf(pFile,"\tNumber of Samples:           %lld\n\n",_nr_of_Samples);
    /*  Throughput Estimation   */
    fprintf(pFile,"Throughput Estimation:\n");
    fprintf(pFile,"\tTotal Throughput :           %lld bytes/s\n",throughput_total);                           //volume of data transferred per unit of time
    fprintf(pFile,"\tSampled Throughput :         %lld bytes/s\n",throughput_sampled);                         //volume of data transferred per unit of time
    fprintf(pFile,"\tCoefficient of Variation :   %.3f\n", get_coefficient_of_variation());                    //helps to identify and characterize the traffic burstiness
    fprintf(pFile,"\tTotal Peak to average :      %.3f\n", get_peak_to_average_ratio(&_throughput_total));     //ration between max and average throughput
    fprintf(pFile,"\tSampled Peak to average :    %.3f\n", get_peak_to_average_ratio(&_throughput_sample));    //ration between max and average throughput
    fprintf(pFile,"\tCorrelation :                %.3f\n", get_pearson_correlation());                         //correlation between the sampled traffic and total traffic
    fprintf(pFile,"\tRelative Error :             %.3f\n\n", get_relative_error());
    
    fclose(pFile);
}
double Statistics::get_relative_error(){
    /*
     (Adaptive Sampling for Network Management   -   Edwin A. Hernandez, Matthew C. Chidester, and Alan D. George)
     
     "In order to compare the performance of the adaptive sampling techniques with the systematic baseline, a measure of accuracy is needed.
     The sum of squared error metric [2] for comparing two N-sample sets, to compare the accuracy of the different techniques.
     This expression makes a point- by-point comparison between the reference and sampled signals using the normalized magnitude of the instantaneous throughput."
     */
    long long int min_throughput_total = 0;
    long long int max_throughput_total = 0;
    long long int min_throughput_sample = 0;
    long long int max_throughput_sample = 0;
    double _relative_error = 0.0;
    
    if (!_throughput_total.empty()) {
        max_throughput_total = *max_element(_throughput_total.begin(),_throughput_total.end());
        min_throughput_total = *min_element(_throughput_total.begin(),_throughput_total.end());
    }
    if (!_throughput_sample.empty()) {
        max_throughput_sample = *max_element(_throughput_sample.begin(),_throughput_sample.end());
        min_throughput_sample = *min_element(_throughput_sample.begin(),_throughput_sample.end());
    }
    
    //cout << "TROUGHPUT TOTAL  - min "<< min_throughput_total << " max - "<< max_throughput_total<< endl;
    //cout << "TROUGHPUT SAMPLE - min "<<min_throughput_sample << " max - "<< max_throughput_sample<< endl;
    double normalized_throughput_total = 0.0;
    double normalized_throughput_sample = 0.0;
    
    for (int i = 0; i<_throughput_total.size(); ++i) {
        normalized_throughput_total = ((double)_throughput_total.at(i) - (double)min_throughput_total)/((double)max_throughput_total-(double)min_throughput_total);
        normalized_throughput_sample = (((double)_throughput_sample.at(i) - (double)min_throughput_sample)/((double)max_throughput_sample - (double)min_throughput_sample));
        _relative_error += pow((normalized_throughput_total - normalized_throughput_sample), 2);
        
        //cout << "["<< i << ","<<i+1<<"]s  "<<_throughput_total.at(i)<< "\t-> " << _throughput_sample.at(i)<< endl;
        
        
    }
    return _relative_error;
}
double Statistics::get_mean(){
    double sum = std::accumulate(_t_data_volume.begin(), _t_data_volume.end(), 0.0);
    double mean = sum / _t_data_volume.size();
    return mean;

}
double Statistics::get_standard_deviation(){
    std::vector<double> diff(_t_data_volume.size());
    double mean = get_mean();
    std::transform(_t_data_volume.begin(), _t_data_volume.end(), diff.begin(),
                   std::bind2nd(std::minus<double>(), mean));
    double sq_sum = std::inner_product(diff.begin(), diff.end(), diff.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / _t_data_volume.size());
    return stdev;
}
long long int Statistics::get_appropriate_sample_size(const double mean, const double std_deviation, const double accuracy){
    double z = 1.96;
    return pow(((100*z*std_deviation)/(accuracy*mean)),2);
}
float Statistics::get_peak_to_average_ratio(vector<long long int> *_throughput){
    if(!_throughput->empty()){
        long long int max = *max_element(_throughput->begin(),_throughput->end());
        long long int average = accumulate(_throughput->begin(), _throughput->end(), 0.0) / _throughput->size();
        if (average != 0) {
            return ((float)max/(float)average);
        }
    }
    return 0.0;
}
double Statistics::get_pearson_correlation(){
    /* The Pearson product-moment correlation coefficient (or Pearson correlation coefficient, for short) is a measure of the strength of a linear association between two variables and is denoted by r. Basically, a Pearson product-moment correlation attempts to draw a line of best fit through the data of two variables, and the Pearson correlation coefficient, r, indicates how far away all these data points are to this line of best fit (how well the data points fit this new model/line of best fit).
     
     
     0.9 positive or negative indicates a very strong correlation.
     0.7 a 0.9 positive or negative indicates a string correlation.
     0.5 a 0.7 positive or negative indicates a moderate correlation
     0.3 a 0.5 positive or negative indicates a weak correlation.
     0 a 0.3 positive or negative indicates a negligible correlation.
     */
    
    double average_total = accumulate(_throughput_total.begin(), _throughput_total.end(), 0.0) / _throughput_total.size();
    double average_sample = accumulate(_throughput_sample.begin(), _throughput_sample.end(), 0.0) / _throughput_sample.size();
    double nom = 0.0, d_t = 0.0, d_s = 0.0;
    
    for(int i = 0; i < _throughput_total.size();++i){
        nom += (_throughput_total.at(i)-average_total)*(_throughput_sample.at(i)-average_sample);
        d_t += pow((_throughput_total.at(i)-average_total),2);
        d_s += pow((_throughput_sample.at(i)-average_sample),2);
    }
    
    d_t = sqrt(d_t);
    d_s = sqrt(d_s);
    if (d_t != 0.0 && d_s != 0.0) {
        return nom / (d_t * d_s);
    }
    return 0.0;
}
double Statistics::get_coefficient_of_variation(){
    double variance = 0;
    long long int average_sample = accumulate(_throughput_sample.begin(), _throughput_sample.end(), 0.0) / _throughput_sample.size();
    for(int i = 0; i < _throughput_sample.size();++i){
        variance += pow((_throughput_sample.at(i)-average_sample),2);
    }
    return sqrt(variance);
    
}

