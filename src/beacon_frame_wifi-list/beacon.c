#include <stdio.h>
#include "beacon.h"

int dump_radiotap(struct radiotap_header *radiotap_header){
    unsigned int len = radiotap_header->len;
    //printf("[Radiotap Length] : %d\n",len);
    return len;
}

int dump_beacon_header(struct beacon_header *beacon_header)
{
    unsigned int frameControl = htons(beacon_header->frame_control);
    return frameControl;
}


void dump_fixed_parameters(struct fixed_parameters *fixed_parameters){
}

int dump_SSID_parameter(struct tag_SSID_parameter *tag_SSID_parameter){
    unsigned int len = tag_SSID_parameter->len;
    return len;
}

int dump_supported_rates(struct tag_supported_rates *tag_supported_rates){
    unsigned int len = tag_supported_rates->len;
    return len;
}

int dump_DS_parameter(struct tag_DS_parameter *tag_DS_parameter){
    unsigned int len = tag_DS_parameter->len;
    return len;
}
