#include <stdio.h>
#include "beacon.h"

int dump_radiotap(struct radiotap_header *radiotap_header){
    unsigned int len = radiotap_header->len;
    printf("[Radiotap Length] : %d\n",len);
    return len;
}

int dump_beacon_header(struct beacon_header *beacon_header)
{
    unsigned int frameControl = htons(beacon_header->frame_control);
    unsigned char *smac = beacon_header->shost;
    unsigned char *dmac = beacon_header->dhost;
    unsigned char *bssid = beacon_header->bssid;
    if (frameControl==0x8000){
    printf("[FrameControl] : 0x%04x\n", frameControl);
    printf("[BEACON] : "\
        "%02x:%02x:%02x:%02x:%02x:%02x -> "\
        "%02x:%02x:%02x:%02x:%02x:%02x\n"\
        "[bssID] : %02x:%02x:%02x:%02x:%02x:%02x\n",
        smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
        dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    }
    return frameControl;
}


void dump_fixed_parameters(struct fixed_parameters *fixed_parameters){
    //printf("dump_fixed\n");
}

int dump_SSID_parameter(struct tag_SSID_parameter *tag_SSID_parameter){
    unsigned char *ssid = tag_SSID_parameter->ssid;
    unsigned int len = tag_SSID_parameter->len;
    unsigned int i;
    printf("[SSID] : ");
    for(i=0; i<len;i++){
        printf("%c",ssid[i]);
    }
    printf("\n");
    return len;
}

int dump_supported_rates(struct tag_supported_rates *tag_supported_rates){
    unsigned int len = tag_supported_rates->len;
    //printf("dump_supported\n");
    return len;
}

int dump_DS_parameter(struct tag_DS_parameter *tag_DS_parameter){
    unsigned int len = tag_DS_parameter->len;
    unsigned int channel = tag_DS_parameter->channel;
    printf("[Channel] : %d\n", channel);
    return len;
}
