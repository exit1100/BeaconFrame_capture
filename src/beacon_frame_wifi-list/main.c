#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include "beacon.c"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NULL "\0"
#define EHTERNET_LEN 24
#define FIXED_PARAM_LEN 12
#define FIELD_JUMP_LEN 2

struct wifiList{
    unsigned char SSID[32];
    unsigned char BSSID[6];
    unsigned int channel;
};
struct wifiList wifi_list[500];
int count = 0;  //와이파이 목록 개수


void list(){    //와이파이 목록 출력 함수
    int i;
    unsigned char bssid[20];
    if (count == 0){
        printf("검색된 Wi-fi가 없습니다. \n\n");
    }else{
        printf("\n SSID \t\t\t\t   BSSID\t\t Channel\n");
        printf("-------------------------------------------------------------------------------\n");
        for (i = 0; i < count; i++){
            sprintf(&bssid, "%02x:%02x:%02x:%02x:%02x:%02x", wifi_list[i].BSSID[0], wifi_list[i].BSSID[1], wifi_list[i].BSSID[2],
                                                            wifi_list[i].BSSID[3], wifi_list[i].BSSID[4], wifi_list[i].BSSID[5]);
            printf(" %-32s  %s\t %d\n", wifi_list[i].SSID, bssid,  wifi_list[i].channel);
        }
    }
}

int search(unsigned char * BSSID){  //이미 목록에 있는 와이파이인지 확인하는 함수
    char bssid[20];
    char bssid_compare[20];
    sprintf(&bssid, "%02x:%02x:%02x:%02x:%02x:%02x", BSSID[0], BSSID[1], BSSID[2], BSSID[3], BSSID[4], BSSID[5]);
    for(int i=0; i<100; i++){
        sprintf(&bssid_compare, "%02x:%02x:%02x:%02x:%02x:%02x", wifi_list[i].BSSID[0], wifi_list[i].BSSID[1], wifi_list[i].BSSID[2],
                                                        wifi_list[i].BSSID[3], wifi_list[i].BSSID[4], wifi_list[i].BSSID[5]);
        if(strcmp(bssid,bssid_compare)==0){
            return 2;
        }
    }
    return 1;
}

void append(unsigned char * SSID, unsigned char * BSSID, int channel){  //와이파이 목록에 추가하는 함수
    count++;
    memcpy(wifi_list[count-1].SSID,SSID,32);
    unsigned int i;
    for (i=0;i<6;i++) wifi_list[count-1].BSSID[i] = BSSID[i];
    wifi_list[count-1].channel = channel;
}


void usage(){
    printf("syntax: ./beacon_frame_wifi-list <interface>\n");
    printf("sample: ./beacon_frame_wifi-list wlan0\n");
}

void* thread_channel(void * dev){   //모든 채널의 와이파이 패킷을 받기 위해 1초마다 채널을 변경
    int cnt = 1;
    while(1){
            char command[100];
            if (cnt>13) cnt=1;
            sprintf(command, "iwconfig %s ch %d", (char *)dev, cnt);
            system(command);
            cnt++;
            sleep(1);
    }
}

void monitor(char *dev){    //랜카드 모니터 모드로 변경 함수
    char command[50];
    if(strlen(dev)>20){
        printf("interface name length less than 20 characters");
        exit(0);
    }
    sprintf(command, "ifconfig %s down",dev);
    system(command);
    sprintf(command, "iwconfig %s mode monitor",dev);
    system(command);
    sprintf(command, "ifconfig %s up",dev);
    system(command);
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 0;
    }
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    monitor(dev);
    pthread_t thread;
    pthread_create(&thread, 0, thread_channel, dev);

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        unsigned int radiotap_len, frame_control, SSID_len, support_len, DS_len, channel, i;
        unsigned char SSID_str[32];
        unsigned char BSSID_str[6];

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);

        radiotap_len = dump_radiotap((struct radiotap_header *)packet);
        packet += radiotap_len;
        frame_control = dump_beacon_header((struct beacon_header *)packet);
        struct beacon_header * BSSID = (struct beacon_header *)packet;
        for(i=0;i<6;i++) {
            BSSID_str[i] = BSSID->bssid[i];
        }
        if (frame_control == 0x8000){   //beacon frame
            packet += EHTERNET_LEN;
            dump_fixed_parameters((struct fixed_parameters *) packet);
            packet += FIXED_PARAM_LEN;
            SSID_len = dump_SSID_parameter((struct tag_SSID_parameter *) packet);

            //SSID를 배열에 저장하는 부분
            struct tag_SSID_parameter * SSID = (struct tag_SSID_parameter *) packet;
            for(i=0;i<SSID_len;i++) SSID_str[i] = SSID->ssid[i];
            SSID_str[SSID_len] = '\0';
            if (SSID_str[0] == '\0') continue;

            packet += SSID_len + FIELD_JUMP_LEN;
            support_len = dump_supported_rates((struct tag_supported_rates *) packet);
            packet += support_len + FIELD_JUMP_LEN;
            DS_len = dump_DS_parameter((struct tag_DS_parameter *) packet);
            struct tag_DS_parameter * DS = (struct tag_DS_parameter *) packet;
            channel = DS->channel;  //현 패킷의 와이파이 채널을 저장
            if (search(BSSID_str)==1){  //1을 리턴하면 현재 와이파이 목록에 없는 BSSID 이므로, 추가해서 목록을 재출력
                append(SSID_str, BSSID_str, channel);
                system("clear");
                list();
            }
        }
    }
    pcap_close(pcap);
}
