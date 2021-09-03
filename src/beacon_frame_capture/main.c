#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include "beacon.c"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define NULL "\0"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void* thread_channel(void * dev){   //1초마다 채널을 변경해주는 함수
    int cnt = 1;
    while(1){
            char command[100];
            if (cnt>13) cnt=1;
            sprintf(command, "iwconfig %s ch %d",(char *)dev, cnt);
            system(command);
            cnt++;
            sleep(1);
    }
}

void monitor(char *dev){    //랜카드 모니터 모드 설정
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

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    pthread_t thread;
    pthread_create(&thread, 0, thread_channel, dev);

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        //void * next_header_ptr;
        unsigned int radiotap_len, frame_control, SSID_len, support_len, DS_len;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);  //패킷의 총 길이

        radiotap_len = dump_radiotap((struct radiotap_header *)packet);
        packet += radiotap_len;
        frame_control = dump_beacon_header((struct beacon_header *)packet);
        if (frame_control == 0x8000){
            packet += 24;
            dump_fixed_parameters((struct fixed_parameters *) packet);
            packet += 12;
            SSID_len = dump_SSID_parameter((struct tag_SSID_parameter *) packet);
            packet += SSID_len + 2;
            support_len = dump_supported_rates((struct tag_supported_rates *) packet);
            packet += support_len + 2;
            DS_len = dump_DS_parameter((struct tag_DS_parameter *) packet);
            packet += DS_len + 2;
        }
        printf("\n\n");
    }
    pcap_close(pcap);
}
