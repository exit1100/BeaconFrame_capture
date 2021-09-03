#ifndef BEACON_H
#define BEACON_H

#include <stdint.h>

struct radiotap_header {
    uint8_t     version;     /* set to 0 */
    uint8_t     pad;
    uint16_t    len;         /* entire length */
    uint32_t    present;     /* fields present */
} __attribute__((__packed__));

struct beacon_header{
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t dhost[6];  //목적지 주소
    uint8_t shost[6];  //출발지 주소
    uint8_t bssid[6];
    uint16_t squence_control;
} __attribute__ ((__packed__));

struct fixed_parameters{
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capacity_info;
} __attribute__ ((__packed__));

struct tag_SSID_parameter{
    uint8_t element_id;
    uint8_t len;
    uint8_t ssid[32];
} __attribute__ ((__packed__));

struct tag_supported_rates{
    uint8_t number;
    uint8_t len;
    uint8_t rates;
} __attribute__ ((__packed__));

struct tag_DS_parameter{
    uint8_t number;
    uint8_t len;
    uint8_t channel;
} __attribute__ ((__packed__));

int dump_radiotap(struct radiotap_header *radiotap_header);
int dump_beacon_header(struct beacon_header *beacon_header);
void dump_fixed_parameters(struct fixed_parameters *fixed_parameters);
int dump_SSID_parameter(struct tag_SSID_parameter *tag_SSID_parameter);
int dump_supported_rates(struct tag_supported_rates *tag_supported_rates);
int dump_DS_parameter(struct tag_DS_parameter *tag_DS_parameter);

#endif // BEACON_H
