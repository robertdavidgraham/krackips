#ifndef DETECT_H
#define DETECT_H
#include <time.h>

struct Detect
{
    struct {
        time_t time_stamp;
        int dbm;
        unsigned channel;
    } kludge;

};

typedef unsigned char mac_addr_t[6];

typedef struct ssid_t {
    size_t length;
    unsigned char value[512];
} ssid_t;


void detect_associate_request(struct Detect *detect, const mac_addr_t bssid, const mac_addr_t client);
void detect_associate_response(struct Detect *detect, const mac_addr_t bssid, const mac_addr_t client);
void detect_ssid(struct Detect *detect, const mac_addr_t bssid, const ssid_t *ssid);

enum {
	ENC_TYPE_WEP	= 1,
	ENC_TYPE_WEP40	= 2,
	ENC_TYPE_WEP128	= 4,
	ENC_TYPE_WPA	=0x0008,
	ENC_TYPE_WPA2	=0x0010,
	ENC_TYPE_WPAu	=0x0020,
	CIPHER_TYPE_WEP	=0x0040,
	CIPHER_TYPE_TKIP=0x0080,
	CIPHER_TYPE_AES =0x0100,
	AUTH_TYPE_OPEN	=0x0400,
	AUTH_TYPE_SKA	=0x0800,
	AUTH_TYPE_EAP	=0x1000,
	AUTH_TYPE_PSK	=0x2000,
	AUTH_TYPE_MGMT	=0x4000,
};

#endif
