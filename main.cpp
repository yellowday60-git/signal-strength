#include "radio.hpp"

#include <iostream>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <signal.h>
#include <cstring>

using namespace std;
bool con = true;

#define offset 12

void usage(){
    printf("syntax : signal-strength <interface> <mac>\n");
    printf("sample : signal-strength mon0 00:11:22:33:44:55\n");
    return;
}

void sig_handler(int signo){
    con = false;
    return;
}

int main(int argc, char* argv[]){
    if(argc != 3){
        usage();
        return 0;
    }

    Mac tar = Mac(argv[2]);

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
    signal(SIGINT,sig_handler);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            cout << "pcap_next_ex return "<<res<<'('<<pcap_geterr(handle)<<')'<<endl;
            break;
        }

        int8_t PWR = 0;
        
        PRadiotapHdr pRadioTapHeader;
        PBeacon pBeaconFrame;

        uint16_t radioHdrLength;
        uint32_t packetLength, tagLength;
        
        pRadioTapHeader = (PRadiotapHdr)packet;
        radioHdrLength = ntohs(pRadioTapHeader->it_len);
        pBeaconFrame = (PBeacon)((char *)packet + radioHdrLength);

        if(pBeaconFrame->type != beacon_frame::MANAGEMENT_FRAMES) continue;
        if(pBeaconFrame->subtype != beacon_frame::Beacon) continue;


        Mac BSSID;
        BSSID = pBeaconFrame->BSSID;
        tagLength = packetLength - radioHdrLength - sizeof(struct beacon_frame) - sizeof(struct fixed_param);

        if(pBeaconFrame->subtype != 0x80) continue;

        if (BSSID == tar){
            
            PWR = (int8_t)*((char *)pRadioTapHeader + sizeof(struct ieee80211_radiotap_header));
            cout << std::string(tar) << " " << PWR << endl;
        }
            


    }

    pcap_close(handle);
    return 0;
}