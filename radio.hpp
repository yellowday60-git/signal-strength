#pragma once

#include <iostream>
#include "mac.h"
#include <netinet/in.h>

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
    uint8_t it_version;     // radiotap version, always 0
    uint8_t it_pad;         // padding (or alignment)
    uint16_t it_len;        // overall radiotap header length
    uint32_t it_present;    // (first) present word;
} __attribute__((__packed__));
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_frame {
    uint8_t version:2;
    enum {
        MANAGEMENT_FRAMES       = 0,    // 802.11 Management Frames
        CONTROL_FRAMES          = 1,    // 802.11 Control Frames
        DATA_FRAMES             = 2     // 802.11 Data Frames
    } type:2;
    enum {

        //  Management Frames
        Association_request     = 0,
        Association_response    = 1,
        Reassociation_request   = 2,
        Reassociation_response  = 3,
        Probe_request           = 4,
        Probe_response          = 5,
        Timing_Advertisemant    = 6,
        Beacon                  = 8,
        ATIM                    = 9,
        Disassociation          = 10,
        Authentication          = 11,
        Deauthentication        = 12,
        Action                  = 13,
        Action_no_ack           = 14,

        // Control Frames
        Beamforming_report_poll = 4,
        VHT_NDP_Announcement    = 5,
        Control_wrapper         = 7,
        Block_ACK_request       = 8,
        Block_ACK               = 9,
        PS_Poll                 = 10,
        Ready_To_Send           = 11,
        Clear_To_Send           = 12,
        ACK                     = 13,
        CF_End                  = 14,
        CF_End_CF_Ack           = 15,

        //  Data Frames
        Data                    = 0,
        Data_CF_Ack             = 1,
        Data_CF_Poll            = 2,
        Data_CF_Ack_CF_Poll     = 3,
        Null                    = 4,
        CF_Ack                  = 5,
        CF_Poll                 = 6,
        CF_Ack_CF_Poll          = 7,
        QoS_Data                = 8,
        QoS_Data_CF_Ack         = 9,
        QoS_Data_CF_Poll        = 10,
        QoS_Data_CF_Ack_CF_Poll = 11,
        QoS_Null                = 12,
        QoS_CF_Poll             = 14,
        QoS_CF_Ack_CF_Poll      = 15
    } subtype:4;

    uint8_t flags;
    uint16_t duration;
    uint8_t destMAC[6];
    uint8_t srcMAC[6];
    uint8_t BSSID[6];

    uint16_t fragNum:4, seqNum:12;

} __attribute__((__packed__));
#pragma pack(pop)

#pragma pack(push, 1)
struct Dot11 {
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;
    uint16_t duration;
    Mac addr1_;
    Mac addr2_;
    Mac addr3_;
    uint8_t frag:4;
    uint16_t seq:12;

    enum Type: uint8_t {
        MANAGEMENT_FRAMES       = 0,
        CONTROL_FRAMES          = 1, 
        DATA_FRAMES             = 2, 
        EXTENSION_FRAME         = 3 
    };

    enum Subtype: uint8_t {

        Association_request     = 0x0,
        Association_response    = 0x1,
        Reassociation_request   = 0x2,
        Reassociation_response  = 0x3,
        Probe_request           = 0x4,
        Probe_response          = 0x5,
        Timing_Advertisemant    = 0x6,
        Beacon                  = 0x8,
        ATIM                    = 0x9,
        Disassociation          = 0xa,
        Authentication          = 0xb,
        Deauthentication        = 0xc,
        Action                  = 0xd,
        Action_no_ack           = 0xe,

        Beamforming_report_poll = 0x14,
        VHT_NDP_Announcement    = 0x15,
        Control_frame_extension = 0x16,
        Control_wrapper         = 0x17,
        Block_ACK_request       = 0x18,
        Block_ACK               = 0x19,
        PS_Poll                 = 0x1a,
        Ready_To_Send           = 0x1b,
        Clear_To_Send           = 0x1c,
        ACK                     = 0x1d,
        CF_End                  = 0x1e,
        CF_End_CF_Ack           = 0x1f,

        Data                    = 0x20,
        Data_CF_Ack             = 0x21,
        Data_CF_Poll            = 0x22,
        Data_CF_Ack_CF_Poll     = 0x23,
        Null                    = 0x24,
        CF_Ack                  = 0x25,
        CF_Poll                 = 0x26,
        CF_Ack_CF_Poll          = 0x27,
        QoS_Data                = 0x28,
        QoS_Data_CF_Ack         = 0x29,
        QoS_Data_CF_Poll        = 0x2a,
        QoS_Data_CF_Ack_CF_Poll = 0x2b,
        QoS_Null                = 0x2c,
        QoS_CF_Poll             = 0x2e,
        QoS_CF_Ack_CF_Poll      = 0x2f,

        DMG_Beacon              = 0x30,
        S1G_Beacon              = 0x31
    };

    Mac getReceiverMac() const { return addr1_; }
    Mac getTargetMac() const { return addr2_; }
    Mac getBSSID() const { return addr3_; }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fixed_param {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_information;
} __attribute__((__packed__));

typedef struct fixed_manage_frame* PFixedManageFrame;
typedef struct ieee80211_radiotap_header* PRadiotapHdr;
typedef struct beacon_frame* PBeacon;
typedef struct Dot11* PDot11;