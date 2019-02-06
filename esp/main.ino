extern "C" {
  #include <user_interface.h>
}

#define PATH_LOSS 2.7
#define TX_POWER 44. //RSSI with sender 1m from the ESP

#define DATA_LENGTH           112
#define CHANNEL_HOP_INTERVAL_MS   100


#define TYPE_MANAGEMENT                       0x00
#define TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST 0x04
#define TYPE_MANAGEMENT_SUBTYPE_BEACON        0x08

#define TYPE_CONTROL                          0x01
#define TYPE_CONTROL_SUBTYPE_BLOCKACK_REQ     0x08
#define TYPE_CONTROL_SUBTYPE_BLOCKACK         0x09

#define TYPE_DATA                             0x02
#define TYPE_DATA_SUBTYPE_DATA                0x04


struct RxControl {
 signed rssi:8; // signal intensity of packet
 unsigned rate:4;
 unsigned is_group:1;
 unsigned:1;
 unsigned sig_mode:2; // 0:is 11n packet; 1:is not 11n packet;
 unsigned legacy_length:12; // if not 11n packet, shows length of packet.
 unsigned damatch0:1;
 unsigned damatch1:1;
 unsigned bssidmatch0:1;
 unsigned bssidmatch1:1;
 unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
 unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
 unsigned HT_length:16;// if is 11n packet, shows length of packet.
 unsigned Smoothing:1;
 unsigned Not_Sounding:1;
 unsigned:1;
 unsigned Aggregation:1;
 unsigned STBC:2;
 unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
 unsigned SGI:1;
 unsigned rxend_state:8;
 unsigned ampdu_cnt:8;
 unsigned channel:4; //which channel this packet in.
 unsigned:12;
};

struct SnifferPacket{
    struct RxControl rx_ctrl;
    uint8_t data[DATA_LENGTH];
    uint16_t cnt;
    uint16_t len;
};
uint16_t num_packets = 0;

static int getDistance(int RSSI){

  int d = round(pow(10., (TX_POWER - RSSI) / (10. * PATH_LOSS)) / 1000.);
  return d;

}

static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length) {

  if (length == 12) return; //Unknown spurious frame
  struct SnifferPacket *snifferPacket = (struct SnifferPacket*) buffer;

  unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

  //uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
  uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

  if ((fromDS == 0) && (toDS == 0) && (frameType == 2) && (frameSubType == 1)) return; //Unknown spurious frame

  char addr1[] = "FF:FF:FF:FF:FF:FF";
  char addr2[] = "FF:FF:FF:FF:FF:FF";
  char addr3[] = "FF:FF:FF:FF:FF:FF";
  char addr4[] = "FF:FF:FF:FF:FF:FF";
  getMAC(addr1, snifferPacket->data, 2+2);
  getMAC(addr2, snifferPacket->data, 2+2+6);
  getMAC(addr3, snifferPacket->data, 2+2+6+6);
  char* BSSID = addr1;
  char* dest_addr = addr2;
  char* source_addr = addr3;
  /*
    Destination Address (DA) : Final recipient of the frame
    Source Address (SA) : Original source of the frame
    Receiver Address (RA) : Immediate receiver of the frame.
    Transmitter Address (TA) : Immediate sender of the frame.
*/
  if ((fromDS == 0) && (toDS == 0)) {
    /*
    Address 1: RA/DA (identical)
    Address 2: TA/SA (identical)
    Address 3: BSSID
    Address 4: n/a
    */
    dest_addr = addr1;
    source_addr = addr2;
    BSSID = addr3;

  } else if ((fromDS == 0) && (toDS == 1)) {
    /*
    Address 1: RA/BSSID (receiver is the AP which is the BSSID)
    Address 2: TA/SA (original station sending)
    Address 3: DA (end station)
    Address 4: n/a
    */
    BSSID = addr1;
    source_addr = addr2;
    dest_addr = addr3;
  
  } else if ((fromDS == 1) && (toDS == 0)) {
    /*
    Address 1: RA/DA (identical = end station)
    Address 2: TA/BSSID (transmitter is the AP, it is also the BSSID by the way)
    Address 3: SA (original station sending the frame)
    Address 4: n/a
    */
    dest_addr = addr1;
    BSSID = addr2;
    source_addr = addr3;
  
  } else if ((fromDS == 1) && (toDS == 1)) {
    /*
    Address 1: RA (end AP)
    Address 2: TA (first AP)
    Address 3: DA (end station)
    Address 4: SA (original station)
    */
    getMAC(addr4, snifferPacket->data, 2+2+6+6+6+2);
    BSSID = addr2;
    dest_addr = addr3;
    source_addr = addr4;  
  }



  Serial.print(source_addr);
  Serial.print(",");
  
  if (!String(dest_addr).equals("FF:FF:FF:FF:FF:FF") && !String(dest_addr).equals(source_addr) && !String(dest_addr).equals(BSSID))
    Serial.print(dest_addr);
  Serial.print(",");      

  if (!String(BSSID).equals("FF:FF:FF:FF:FF:FF") && 
      !String(BSSID).equals(source_addr) && 
      !String(BSSID).equals(dest_addr) &&
      !((frameType == TYPE_CONTROL) && (frameSubType == TYPE_CONTROL_SUBTYPE_BLOCKACK)) &&
      !((frameType == TYPE_CONTROL) && (frameSubType == TYPE_CONTROL_SUBTYPE_BLOCKACK_REQ)))
    Serial.print(BSSID);    
  Serial.print(",");      

  if ((frameType == TYPE_MANAGEMENT) && (frameSubType == TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST)) {
    uint8_t SSID_length = snifferPacket->data[25];
    printDataSpan(26, SSID_length, snifferPacket->data);
  } 
  
  Serial.print(",");
  
  Serial.print(wifi_get_channel(), DEC);
  Serial.print(",");
  
  Serial.print(snifferPacket->rx_ctrl.rssi, DEC);
  Serial.print(",");
  
  Serial.print(getDistance(snifferPacket->rx_ctrl.rssi), DEC);


  Serial.print(",");
  Serial.print(fromDS, DEC);
  
  Serial.print(",");
  Serial.print(toDS, DEC);

  Serial.print(",");
  Serial.print(frameType, DEC);
  
  Serial.print(",");
  Serial.print(frameSubType, DEC);

  

  Serial.println();
  
}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data) {
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    Serial.write(data[i]);
  }
}

static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);
}


static os_timer_t channelHop_timer;

void channelHop()
{
  uint8 new_channel = wifi_get_channel() + 1;
  if (new_channel > 13)
    new_channel = 1;
  wifi_set_channel(new_channel);
}

#define DISABLE 0
#define ENABLE  1

void setup() {

  //Serial.begin(115200);
  Serial.begin(230400);
  //Serial.begin(460800);
  //Serial.begin(921600);
  //Serial.begin(1500000);
  //Serial.begin(2000000);
  delay(10);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(1);
  wifi_promiscuous_enable(DISABLE);
  delay(10);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  delay(10);
  wifi_promiscuous_enable(ENABLE);

  Serial.print("Starting\n");
  os_timer_disarm(&channelHop_timer);
  os_timer_setfn(&channelHop_timer, (os_timer_func_t *) channelHop, NULL);
  os_timer_arm(&channelHop_timer, CHANNEL_HOP_INTERVAL_MS, 1);
}

void loop() {
  delay(10);
}
