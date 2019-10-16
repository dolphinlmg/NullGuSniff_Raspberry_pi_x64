#ifndef FRAME_H
#define FRAME_H
#include <stdint.h>
#include <cstring>
#include <string>
#include <pcap/pcap.h>

class n_Frame
{
public:
    n_Frame();
    n_Frame(uint8_t* data, pcap_pkthdr* header);
    n_Frame(const uint8_t* data, pcap_pkthdr* header);
    virtual ~n_Frame();
    uint32_t getLength() const ;
    void setFrameData(uint8_t* data, uint32_t len);
    void setFrameData(const uint8_t* data, uint32_t len);
    uint8_t* getFrameData() const ;
    void setFrameHeader(pcap_pkthdr* header);
    pcap_pkthdr* getFrameHeader();
    virtual std::string what() const { return "Frame"; } //return name of class

private:
    pcap_pkthdr* header;
    uint8_t* data;
};

#endif // FRAME_H
