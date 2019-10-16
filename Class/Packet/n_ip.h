#ifndef n_IP_H
#define n_IP_H
#include <netinet/ip.h>
#include "n_ethernet.h"

class n_IP : public n_Ethernet
{
public:
    n_IP(uint8_t* data, pcap_pkthdr* header);
    n_IP(const uint8_t* data, pcap_pkthdr* header);
    iphdr* getIPData() const ;
    uint32_t getDst() const ;
    void setDst(uint32_t addr);
    uint32_t getSrc() const ;
    void setSrc(uint32_t addr);
    uint8_t getProtocol() const ;
    uint32_t getSizeOfIPHeader() const ;
    std::string what() const override { return "IP"; }

private:
    iphdr* ip_data;
};

#endif // n_IP_H
