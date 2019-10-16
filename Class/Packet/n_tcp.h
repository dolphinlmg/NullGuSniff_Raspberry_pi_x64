#ifndef N_TCP_H
#define N_TCP_H
#include <netinet/tcp.h>
#include "n_ip.h"

class n_TCP : public n_IP
{
public:
    n_TCP(uint8_t* data, pcap_pkthdr* header);
    n_TCP(const uint8_t* data, pcap_pkthdr* header);
    tcphdr* getTcpData() const;
    uint32_t getSizeOfTcpHeader() const;
    bool isTLS() const ;
    std::string what() const override { return "TCP"; }
    //TODO: Add Methods

private:
    tcphdr* tcp_data;
};

#endif // N_TCP_H
