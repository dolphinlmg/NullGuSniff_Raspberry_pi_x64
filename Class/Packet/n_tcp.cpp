#include "n_tcp.h"
#include <iostream>

// constructor with uint8_t*
n_TCP::n_TCP(uint8_t* data, pcap_pkthdr* header) : n_IP(data, header) {
    this->tcp_data = reinterpret_cast<tcphdr*>(reinterpret_cast<uint8_t*>(this->getIPData()) + this->getSizeOfIPHeader());
}

// constructor with const uint8_t*
n_TCP::n_TCP(const uint8_t* data, pcap_pkthdr* header) : n_IP(data, header) {
    this->tcp_data = reinterpret_cast<tcphdr*>(reinterpret_cast<uint8_t*>(this->getIPData()) + this->getSizeOfIPHeader());
}

// return tcphdr*
tcphdr* n_TCP::getTcpData() const {
    return this->tcp_data;
}

// return size of tcp header
uint32_t n_TCP::getSizeOfTcpHeader() const {
    return unsigned(this->tcp_data->th_off << 2);
}

// return is this packet is tls
bool n_TCP::isTLS() const {
    if (this->getLength() == sizeof(ethhdr) + this->getSizeOfIPHeader() + this->getSizeOfTcpHeader())
        return false;
    uint8_t* tmp = reinterpret_cast<uint8_t*>(this->getTcpData()) + this->getSizeOfTcpHeader();
    return (*tmp >= 0x14) && (*tmp <= 0x17);
}
