#include "n_frame.h"

// default constructor setting data to nullptr
n_Frame::n_Frame() { this->data = nullptr; }

// constructor with uint8_t*
n_Frame::n_Frame(uint8_t* data, pcap_pkthdr* header) {
    this->data = new uint8_t [header->len];
    if (this->data != nullptr)
        memcpy(this->data, data, static_cast<size_t>(header->len));
    this->header = new pcap_pkthdr;
    memcpy(this->header, header, sizeof(pcap_pkthdr));
}

// constructor with const uint8_t*
n_Frame::n_Frame(const uint8_t* data, pcap_pkthdr* header) {
    this->data = new uint8_t [header->len];
    if (this->data != nullptr)
        memcpy(this->data, data, static_cast<size_t>(header->len));
    this->header = new pcap_pkthdr;
    memcpy(this->header, header, sizeof(pcap_pkthdr));
}

//destructor: delete[] data
n_Frame::~n_Frame(){
    if (this->data != nullptr)
        delete[] this->data;
}

uint32_t n_Frame::getLength() const {
    return this->header->len;
}

// set length of packet
void n_Frame::setFrameHeader(pcap_pkthdr* header){
    this->header = new pcap_pkthdr;
    memcpy(this->header, header, sizeof(pcap_pkthdr));
}

// set data with uint8_t*
void n_Frame::setFrameData(uint8_t* data, uint32_t len){
    if (this->data != nullptr){
        delete[] this->data;
    }
    this->data = new uint8_t [len];
    memcpy(this->data, data, static_cast<size_t>(len));
}

// set data with const uint8_t*
void n_Frame::setFrameData(const uint8_t* data, uint32_t len){
    if (this->data != nullptr){
        delete[] this->data;
    }
    this->data = new uint8_t [len];
    memcpy(this->data, data, static_cast<size_t>(len));
}

// return data
uint8_t* n_Frame::getFrameData() const {
    return this->data;
}

pcap_pkthdr* n_Frame::getFrameHeader() {
    return this->header;
}
