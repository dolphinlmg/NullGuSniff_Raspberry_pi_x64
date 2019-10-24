#include "n_main.h"

int main() {
    n_Pcap wlan0("wlan0");
    n_Pcap dummy("dum0");

    file = new n_Pcap_Data("./test.pcap");

    init();

    while (true){
        n_Frame* packet;
        int res = wlan0 >> packet;
        if (res == 0) continue;
        else if (res == -1 || res == -2) break;

        // dump packet data
        cout << packet;

        // continue if packet has filtered ports
        if (packet->what() == "TCP") {
            n_TCP* tmp = dynamic_cast<n_TCP*>(packet);
            if (tmp->isFilteredPort(ports)) continue;
        }
        // only not filtered packet

        // send to another interface
        dummy << packet;

        // push&save packet
        *file << packet;
    }
    return 0;
}
