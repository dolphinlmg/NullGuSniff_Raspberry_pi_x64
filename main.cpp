#include "n_main.h"

int main() {
    n_Pcap pcap_1("eth0");
    //n_Pcap dummy("dum0");
    file = new n_Pcap_Data("./test.pcap");

    // register signal interrupt handler
    signal(SIGINT, &handler);

    while (true){
        // get next packet from wlp0s20f3
        int res = pcap_1.getNextPacket();
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // get appropriate object
        n_Frame* packet = pcap_1.recognizePacket();

        cout << packet->what() << endl
             << n_Packet::dumpPacket(packet->getFrameData(), packet->getLength()) << endl;

        if (packet->what() == "TCP") {
            if (dynamic_cast<n_TCP*>(packet)->isTLS()) {
                file->push_packet(packet);
                //dummy.sendPacket(packet->getFrameData(), packet->getLength());
            }
        }
    }
    return 0;
}
