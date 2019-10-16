#ifndef N_MAIN_H
#define N_MAIN_H
#include <iostream>
#include <signal.h>
#include "Class/Packet/n_tcp.h"
#include "Class/Packet/n_packet.h"
#include "Class/n_Pcap/n_pcap.h"
#include "Class/n_Pcap/n_pcap_data.h"

using namespace std;

// namespace for main
namespace MAIN {
    static n_Pcap_Data* file;

    // signal handler for sigint
    [[ noreturn ]] void handler(int s) {
        cout << endl << "Signal Captured: " << s
             << endl << "Exporting to file..." << endl;
        file->exportToFile();
        exit(0);
    }
}

using namespace MAIN;

#endif // N_MAIN_H
