#ifndef N_MAIN_H
#define N_MAIN_H
#include <iostream>
#include <fstream>
#include <signal.h>
#include "Class/Packet/n_tcp.h"
#include "Class/Packet/n_packet.h"
#include "Class/n_Pcap/n_pcap.h"
#include "Class/n_Pcap/n_pcap_data.h"

using namespace std;

// namespace for main
namespace MAIN {
    static n_Pcap_Data* file;
    static vector<uint16_t> ports;
    static const char* portFileName = "ports.ng";

    // signal handler for sigint
    [[ noreturn ]] void handler(int s) {
        cout << endl << "Signal Captured: " << s
             << endl << "Exporting to file..." << endl;
        file->exportToFile();
        exit(0);
    }

    bool readPortsFromFile() {
        try {
            ifstream is(portFileName, ios::in);
            if (!is.is_open())
                return false;
            uint16_t tmp;
            while(!is.eof()){
                is >> tmp;
                if (is.good())
                    ports.push_back(tmp);
            }
            is.close();
        } catch (exception& ex) {
           cerr << ex.what() << endl;
           return false;
        }
       return true;
    }

    void init() {
        // read ports from 'ports.ng'
        readPortsFromFile();

        // register signal handler
        signal(SIGINT, handler);
    }

}

using namespace MAIN;

#endif // N_MAIN_H
