#include "n_main.h"

int main() {
    n_Pcap eth1("eth1");
    n_Pcap eth0("eth0");

    file = new n_Pcap_Data("./test.pcap");

    init();

    while (true){
        // get next packet from interfaces
        n_Frame *input, *output;
        int input_res = eth1 >> input;
        int output_res = eth0 >> output;

        // break if error occured
        if (input_res == -1 || input_res == -2 || output_res == -1 || output_res == -2) break;

        // if input packet captured
        if (input_res != 0) {
            cout << input;
	    dynamic_cast<n_Ethernet*>(input)->setEthDst(reinterpret_cast<const uint8_t*>("\xff\xff\xff\xff\xff\xff"));
            if (input->what() == "TCP"){
                n_TCP* input_tcp = dynamic_cast<n_TCP*>(input);

                if (!input_tcp->isFilteredDstPort(ports)) {
                    input_tcp->setIPSrc(parseIP("172.203.0.22"));
                    input_tcp->setProferChecksum();
                }
            } else if (input->what() == "IP") {
		n_IP* input_ip = dynamic_cast<n_IP*>(input);
            if (input_ip->getIPData()->protocol == 1) {
                    string a;
                    cin >> a;
                }
		input_ip->setIPSrc(parseIP("172.203.0.22"));
		input_ip->setProferIPChecksum();
	    }
            cout << input;
            eth0 << input;
            *file << input;
        }
        // if output packet captured
        if (output_res != 0) {
            cout << output;
	    dynamic_cast<n_Ethernet*>(output)->setEthDst(reinterpret_cast<const uint8_t*>("\xff\xff\xff\xff\xff\xff"));
            if (output->what() == "TCP"){
                n_TCP* output_tcp = dynamic_cast<n_TCP*>(output);

                if (!output_tcp->isFilteredPort(ports)) {
                    output_tcp->setIPSrc(parseIP("172.24.1.102"));
                    output_tcp->setProferChecksum();
                }
            } else if (output->what() == "IP") {
		n_IP* output_ip = dynamic_cast<n_IP*>(output);

            if (output_ip->getIPData()->protocol == 1) {
                    string a;
                    cin >> a;
                }

        output_ip->setIPSrc(parseIP("172.24.1.102"));
		output_ip->setProferIPChecksum();
	    }

            cout << output;
            eth1 << output;
            *file << output;
        }
    }
    return 0;
}
