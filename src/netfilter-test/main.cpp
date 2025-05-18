#include "../../include/iphdr.hpp"
#include "../../include/tcphdr.hpp"

#include <iostream>
#include <cstdint>
#include <exception>
#include <string>

extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}

#include <glog/logging.h>

#define RECV_BUF_SIZE           4096
#define PKT_BUFF_EXTRA_MEM      512

#define HTTP                    80

using namespace std;

void usage();
bool parse(int argc);
static int cb(nfq_q_handle* qh, nfgenmsg* nfmsg, nfq_data* nfa, void* data);

int main(int argc, char* argv[]) {
    if(!parse(argc)) return -1;

    //unordered_map<

    nfq_handle* h{};
    nfq_q_handle* qh{};
    int socket{};

    alignas(RECV_BUF_SIZE) char buf[RECV_BUF_SIZE]{};

    try {
        h = nfq_open();

        if(!h) throw runtime_error("Failed to call nfq_open");
        if(nfq_unbind_pf(h, AF_INET) < 0) throw runtime_error("Failed to call nfq_unbind_pf");
        if(nfq_bind_pf(h, AF_INET) < 0) throw runtime_error("Failed to call nfq_bind_pf");

        // NFQNL_COPY_NONE - noop, do not use it
        // NFQNL_COPY_META - copy only packet metadata
        // NFQNL_COPY_PACKET - copy entire packet
        if(!(qh = nfq_create_queue(h, 0, &cb, argv[1]))) throw runtime_error("Failed to call nfq_create_queue");
        if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) throw runtime_error("Failed to call nfq_set_mode");

        socket = nfq_fd(h);

        int ret{};

        while(1) {
            ret = recv(socket, buf, sizeof(buf), 0);
            if(ret < 0) throw runtime_error("Failed to call recv" + errno);
            if(ret == 0) {
                cout<<"The connection was closed."<<endl;
                break;
            }


            nfq_handle_packet(h, buf, ret);
        }
    }catch(const exception& e) {
        cerr<<"[main] "<<e.what()<<endl;
    }

    nfq_destroy_queue(qh);
    nfq_unbind_pf(h, AF_INET);
    nfq_close(h);
}

void usage() {
    printf("syntax : netfilter-test <host> \n");
    printf("sample : netfilter-test test.gilgil.net \n");
}

bool parse(int argc) {
    if(argc < 2) {
        usage();
        return false;
    }

    return true;
}

int cb(nfq_q_handle* qh, nfgenmsg* nfmsg, nfq_data* nfa, void* data) {
    int id = 0;
    try {
        nfqnl_msg_packet_hdr* hdr = nfq_get_msg_packet_hdr(nfa);
        if(hdr == nullptr) throw runtime_error("Failed to call nfqnl_msg_packet_hdr");

        id = ntohl(hdr->packet_id);

        uint8_t* pData{};
        uint32_t pLen{};

        if((pLen = nfq_get_payload(nfa, &pData)) == -1) throw runtime_error("Failed to call nfq_get_payload");

        pkt_buff* buf = pktb_alloc(AF_INET, pData, pLen, PKT_BUFF_EXTRA_MEM);
        if(buf == nullptr) throw runtime_error("Failed to call pktb_alloc");

        PIpHdr ipHdr = reinterpret_cast<PIpHdr>(nfq_ip_get_hdr(buf));
        if(nfq_ip_set_transport_header(buf, reinterpret_cast<iphdr*>(ipHdr)) == 0) {
            PTcpHdr tcpHdr = reinterpret_cast<PTcpHdr>(nfq_tcp_get_hdr(buf));
            if(tcpHdr == nullptr) throw runtime_error("Failed to call nfq_tcp_get_hdr");
            //LOG(INFO)<<"this packet is tcp :) \n";

            if(tcpHdr->sPort() == HTTP || tcpHdr->dPort() == HTTP) {
                static constexpr char httpHostCheck[] = "Host: ";
                static constexpr char httpHeaderEndCheck[] = "\r\n";

                uint8_t* payloadPtr{};
                uint32_t payloadSize{};
                int sPos{}, ePos{};

                if((payloadPtr = reinterpret_cast<uint8_t*>(nfq_tcp_get_payload(reinterpret_cast<tcphdr*>(tcpHdr), buf))) == nullptr)
                    throw runtime_error("Failed to call nfq_tcp_get_payload");

                if((payloadSize = nfq_tcp_get_payload_len(reinterpret_cast<tcphdr*>(tcpHdr), buf)) <= 0)
                    throw runtime_error("Failed to call nfq_tcp_get_payload_len");

                string planeText(reinterpret_cast<const char*>(payloadPtr), payloadSize);


                if((sPos = planeText.find(httpHostCheck)) < 0) throw runtime_error("Failed to call find start pos");
                if((ePos = planeText.find(httpHeaderEndCheck, sPos)) < 0) throw runtime_error("Failed to call find end pos");

                string host = planeText.substr(sPos + sizeof(httpHostCheck) - 1, ePos - sPos - sizeof(httpHostCheck) + 1);

                if(host.find(reinterpret_cast<char*>(data)) != -1) {
                    LOG(INFO)<<"PACKET DROP"<<endl;
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
            }
        }
    }catch(const exception& e) {
        LOG(WARNING)<<"[cb] "<<e.what();
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}
