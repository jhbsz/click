#ifndef CLICK_GATEWAY_SELECTOR_HH
#define CLICK_GATEWAY_SELECTOR_HH
#include <click/element.hh>
#include <click/string.hh>
#include <click/timer.hh>

#include <time.h>

#include <set>
#include <vector>
#include <string>

CLICK_DECLS

/*
 * =c
 * GatewaySelector()
 * =d
 * Assumes input packets are layer 3 packets with L2 header stripped.
 * The correct gateway is decided on the basis of metrics that were collected
 * over time. It also frames the packet with the correct L2 header as it has the
 * IP ETH mapping available for use. Handles packets destined for local networks
 * differently than the ones meant for remote computers. 
 * Input [0] -> Supply packet meant for remote network whose gateway is set.
 * Input [1] -> Supply L2 broadcast packets which contain information about gates.
 * Output[0] -> Output the framed packets which can directly be sent to a ToDevice()
 * Output[1] -> Packets whose annotations couldn't be sent. Usually aimed for a Discard
 *              but useful for debugging.
 */

#define WIFI_FC0_SUBTYPE_ACTION   0xd0

class GatewaySelector : public Element {

public:

    GatewaySelector();
    ~GatewaySelector();

    const char *class_name() const		{ return "GatewaySelector"; }
    const char *port_count() const		{ return "3/2"; }
    const char *processing() const		{ return PUSH; }

    int configure(Vector<String> &, ErrorHandler *);
  
    int initialize(ErrorHandler *errh);
    void run_timer(Timer *timer);
    void push(int port, Packet *p);

    bool _print_anno;
    bool _print_checksum;
    bool _timestamp;

private:
    String _label;

    struct GateInfo {
	std::string mac_address;
	std::string ip_address;
	time_t timestamp;
	// int metric;
	};
    
    struct PortCache {
        uint16_t src_port;
        IPAddress gate_ip;
        time_t timestamp;
	}; 
    
    std::vector<GateInfo> gates;
    std::vector<PortCache> port_cache_table;
  
    Timer _master_timer;
 
    std::string interface_mac_address;
		
    void process_pong(Packet *p);
    void process_antipong(Packet * p);
    Packet * select_gate(Packet *p);
    IPAddress cache_lookup(uint16_t);
    Packet * set_ip_address(Packet *, IPAddress);
    IPAddress find_gate(uint16_t);
    void cache_update(uint16_t, IPAddress);
    };

CLICK_ENDDECLS
#endif
