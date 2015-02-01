#include <click/config.h>
#include <click/ipaddress.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include "gatewayselector.hh"

#include <string>

CLICK_DECLS

#define GATES_REFRESH_INTERVAL 6000 // in seconds
#define STALE_ENTRY_THRESHOLD 6000 //in seconds

std::string mac_to_string(uint8_t address[])
{
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
         address[0], address[1], address[2], address[3], address[4], address[5]);
  return std::string(macStr);
}

std::string ip_to_string(uint8_t ip[])
{
	char ipStr[16];
	sprintf(ipStr, "%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
	return std::string(ipStr);
}

void string_to_mac(std::string mac_string, uint8_t address[])
{
  sscanf(mac_string.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
					(unsigned int *)&address[0], (unsigned int *)&address[1], (unsigned int *)&address[2], 
				  (unsigned int *)&address[3], (unsigned int *)&address[4], (unsigned int *)&address[5]);
}


GatewaySelector::GatewaySelector()
    : _print_anno(false),
      _print_checksum(false),
      _master_timer(this)
{
  // _label = "";
  //   click_chatter("Inside constructor. Leaving now \n");
}

GatewaySelector::~GatewaySelector()
{
}

int GatewaySelector::initialize(ErrorHandler *)
{
  //click_chatter("Initialize inside.");
  _master_timer.initialize(this);
  _master_timer.schedule_now();
  return 0;
}

void GatewaySelector::run_timer(Timer *timer)
{
		assert(timer == &_master_timer);
		
		std::vector<GateInfo>::iterator it;
		for(it = gates.begin(); it != gates.end(); ++it) {
		  
		  if(((*it).timestamp - time(NULL)) > STALE_ENTRY_THRESHOLD)
		    {
		      //click_chatter("Removing gate %s\n", (*it).ip_address.c_str());
		      it = gates.erase(it);
		    }
		}

		std::vector<PortCache>::iterator iter;
		for(iter = port_cache_table.begin(); iter != port_cache_table.end(); ++iter) {
		  
		  if(((*iter).timestamp - time(NULL)) > STALE_ENTRY_THRESHOLD)
		    {
		      //click_chatter("Removing entry for port no. %d\n", (*iter).src_port);
		      iter = port_cache_table.erase(iter);
		    }
		}
		
		_master_timer.reschedule_after_sec(GATES_REFRESH_INTERVAL);		
}

int
GatewaySelector::configure(Vector<String> &conf, ErrorHandler* errh)
{
  int ret;
\
  //click_chatter("Inside configure. ");
  
  _timestamp = false;
  ret = Args(conf, this, errh)
      .read_p("LABEL", _label)
      .read("TIMESTAMP", _timestamp)
      .complete();
  return ret;
}

void GatewaySelector::process_pong(Packet * p)
{
  // process pong here
  // 1. extract mac, ip and metric in pong
  // 2. look for mac as key in unresolved_gates map
  // 3. update the corresponding gate_info structure.
  // 4. Remove the gate_info struct from unresolved and put it in resolved.
	uint8_t src_mac[6], src_ip[4];	
	uint8_t *ptr = NULL;

	//click_chatter("Inside process_pong\n");

	if(p->has_mac_header()) {
		ptr = (uint8_t *)p->mac_header();
		//Skip destination as it should be a broadcast address
		ptr+= 6;
		//Skip to source mac address
		for(int i=0; i<6; i++) {
			src_mac[i] = *ptr;
			ptr++;
		}

		//skip protocol code
		ptr+=2;
		//extract ipv4
		for(int i=0; i<4; i++) {
			src_ip[i] = *ptr;
			ptr++;
		}
		
		std::string src_mac_string = mac_to_string(src_mac);
		std::string src_ip_string = ip_to_string(src_ip);
		
		//click_chatter("----Data from pong------\n");
		//click_chatter("src_mac: %s\nnsrc_ip: %s\n",					
		// src_mac_string.c_str(),
		//			 src_ip_string.c_str()
		//			);
		//click_chatter("------------------------\n");
		click_chatter("Added %s with %s", src_ip_string.c_str(), src_mac_string.c_str()); 
		// Find this gate's entry using its mac address which is the source mac address
		
		std::vector<GateInfo>::iterator it;

		for(it = gates.begin(); it!=gates.end(); it++)
		{
			if((*it).mac_address == src_mac_string)
			{
				if((*it).ip_address != src_ip_string)
				{			
					//click_chatter("Warning: IP address changed from %s to %s for host MAC %s\n",
				  //						(*it).ip_address.c_str(), src_ip_string.c_str(),
				  //		src_mac_string.c_str());
					
					(*it).ip_address = src_ip_string; 
				}
				(*it).timestamp = time(NULL);
				break;
			}
		}

		//New gate discovered
		if(it == gates.end()) {
		  GateInfo new_gate;
		  new_gate.ip_address = src_ip_string;
		  new_gate.mac_address = src_mac_string;
		  new_gate.timestamp = time(NULL);
		  
		  // put metrics when extending this function here

		  gates.push_back(new_gate);		  
		}

		//Printing the list of gates. Drop this later.
		//click_chatter("gates(%d):\n",gates.size());

		for(it = gates.begin(); it!=gates.end(); ++it) {
		  //click_chatter("%s -> %s\n",((*it).mac_address).c_str(), ((*it).ip_address).c_str());
		}				
	}
	else
	  click_chatter("Malformed packet received without header!\n");		
}

void GatewaySelector::process_antipong(Packet * p)
{
  // process pong here
  // 1. extract mac, ip and metric in pong
  // 2. look for mac as key in unresolved_gates map
  // 3. update the corresponding gate_info structure.
  // 4. Remove the gate_info struct from unresolved and put it in resolved.
	uint8_t src_mac[6], src_ip[4];	
	uint8_t *ptr = NULL;

	//click_chatter("Inside process_pong\n");

	if(p->has_mac_header()) {
		ptr = (uint8_t *)p->mac_header();
		//Skip destination as it should be a broadcast address
		ptr+= 6;
		//Skip to source mac address
		for(int i=0; i<6; i++) {
			src_mac[i] = *ptr;
			ptr++;
		}

		//skip protocol code
		ptr+=2;
		//extract ipv4
		for(int i=0; i<4; i++) {
			src_ip[i] = *ptr;
			ptr++;
		}
		
		std::string src_mac_string = mac_to_string(src_mac);
		std::string src_ip_string = ip_to_string(src_ip);
		
		//click_chatter("----Data from pong------\n");
		//click_chatter("src_mac: %s\nnsrc_ip: %s\n",					
		// src_mac_string.c_str(),
		//			 src_ip_string.c_str()
		//			);
		//click_chatter("------------------------\n");
		click_chatter("Removing %s with %s from gate table.", src_ip_string.c_str(), src_mac_string.c_str()); 
		// Find this gate's entry using its mac address which is the source mac address
		
		std::vector<GateInfo>::iterator it;

		for(it = gates.begin(); it!=gates.end(); it++)
		  {
		    if((*it).mac_address == src_mac_string)
		      {
			it = gates.erase(it);

			std::vector<PortCache>::iterator it = port_cache_table.begin();

			while(it != port_cache_table.end())
			  {
			    if(((*it).gate_ip).unparse() == src_ip_string.c_str())
			      {
				click_chatter("Removed %s from port cache table", src_ip_string.c_str());
				it = port_cache_table.erase(it);
				
			      }
			    else
			      ++it;
			  }			
			break;
		      }
		  }
	}
	else
	  click_chatter("Malformed antipong packet received!\n");
}


void GatewaySelector::push(int port, Packet *p)
{
  //click_chatter("Inside push()\n");
  switch(port)
    {
    case 0: /* Normal packet for setting the gateway */
      //click_chatter("Calling case 0 : select_gate\n");      
      p = select_gate(p);

      if(p == NULL)
	{
	  click_chatter("Select gate returning NULL packet! This seems like a bug.");
	}
      else if((p->dst_ip_anno()).unparse() == "0.0.0.0")
	{
	  //click_chatter("IP Address is 0.0.0.0. Pushing on [1]");
	  output(1).push(p);
	}
      else
	output(0).push(p);
      break;
      
    case 1:
      //click_chatter("case 1 : process_pong\n");		   
      process_pong(p);
      p -> kill();
      // output(1).push(p); // Do something with this packet
      break;

    case 2:
      click_chatter("Got antipong.");
      process_antipong(p);
      p -> kill();
      break;
    }
}

/*
TODO : Function is mostly broken for the scenario when no gates exist.
Find a way to associate an error handler which gracefully drops the packet
instead of the ugly hack used right now
FIXED by adding another output
*/

Packet * GatewaySelector::select_gate(Packet *p)
{
  IPAddress ip;
  //click_chatter("Inside select_gate function");

  if(p->has_transport_header())
    {
      //click_chatter("Yes, Has a transport header");
      uint8_t *ptr = (uint8_t *)p->transport_header();
      // Need a better way to extract src port
      // maybe ntohs(tcp_header->th_sport) where tcp_header is a struct click_tcp object.
      uint16_t src_port = 0;
      src_port += *ptr;
      ptr++;
      src_port = src_port << 8;
      src_port += *ptr;
      //click_chatter("src port is : %" PRIu16 "\n",src_port);
      
      ip = cache_lookup(src_port);
      
      if(ip == IPAddress(String("0.0.0.0")))
	{
	  //click_chatter("IP 0.0.0.0");
	  ip = find_gate(src_port);

	  if(ip != IPAddress(String("0.0.0.0")))
	    cache_update(src_port,ip);
	}
      
      p = set_ip_address(p,ip);
      return p;
    }
  else
    return NULL;
}

IPAddress GatewaySelector::cache_lookup(uint16_t src_port)
{
  std::vector<PortCache>::iterator it = port_cache_table.begin();

  //click_chatter("Inside cache_lookup");

  while(it != port_cache_table.end())
  {
    if((*it).src_port == src_port)
      {
 	//click_chatter("Returning gate ip from cache as : %s", ((*it).gate_ip).unparse().c_str());
	return (*it).gate_ip;
      }
    ++it;
  }
  
  //click_chatter("Returning from cache 0.0.0.0");
  return IPAddress(String("0.0.0.0"));
}

Packet * GatewaySelector::set_ip_address(Packet *p, IPAddress ip)
{
  //click_chatter("Calling set_ip_address");
  p->set_dst_ip_anno(ip); // is setting annotation fine or we should use set_ip_header()?
  return p;
}

IPAddress GatewaySelector::find_gate(uint16_t src_port)
{
  int index;

  if(gates.size() > 0)
    {
      index = src_port % gates.size();  
      return IPAddress(String((gates[index].ip_address).c_str()));
    }
  else
    {
      return IPAddress(String("0.0.0.0"));
    }
}

void GatewaySelector::cache_update(uint16_t src_port, IPAddress ip)
{
  PortCache entry;
  entry.src_port = src_port;
  entry.gate_ip = ip;
  entry.timestamp = 0;
  port_cache_table.push_back(entry);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GatewaySelector)
