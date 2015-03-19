#include <click/config.h>
#include <click/ipaddress.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <string>
#include <cstdio>

#include "gatewayselector.hh"

CLICK_DECLS

#define GATES_REFRESH_INTERVAL 15 // in seconds
#define STALE_ENTRY_THRESHOLD 20 //in seconds

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
  FILE *addr = fopen("/sys/class/net/mesh0/address", "r");
  if(addr!=NULL)
    {
      fscanf(addr, "%x:%x:%x:%x:%x:%x", (unsigned int *)&self_mac_address[0], (unsigned int *)&self_mac_address[1], (unsigned int *)&self_mac_address[2], (unsigned int *)&self_mac_address[3], (unsigned int *)&self_mac_address[4], (unsigned int *)&self_mac_address[5]);
      
      fclose(addr);
    }
  else
    {
      printf("Failed to read Mac address");      
      exit(0);
    }
}

GatewaySelector::~GatewaySelector()
{
}

int GatewaySelector::initialize(ErrorHandler *)
{
  _master_timer.initialize(this);
  _master_timer.schedule_now();
  return 0;
}

void GatewaySelector::run_timer(Timer *timer)
{
		assert(timer == &_master_timer);
		
		std::vector<GateInfo>::iterator it;
		for(it = gates.begin(); it != gates.end(); ) {

		    if((time(NULL) - (*it).timestamp) > STALE_ENTRY_THRESHOLD)
			{
			click_chatter("Removing gate %s due to inactivity.\n", (*it).ip_address.c_str());
			it = gates.erase(it);
			}
		    else
			++it;
		    
		    if(gates.size() == 0)
			break;
		}

		std::vector<PortCache>::iterator iter;
		for(iter = port_cache_table.begin(); iter != port_cache_table.end();) {
		  
		  if((time(NULL) - (*iter).timestamp) > STALE_ENTRY_THRESHOLD)
		    {
		      //click_chatter("Removing entry for port no. %d\n", (*iter).src_port);
		      iter = port_cache_table.erase(iter);
		    }
		  else
		      ++iter;

		  if(port_cache_table.size() == 0)
		      break;
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
  // 1. extract mac, ip and metric from pong
  // 2. upate gate table with extracted info

        uint8_t src_mac[6];
	uint8_t src_ip[4];	
	uint16_t link_speed;
	uint8_t *ptr = NULL;

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
		//extract link speed

		//		click_chatter("Extract link speed");

		link_speed = *ptr;
		link_speed = link_speed<<8;
		ptr++;
		link_speed += *ptr;
		
		//std::string src_mac_string = mac_to_string(src_mac);
		std::string src_ip_string = ip_to_string(src_ip);
		
		//click_chatter("----Data from pong------\n");
		//click_chatter("src_mac: %s\nnsrc_ip: %s\n",		
		// src_mac_string.c_str(),
		//			 src_ip_string.c_str()
		//			);
		//click_chatter("------------------------\n");

		//click_chatter("Added %s with %s and link speed %" PRIu16 ".", src_ip_string.c_str(), src_mac_string.c_str(), link_speed); 
		//click_chatter("%s,%s,%" PRIu16, src_ip_string.c_str(), link_speed);

		// Find this gate's entry using its mac address which is the source mac address
		
		std::vector<GateInfo>::iterator it;
		//click_chatter("Going through gates.");

		for(it = gates.begin(); it!=gates.end(); it++)
		  {
		    if( ((*it).mac_address[0] == src_mac[0]) && ((*it).mac_address[1] == src_mac[1]) && ((*it).mac_address[2] == src_mac[2]) && ((*it).mac_address[3] == src_mac[3]) && ((*it).mac_address[4] == src_mac[4]) && ((*it).mac_address[5] == src_mac[5]))
			{
				if((*it).ip_address != src_ip_string)
				{			
				  //click_chatter("Warning: IP address changed from %s to %s for host MAC %s\n",
				  //(*it).ip_address.c_str(), src_ip_string.c_str(),
				  //src_mac_string.c_str());
					
					(*it).ip_address = src_ip_string; 
					(*it).link_kbps = link_speed;
				}
				(*it).timestamp = time(NULL);
				break;
			}
		}
		
		//New gate discovered
		if(it == gates.end()) {
		  GateInfo new_gate;
		
		  new_gate.ip_address = src_ip_string;
		  for(int i = 0;i<6;i++)
		    {
		    new_gate.mac_address[i] = src_mac[i];
		    }

		  new_gate.link_kbps = link_speed;		
		  new_gate.timestamp = time(NULL);


		  click_chatter("Adding Gate: %s [%x:%x:%x:%x:%x:%x] (%" PRIu16 " kbps)", src_ip_string.c_str(), src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], link_speed);
		 
		  // put metrics when extending this function here

		  gates.push_back(new_gate);
		  //click_chatter("Gate pushed.");
		}

		//Printing the list of gates. Drop this later.
		//click_chatter("gates(%d):\n",gates.size());

		// for(it = gates.begin(); it!=gates.end(); ++it) {
		//   //click_chatter("%s -> %s\n",((*it).mac_address).c_str(), ((*it).ip_address).c_str());
		// }
	}
	else
	  {
	  }
	//click_chatter("Malformed packet received without header!\n");
	//click_chatter("Processed pong.");
}

void GatewaySelector::process_antipong(Packet * p)
{
  // process antipong here
  // 1. extract mac and ip
  // 2. Remove corresponding entries from gates table

	uint8_t src_mac[6], src_ip[4];	
	uint8_t *ptr = NULL;
	bool gate_removed = false;

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
		
		//std::string src_mac_string = mac_to_string(src_mac);
		std::string src_ip_string = ip_to_string(src_ip);

		click_chatter("Request for Removal : %s [%x:%x:%x:%x:%x:%x]", src_ip_string.c_str(), src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
		// Find this gate's entry using it's mac address from mac-beacon
		
		std::vector<GateInfo>::iterator it;

		for(it = gates.begin(); it!=gates.end(); it++)
		  {
		    if(((*it).mac_address[0] == src_mac[0]) && ((*it).mac_address[1] == src_mac[1]) && ((*it).mac_address[2] == src_mac[2]) && ((*it).mac_address[3] == src_mac[3]) && ((*it).mac_address[4] == src_mac[4]) && ((*it).mac_address[5] == src_mac[5]))
		      {
			uint16_t deleted_gate_index = std::distance(gates.begin(), it);
			
			it = gates.erase(it);
			gate_removed = true;

			std::vector<PortCache>::iterator it2 = port_cache_table.begin();

			while(it2 != port_cache_table.end())
			  {
			    if((*it2).gates_index == deleted_gate_index)
			      {
				it2 = port_cache_table.erase(it2);
			      }
			    else if((*it2).gates_index > deleted_gate_index)
			      {
				((*it2).gates_index) -= 1;
				++it2;
			      }
			    else
			      ++it2;
			  }			
			break;
		      }
		  }

		if(!gate_removed)		  
		  click_chatter("No such gate exists in table.");		  
		else
		  click_chatter("Gate removed");
	}
	else
	  {
	  }
	//	  click_chatter("Malformed antipong packet received!\n");
}


void GatewaySelector::push(int port, Packet *p)
{
  //  click_chatter("Inside push()\n");
  Packet *q;

  switch(port)
    {
    case 0: /* Normal packet for setting the gateway */

      q = select_gate(p);
      
      if(q == NULL)
	{
	  output(1).push(p);	
	}
      else
	output(0).push(q);

      break;
      
    case 1:
      //click_chatter("case 1 : process_pong\n");
      process_pong(p);
      p -> kill();
      break;

    case 2:
      //click_chatter("Got antipong.");
      process_antipong(p);
      p -> kill();
      break;
    }
}

/*
TODO : Function is mostly broken for the scenario when no gates exist.
Find a way to associate an error handler which gracefully drops the packet
instead of the ugly hack used right now
FIXED: by adding another output port.
*/

Packet * GatewaySelector::select_gate(Packet *p)
{
  int port_index;

  if(p->has_transport_header())
    {
      uint8_t *ptr = (uint8_t *)p->transport_header();

      // Need a better way to extract src port
      // maybe ntohs(tcp_header->th_sport) where tcp_header is a struct click_tcp object.
      uint16_t src_port = 0;
      
      src_port += *ptr;
      ptr++;
      src_port = src_port << 8;
      src_port += *ptr;
      
      port_index = cache_lookup(src_port);

      WritablePacket *q = p->push_mac_header(14);
      uint8_t *q_ptr = q->data();
      uint16_t gates_index;

      if(port_index != -1)
	{
	  //click_chatter("IP 0.0.0.0");
	  gates_index = port_cache_table[port_index].gates_index;
	}
      else
	{	  
	  if(gates.size() == 0)
	    {
	    gates_index = -1;
	    return NULL;
	    }
	  else 
	    {
	    gates_index = src_port % gates.size();	    
	    //click_chatter("Calling cache_update");
	    cache_update(src_port, gates_index);
	    }
	}

      uint8_t type[2] = {0x08, 0x00};

      //Etherencap happens here
      memcpy(q_ptr, gates[gates_index].mac_address, 6);
      q_ptr+=6;
      memcpy(q_ptr, self_mac_address, 6);
      q_ptr+=6;
      memcpy(q_ptr, type, 2);
      
      return (Packet *)q;
    }
  else
    return NULL;
}

int GatewaySelector::cache_lookup(uint16_t src_port)
{
  std::vector<PortCache>::iterator it = port_cache_table.begin();

  while(it != port_cache_table.end())
  {
    if((*it).src_port == src_port)
      {	
	return std::distance(port_cache_table.begin(), it);
      }
    ++it;
  }
  
  return -1;
}

void GatewaySelector::cache_update(uint16_t src_port, uint16_t gates_index)
{
  PortCache entry;
  entry.src_port = src_port;
  entry.gates_index = gates_index;
  entry.timestamp = time(NULL);
  port_cache_table.push_back(entry);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GatewaySelector)
