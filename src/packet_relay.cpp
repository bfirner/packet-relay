#include <string>
#include <vector>

#include <owl/world_model_protocol.hpp>
#include <owl/grail_types.hpp>
#include <owl/simple_sockets.hpp>
#include <owl/grailV3_solver_client.hpp>
#include <owl/client_world_connection.hpp>
#include <owl/netbuffer.hpp>
#include <owl/sensor_aggregator_protocol.hpp>
#include <owl/aggregator_solver_protocol.hpp>
#include <thread>
#include <mutex>

#include <sys/time.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <arpa/inet.h>

using world_model::Attribute;
using world_model::grail_time;
using world_model::URI;

using namespace aggregator_solver;

typedef unsigned int frequency;
typedef unsigned char bsid;

//Global variable for the signal handler.
bool killed = false;
//Signal handler.
void handler(int signal) {
  psignal( signal, "Received signal ");
  if (killed) {
    std::cerr<<"Aborting.\n";
    // This is the second time we've received the interrupt, so just exit.
    exit(-1);
  }
  std::cerr<<"Shutting down...\n";
  killed = true;
}


float toFloat(unsigned char* pipFloat) {
    return ((float)pipFloat[0] * 0x100 + (float)pipFloat[1] + (float)pipFloat[2] / (float)0x100);
}

//TODO FIXME The relays should convert this value into a float in the first place
//so that platform specific code is not required here
#define RSSI_OFFSET 78
#define CRC_OK 0x80

struct compareRepeater {
  bool operator()(const grail_types::transmitter& A, const grail_types::transmitter& B) const {
    return (A.phy < B.phy) or
      ( (A.phy == B.phy) and (A.id < B.id));
  }
};

int main(int ac, char** arg_vector) {
  if (ac != 6) {
    std::cerr<<"This program requires 5 arguments,"<<
      " the ip address, sensor port, and solver port of the aggregation server\n"<<
      " and the ip address and client port of world model to discover relay IDs.\n";
    std::cerr<<"An optional third argument specifies the minimum RSS for a packet to be reported.\n";
    return 0;
  }
  //Get the ip address and ports of the aggregation server
  std::string server_ip(arg_vector[1]);
  int sensor_port = std::stoi(std::string(arg_vector[2]));
  uint16_t server_port = std::stoi(std::string(arg_vector[3]));

  std::string wm_ip(arg_vector[4]);
  int client_port = std::stoi(std::string(arg_vector[5]));

  std::mutex relay_mutex;
  std::set<grail_types::transmitter, compareRepeater> relays;

  /*****************************************************************************
  * Set up a socket to connect to the aggregator as a sensor
  *****************************************************************************/
  ClientSocket agg(AF_INET, SOCK_STREAM, 0, sensor_port, server_ip);

  //TODO This should be inside of a loop so that we reconnect after a disconnection.
  try {
    if (agg) {
      std::cerr<<"Connecting to the GRAIL aggregation server.\n";
      //Try to get the handshake message
      {
        std::vector<unsigned char> handshake = sensor_aggregator::makeHandshakeMsg();

        //Send the handshake message
        agg.send(handshake);
        std::vector<unsigned char> raw_message(handshake.size());
        size_t length = agg.receive(raw_message);

        //Check if the handshake message failed
        if (not (length == handshake.size() and
              std::equal(handshake.begin(), handshake.end(), raw_message.begin()) )) {
          //Quit on failure - what we are trying to connect to is not a proper server.
          std::cerr<<"Failure during handshake with aggregator - aborting.\n";
          return 0;
        }
      }
    }
    else {
      std::cerr<<"Failed to connect to the aggregator as a sensor! Aborting!\n";
      return 0;
    }
  }
  catch (std::system_error& err) {
    std::cerr<<"Error connecting to the aggregator: "<<err.what()<<'\n';
    return 0;
  }

  /*****************************************************************************
  * Connect to the aggregator as a solver so that we can request relay data
  * Use a callback to interpret each relay packet into the packets that
  * are being repeated and send those to the aggregator.
  *****************************************************************************/
  std::vector<NetTarget> servers{NetTarget{server_ip, server_port}};
  auto packet_callback = [&](SampleData& s) {
    bool is_relay = false;
    {
      std::unique_lock<std::mutex> lck(relay_mutex);
      grail_types::transmitter source;
      source.phy = s.physical_layer;
      source.id = s.tx_id;
      is_relay = 0 < relays.count(source);
    }
    if (s.valid and is_relay and s.sense_data.size() > 0) {
      //std::cerr<<"Got packet from relay "<<s.tx_id<<" with "<<s.sense_data.size()<<" extra bytes\n";
      auto begin = s.sense_data.begin();
      //Read out the timestamp and packet data for each repeated packet
      //Packet format: timestamp, length, ID/parity, sensed data, RSSI/LQI
      std::vector<unsigned char> data(begin, s.sense_data.end());
      //Big enough to actually have a packet?
      if (data.size() >= 6) {
        //This packet consists of 4 bytes of time, 1 byte of length, the packet,
        //and two status bytes.
        uint32_t length = data[0];
        //Is the packet large enough?
        if (std::distance(begin, s.sense_data.end()) == 1+length+2) {
          //This packet is 1 byte of length, length bytes (first 3 are ID+parity), and 2 bytes of RSSI/LQI
          data = std::vector<unsigned char>(begin, begin + 1 + length + 2);
          //Now assemble sample data for the aggregation server.
          SampleData sd;
          //Calculate the tagID here instead of using be32toh since it is awkward to convert a
          //21 bit integer to 32 bits. Multiply by 8192 and 32 instead of shifting by 13 and 5
          //bits respectively to avoid endian issues with bit shifting.
          unsigned int netID = ((unsigned int)data[1] * 8192)  + ((unsigned int)data[2] * 32) +
            ((unsigned int)data[3] >> 3);

          //Use the physical layer of the receiver
          sd.physical_layer = s.physical_layer;
          sd.tx_id = netID;
          //The relay ID is the ID of the receiver
          sd.rx_id = s.tx_id;
          //Set this to the real timestamp, milliseconds since 1970
          timeval tval;
          gettimeofday(&tval, NULL);
          sd.rx_timestamp = s.rx_timestamp - 4;
          //Sense data offset is 4, there should be length - 3 bytes,
          //and there are 2 status bytes at end
          if (data.size() == 4 + length - 3 + 2) {
            sd.sense_data = std::vector<unsigned char>(data.begin()+4, data.begin()+4+length-3);
          }
          //Convert from one byte value to a float for received signal
          //strength as described in the TI/chipcon Design Note DN505 on cc1100
          size_t rss_index = data.size() - 2;
          sd.rss = ( (data[rss_index]) >= 128 ? (signed int)(data[rss_index]-256)/2.0 : (data[rss_index])/2.0) - RSSI_OFFSET;
          sd.valid = true;
          //Send the interpreted sample back into the aggregator
          agg.send(sensor_aggregator::makeSampleMsg(sd));
          //std::cerr<<"Sending sample from id "<<sd.tx_id<<" with rss "<<sd.rss<<" from relay "<<sd.rx_id<<" with "<<sd.sense_data.size()<<" bytes of sensed data\n";
        }
      }
    }
  };

  SolverAggregator aggregator(servers, packet_callback);

  /*****************************************************************************
  //Now discover relay names and update every 10 seconds
  //Request data from relays from the aggregators
  *****************************************************************************/
  //Connect to the world model as a client
  ClientWorldConnection cwc(wm_ip, client_port);
  if (not cwc.connected()) {
    std::cerr<<"Could not connect to the world model as a client - aborting.\n";
    return 0;
  }
  URI desired_uris = u".*relay.*";
  std::vector<URI> attributes{u"sensor"};
  world_model::grail_time interval = 10000;
  StepResponse sr = cwc.streamRequest(desired_uris, attributes, interval);
  std::map<uint8_t, aggregator_solver::Rule> rules;
  while (sr.hasNext() and not killed) {
    world_model::WorldState ws = sr.next();

    for (auto WS = ws.begin(); WS != ws.end(); ++WS) {
      for (auto attr = WS->second.begin(); attr != WS->second.end(); ++attr) {
        if (attr->name == u"sensor.relay") {
          //See if this is a new relay
          //Transmitters are stored as one byte of physical layer and 16 bytes of ID
          grail_types::transmitter relay = grail_types::readTransmitter(attr->data);

          //Mark that we are making a change to the aggregator rules.
          Transmitter sensor_id;
          sensor_id.base_id = relay.id;
          sensor_id.mask.upper = 0xFFFFFFFFFFFFFFFF;
          sensor_id.mask.lower = 0xFFFFFFFFFFFFFFFF;
          rules[relay.phy].txers.push_back(sensor_id);
          std::cerr<<"Found relay "<<(unsigned int)relay.phy<<"."<<relay.id<<'\n';
          {
            std::unique_lock<std::mutex> lck(relay_mutex);
            relays.insert(relay);
          }
        }
      }
    }
    //Make new subscriptions to the aggregator if there are new repeaers
    if (not rules.empty()) {
      Subscription sub;
      for (auto I = rules.begin(); I != rules.end(); ++I) {
        I->second.physical_layer = I->first;
        //Get all packets
        I->second.update_interval = 0;
        sub.push_back(I->second);
      }
      aggregator.updateRules(sub);
      std::cerr<<"Updating aggregator rules.\n";
    }
  }
}


