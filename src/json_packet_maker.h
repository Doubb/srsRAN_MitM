#ifndef __JSON_PACKET_MAKER__
#define __JSON_PACKET_MAKER__

#include <iostream>
#include <unistd.h>
#include <string>

#include "mitm_lib/asn1/asn1_utils.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace jsonPacketMaker {
  uint8_t* json_to_packet(std::string buf, uint8_t* original_msg, int size);

  // RRC
  void handle_rrc_security_mode_complete(uint8_t* original_msg, int rrcTransactionIdentifier, int size);
  void handle_rrc_security_mode_command(uint8_t* original_msg, int rrcTransactionIdentifier, std::string cipheringAlgorithm, std::string integrityAlgorithm, bool non_crit_ext_present, std::string late_non_crit_ext, int size);
  void handle_rrc_reject(uint8_t* original_msg, uint8_t waitTime, int size);
  void handle_rrc_ue_cap_enquiry(uint8_t* original_msg, int rrcTransactionIdentifier, std::string ratType, std::string capReqFilter, int size);
  void handle_rrc_ue_cap_information(uint8_t* original_msg, int rrcTransactionIdentifier, std::string ratType, std::string capRatContainer, int size);
  void handle_rrc_setup_complete(uint8_t* original_msg, int rrcTransactionIdentifier, int plmnIdentity, std::string dedicatedNAS, int size, const rapidjson::Value& obj);
  void handle_rrc_setup_request(uint8_t* original_msg, std::string ue_id_type, std::string ue_id_value, std::string establishment_cause, std::string spare, int size);
  void handle_rrc_setup(uint8_t* original_msg, int rrcTransactionIdentifier, int srb_identity, std::string masterCellGroup, bool reestablish_pdcp_present, bool discard_on_pdcp_present, int size);
  //void handle_rrc_reject(uint8_t waitTime, int size);
  
  // NAS
  void handle_nas_security_mode_command(uint8_t* original_msg, int rrcTransactionIdentifier, std::string dedicatedNas, int size, const rapidjson::Value& obj);
  void handle_nas_authentication_request(uint8_t* original_msg, int rrcTransactionIdentifier, std::string dedicatedNas, int size, const rapidjson::Value& obj);

  // Util
  int string_to_number(const rapidjson::Value& value);
  int hex_value(unsigned char hex_digit);
  const char* hex_to_string(const std::string& input);
}
  

#endif
