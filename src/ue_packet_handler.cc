#include "ue_packet_handler.h"
#include "nas_packet_handler.h"

#include <iostream>

#include "mitm_lib/asn1/rrc_nr.h"
#include "mitm_lib/common/byte_buffer.h"
#include "mitm_lib/common/common_nr.h"


int decode_ul_ccch(uint8_t * buf, int n, asn1::json_writer & json_buffer);
int decode_ul_dcch(uint8_t * buf, int n, asn1::json_writer & json_buffer);

int UE::decode_packet(uint8_t *buf, int n, asn1::json_writer & json_buffer)
{
    struct from_ue_struct
    {
        uint32_t channel;
        uint8_t msg[32768];
    } buffer;
    
    memcpy(&buffer, buf, n);

    switch (static_cast<srsran::nr_srb>(buffer.channel))
    {
    case srsran::nr_srb::srb0:
        // ccch
        return decode_ul_ccch(buffer.msg, n - sizeof(uint32_t), json_buffer);
        break;
    case srsran::nr_srb::srb1:
    case srsran::nr_srb::srb2:
    case srsran::nr_srb::srb3:
        // dcch
        return decode_ul_dcch(buffer.msg, n - sizeof(uint32_t), json_buffer);
        break;
    default:
        std::string errcause = fmt::format("Invalid LCID=%d", buffer.channel);
        std::cerr <<errcause <<std::endl;
        break;
    }

    return -1;
}

int decode_ul_dcch(uint8_t * buf, int n, asn1::json_writer & json_buffer)
{
    using namespace srsran;
    using namespace asn1::rrc_nr;

    // Right now we only consider DCCH message
    struct asn1::rrc_nr::ul_dcch_msg_s ul_dcch_msg;
    {
        asn1::cbit_ref bref(buf, n);
        if (ul_dcch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
            ul_dcch_msg.msg.type().value != asn1::rrc_nr::ul_dcch_msg_type_c::types_opts::c1)
        {
            std::cerr << "Failed to unpack UL-DCCH message" << std::endl;
            return SRSRAN_ERROR;
        }
    }

    ul_dcch_msg.to_json(json_buffer);

    unique_byte_buffer_t pdu = srsran::make_byte_buffer();

    switch (ul_dcch_msg.msg.c1().type().value)
    {
        case ul_dcch_msg_type_c::c1_c_::types::ul_info_transfer:
        {
            ul_info_transfer_s &ul_info_transfer = ul_dcch_msg.msg.c1().ul_info_transfer();
            if (pdu->get_tailroom() < ul_info_transfer.crit_exts.ul_info_transfer().ded_nas_msg.size())
            {
                fprintf(stderr, "DL Info Transfer too big (%d > %d)",
                        ul_info_transfer.crit_exts.ul_info_transfer().ded_nas_msg.size(),
                        pdu->get_tailroom());
                return SRSRAN_ERROR;
            }

            pdu->N_bytes = ul_info_transfer.crit_exts.ul_info_transfer().ded_nas_msg.size();
            memcpy(pdu->msg, ul_info_transfer.crit_exts.ul_info_transfer().ded_nas_msg.data(), pdu->N_bytes);

            handle_nas_msg(std::move(pdu), json_buffer);
            break;
        }
        case ul_dcch_msg_type_c::c1_c_::types::rrc_setup_complete:
        {
            rrc_setup_complete_s &rrc_setup_complete = ul_dcch_msg.msg.c1().rrc_setup_complete();
            
            if (pdu->get_tailroom() < rrc_setup_complete.crit_exts.rrc_setup_complete().ded_nas_msg.size())
            {
                fprintf(stderr, "DL Info Transfer too big (%d > %d)",
                        rrc_setup_complete.crit_exts.rrc_setup_complete().ded_nas_msg.size(),
                        pdu->get_tailroom());
                return SRSRAN_ERROR;
            }

            pdu->N_bytes = rrc_setup_complete.crit_exts.rrc_setup_complete().ded_nas_msg.size();
            memcpy(pdu->msg, rrc_setup_complete.crit_exts.rrc_setup_complete().ded_nas_msg.data(), pdu->N_bytes);

            handle_nas_msg(std::move(pdu), json_buffer);
            break;
        }
    }

    return 0;
}

int decode_ul_ccch(uint8_t * buf, int n, asn1::json_writer & json_buffer)
{
    struct asn1::rrc_nr::ul_ccch_msg_s ul_ccch_msg;
    {
        asn1::cbit_ref bref(buf, n);
        if (ul_ccch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
            ul_ccch_msg.msg.type().value != asn1::rrc_nr::ul_ccch_msg_type_c::types_opts::c1)
        {
            std::cerr << "Failed to unpack UL-CCCH message" << std::endl;
            return SRSRAN_ERROR;
        }
    }

    ul_ccch_msg.to_json(json_buffer);

    return 1;
}