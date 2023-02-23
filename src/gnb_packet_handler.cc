#include "gnb_packet_handler.h"
#include "nas_packet_handler.h"

#include "mitm_lib/asn1/rrc_nr.h"
#include "mitm_lib/common/byte_buffer.h"
#include "mitm_lib/common/common_nr.h"
#include "mitm_lib/asn1/nas_5g_msg.h"

int decode_dl_dcch(uint8_t *buf, int n, asn1::json_writer & json_buffer);
int decode_dl_ccch(uint8_t *buf, int n, asn1::json_writer & json_buffer);

int gNB::decode_packet(uint8_t *buf, int n, asn1::json_writer & json_buffer)
{
    struct from_gnb_struct
    {
        uint32_t channel;
        uint8_t buf[32768];
    } buffer;

    memcpy(&buffer, buf, n);

    switch (static_cast<srsran::nr_srb>(buffer.channel))
    {
    case srsran::nr_srb::srb0:
        // ccch
        return decode_dl_ccch(buffer.buf, n - sizeof(buffer.channel), json_buffer);
        break;
    case srsran::nr_srb::srb1:
    case srsran::nr_srb::srb2:
        // dcch
        return decode_dl_dcch(buffer.buf, n - sizeof(buffer.channel), json_buffer);
        break;
    default:
        std::string errcause = fmt::format("Invalid LCID=%d", buffer.channel);
        std::cerr << errcause << std::endl;
        break;
    }

    return -1;
}

int decode_dl_ccch(uint8_t *buf, int n, asn1::json_writer & json_buffer)
{
    asn1::cbit_ref bref(buf, n);
    asn1::rrc_nr::dl_ccch_msg_s dl_ccch_msg;
    if (dl_ccch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
        dl_ccch_msg.msg.type().value != asn1::rrc_nr::dl_ccch_msg_type_c::types_opts::c1)
    {
        std::cerr << "Failed to unpack UL-DCCH message" << std::endl;
        return SRSRAN_ERROR;
    }

    dl_ccch_msg.to_json(json_buffer);

    return 1;
}

int decode_dl_dcch(uint8_t *buf, int n, asn1::json_writer & json_buffer)
{
    using namespace srsran;
    using namespace asn1::rrc_nr;

    asn1::cbit_ref bref(buf, n);
    dl_dcch_msg_s dl_dcch_msg;
    if (dl_dcch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
        dl_dcch_msg.msg.type().value != asn1::rrc_nr::dl_dcch_msg_type_c::types_opts::c1)
    {
        std::cerr << "Failed to unpack UL-DCCH message" << std::endl;
        return SRSRAN_ERROR;
    }
    dl_dcch_msg.to_json(json_buffer);
    
    srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
    switch (dl_dcch_msg.msg.c1().type().value)
    {
        case dl_dcch_msg_type_c::c1_c_::types::dl_info_transfer:
        {
            dl_info_transfer_s &dl_info_transfer = dl_dcch_msg.msg.c1().dl_info_transfer();
            if (pdu->get_tailroom() < dl_info_transfer.crit_exts.dl_info_transfer().ded_nas_msg.size())
            {
                fprintf(stderr, "DL Info Transfer too big (%d > %d)",
                        dl_info_transfer.crit_exts.dl_info_transfer().ded_nas_msg.size(),
                        pdu->get_tailroom());
                return SRSRAN_ERROR;
            }

            pdu->N_bytes = dl_info_transfer.crit_exts.dl_info_transfer().ded_nas_msg.size();
            memcpy(pdu->msg, dl_info_transfer.crit_exts.dl_info_transfer().ded_nas_msg.data(), pdu->N_bytes);

            handle_nas_msg(std::move(pdu), json_buffer);
            break;
        }
        case dl_dcch_msg_type_c::c1_c_::types::rrc_recfg:
        {
            rrc_recfg_s &rrc_recfg = dl_dcch_msg.msg.c1().rrc_recfg();
            if(rrc_recfg.crit_exts.rrc_recfg().non_crit_ext_present)
            {
                for (const auto& e1 : rrc_recfg.crit_exts.rrc_recfg().non_crit_ext.ded_nas_msg_list) 
                {
                    pdu->N_bytes = e1.size();
                    memcpy(pdu->msg, e1.data(), pdu->N_bytes);

                    handle_nas_msg(std::move(pdu), json_buffer);
                }
            }
            break;
        }
    }

    return 0;
}