/*
 * gbcs.c - Great Britain Companion Specification dissector plugin for Wireshark
 *
 * Copyright (C) 2018 Andre B. Oliveira
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * References:
 *
 * [GBCS] Smart Metering Implementation Programme
 *        Great Britain Companion Specification (GBCS),
 *        Version 2.0, February 2018.
 *        https://www.smartenergycodecompany.co.uk/sec/the-developing-sec
 *        https://smartenergycodecompany.co.uk/download/4619/
 *
 * [X680] Abstract Syntax Notation One (ASN.1) specification of basic notation,
 *        ITU-T recommendation X.680, July 2002.
 *        https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.680-200207-S!!PDF-E&type=items
 *
 * [X690] Abstract Syntax Notation One (ASN.1) encoding rules,
 *        ITU-T recommendation X.690, July 2002.
 *        https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.690-200207-S!!PDF-E&type=items
 */

#define WS_BUILD_DLL
#define NEW_PROTO_TREE_API
#include <config.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-ieee802154.h>
#include <epan/dissectors/packet-zbee-nwk.h>
#include <ws_symbol_export.h>

/* The name of the GBCS use case for each message code. */
static const value_string gbcs_message_code_names[] = {
    { 0x0001, "CCS01 Add device to CHF device log" },
    { 0x0002, "CCS02 Remove device from CHF device log" },
    { 0x0003, "CCS03 Restore CHF device log" },
    { 0x0004, "0x0004 (no longer used)" },
    { 0x0007, "CS01a Apply prepayment top up to ESME" },
    { 0x0008, "CS02a Provide security credentials details" },
    { 0x000a, "CS02c Issue security credentials" },
    { 0x000b, "CS02d Update device certificates on device" },
    { 0x000c, "CS02e Provide device certificates from device" },
    { 0x000d, "CS03a1 Method A join (meter)" },
    { 0x000e, "CS03b Method B join" },
    { 0x000f, "CS04ac Method A or C unjoin" },
    { 0x0010, "CS04b Method B unjoin" },
    { 0x0012, "CS06 Activate firmware" },
    { 0x0013, "CS07 Read device join details" },
    { 0x0014, "CS10a Read zigbee device event log" },
    { 0x0015, "CS11 Clear zigbee device event log" },
    { 0x0018, "CS14 device addition to / removal from HAN whitelist alerts" },
    { 0x0019, "ECS01a Set tariff and price on ESME" },
    { 0x001a, "ECS02 Set ESME payment mode to credit" },
    { 0x001b, "ECS03 Set ESME payment mode to prepayment" },
    { 0x001c, "ECS04a Adjust meter balance on ESME" },
    { 0x001d, "ECS05 Reset tariff block counter matrix" },
    { 0x001e, "ECS07 Manage debt on ESME" },
    { 0x001f, "0x001F (no longer used)" },
    { 0x0020, "ECS09 Activate emergency credit remotely on ESME" },
    { 0x0021, "ECS10 Send message to ESME" },
    { 0x0022, "ECS12 Set change of tenancy date on ESME" },
    { 0x0023, "ECS14 Disable privacy PIN protection on ESME" },
    { 0x0024, "ECS15a Clear ESME event log" },
    { 0x0025, "ECS16 Write supplier contact details on ESME" },
    { 0x0026, "ECS17a Read ESME energy registers (export energy)" },
    { 0x0027, "ECS17b Read ESME energy registers (import energy)" },
    { 0x0028, "ECS17c Read ESME energy registers (power)" },
    { 0x0029, "ECS17d Read ESME energy register (TOU)" },
    { 0x002a, "ECS17e Read ESME energy register (TOU with blocks)" },
    { 0x002b, "ECS18a Read maximum demand registers (export)" },
    { 0x002c, "ECS18b Read maximum demand registers (import)" },
    { 0x002d, "ECS19 Read ESME prepayment registers" },
    { 0x002e, "ECS20a Read ESME billing data log (payment-based debt payments)" },
    { 0x002f, "ECS20b Read ESME billing data log (change of mode / tariff triggered exc export)" },
    { 0x0030, "ECS20c Read ESME billing data log (billing calendar triggered exc export)" },
    { 0x0033, "ECS21a Read electricity daily read log (exc export)" },
    { 0x0034, "ECS21b Read electricity prepayment daily read log" },
    { 0x0035, "ECS21c Read electricity daily read log (export only)" },
    { 0x0036, "ECS22a Read electricity half hour profile data (export)" },
    { 0x0037, "ECS22b Read electricity half hour profile data (active import)" },
    { 0x0038, "ECS22c Read electricity half hour profile data (reactive import)" },
    { 0x0039, "ECS23 Read voltage operational data" },
    { 0x003a, "ECS24 Read ESME tariff data" },
    { 0x003b, "ECS26a Read ESME configuration data prepayment" },
    { 0x003c, "ECS26b Read ESME configuration voltage data" },
    { 0x003d, "ECS26c Read ESME configuration data device information (randomisation)" },
    { 0x003e, "ECS26d Read ESME configuration data device information (billing calendar) (unused since GBCS 1.0)" },
    { 0x003f, "ECS26e Read ESME configuration data device information (device identity exc MPAN) (unused since GBCS 1.0)" },
    { 0x0040, "ECS26f Read ESME configuration data device information (instantaneous power thresholds" },
    { 0x0042, "ECS27 Read ESME load limit data" },
    { 0x0043, "ECS28a Set load limit configuration general settings" },
    { 0x0044, "ECS28b Set load limit configuration counter reset" },
    { 0x0045, "ECS29a Set voltage configuration on ESME" },
    { 0x0046, "ECS30 Set billing calendar on ESME (unused since GBCS 1.0)" },
    { 0x0047, "ECS34 Set instantaneous power threshold configuration" },
    { 0x0048, "ECS35a Read ESME event log" },
    { 0x0049, "ECS35b Read ESME security log" },
    { 0x004a, "ECS37 Set maximum demand configurable time period" },
    { 0x004b, "ECS38 Update randomised offset limit" },
    { 0x004c, "ECS39a Set MPAN value on ESME" },
    { 0x004d, "ECS39b Set export MPAN value on ESME" },
    { 0x004e, "ECS40 Read MPAN value on ESME" },
    { 0x004f, "ECS42 Remotely close the load switch on ESME" },
    { 0x0050, "ECS43 Remotely open the load switch on ESME" },
    { 0x0051, "ECS44 Arm load switch on ESME" },
    { 0x0052, "ECS45 Read status of load switch on ESME" },
    { 0x0053, "ECS46a Set HCALCS or ALCS labels on ESME" },
    { 0x0054, "ECS46c Set HCALCS and ALCS configuration in ESME (excluding labels)" },
    { 0x0055, "ECS47 Set or reset HCALCS or ALCS state" },
    { 0x0058, "ECS50 Send CIN to ESME" },
    { 0x0059, "ECS52 Read ESME / CH firmware version" },
    { 0x005a, "ECS57 Reset ESME maximum demand registers" },
    { 0x005e, "ECS61c Read boost button data from ESME" },
    { 0x005f, "ECS62 Set ALCS and boost button assiciation" },
    { 0x0060, "ECS66 Read ESME daily consumption log" },
    { 0x0061, "ECS68 ESME critical sensitive alert (billing data log)" },
    { 0x0062, "ECS70 Set clock on ESME" },
    { 0x0067, "ECS80 Supply outage restore alert from ESME" },
    { 0x0068, "ECS71 Set supply tamper state on ESME" },
    { 0x0069, "ECS82 Read meter balance for ESME" },
    { 0x006b, "GCS01a Set tariff and price on GSME" },
    { 0x006c, "GCS02 Set GSME payment  mode to credit" },
    { 0x006d, "GCS03 Set GSME payment mode to prepayment" },
    { 0x006e, "GCS04 Manage debt on GSME" },
    { 0x006f, "GCS05 Update prepayment configuration on GSME" },
    { 0x0070, "GCS06 Activate emergency credit remotely on GSME" },
    { 0x0071, "GCS07 Send message to GSME" },
    { 0x0072, "GCS09 Set change of tenancy date on GSME" },
    { 0x0073, "GCS11 Disable privacy PIN protection on GSME" },
    { 0x0074, "GCS13a Read GSME consumption register" },
    { 0x0075, "GCS14 Read GSME prepayment registers" },
    { 0x0076, "GCS15c Read GSME billing data log (billing calendar triggered)" },
    { 0x0077, "GCS16a Read GSME daily read logs" },
    { 0x0078, "GCS17 Read GSME profile data log" },
    { 0x0079, "GCS18 Read gas network data log" },
    { 0x007b, "GCS21a Read gas configuration data device information" },
    { 0x007c, "GCS23 Set CV and conversion factor values on GSME" },
    { 0x007d, "GCS24 Set uncontrolled gas flow rate and supply tamper state on GSME" },
    { 0x007e, "GCS25 Set billing calendar on GSME" },
    { 0x007f, "GCS28 Set clock on GSME" },
    { 0x0080, "GCS31 Start network data log on GSME" },
    { 0x0081, "GCS32 Remotely close the valve on GSME" },
    { 0x0082, "GCS33 Read GSME valve status" },
    { 0x0083, "GCS36 Send CIN to ESME" },
    { 0x0084, "GCS38 Read GSME firmware version" },
    { 0x0085, "GCS39 Arm valve on GSME" },
    { 0x0086, "GCS40a Adjust prepayment mode meter balance on GSME" },
    { 0x0087, "GCS41 Set MPRN value on GSME" },
    { 0x0088, "GCS44 Write contact details on GSME" },
    { 0x0089, "GCS46 Read MPRN on GSME" },
    { 0x008b, "GCS53 Push billing data log as an alert" },
    { 0x008c, "GCS59 Restore GPF device log" },
    { 0x008d, "GCS60 Read meter balance for GSME" },
    { 0x0090, "PCS02 Activate emergency credit on GSME from PPMID" },
    { 0x0092, "ECS26i Read configuration data device information (CHF identity) (unused since GBCS 1.0)" },
    { 0x0093, "ECS35c Read CHF event log" },
    { 0x0094, "ECS35d Read CHF security log" },
    { 0x0096, "GCS16b Read GSME daily read logs (prepayment)" },
    { 0x0097, "CS01b Apply prepayment top up to GSME" },
    { 0x009b, "PCS01 Apply prepayment top up to GSME using PPMID" },
    { 0x009d, "GCS21d Read GSME configuration data device information (billing calendar) (unused since GBCS 1.0)" },
    { 0x009e, "GCS21e Read GSME/GPF configuration data device information (device identity) (unused since GBCS 1.0)" },
    { 0x009f, "GCS21f Read GSME tariff data" },
    { 0x00a0, "GCS61 Read gas daily consumption log" },
    { 0x00a1, "CS10b Read zigbee device security log" },
    { 0x00a2, "ECS01b Set price on ESME" },
    { 0x00a3, "GCS01b Set price on GSME" },
    { 0x00ab, "CS03a2 Method A join (non meter)" },
    { 0x00ac, "ECS25a Set alert behaviours ESME supplier" },
    { 0x00ad, "GCS20 Set alert behaviours GSME" },
    { 0x00ae, "ECS29b Set voltage configuration 3 phase" },
    { 0x00af, "CS03c Method C join" },
    { 0x00b0, "ECS25b Set alert behaviours ESME network operator" },
    { 0x00b2, "GCS62 Backup GPF device log" },
    { 0x00b3, "ECS04b Reset meter balance on ESME" },
    { 0x00b4, "GCS40b Reset prepayment mode meter balance on GSME" },
    { 0x00b5, "GCS21b Read GSME configuration data prepayment" },
    { 0x00b6, "GCS13c Read GSME register (TOU)" },
    { 0x00b7, "ECS01c Set tariff and price on ESME secondary" },
    { 0x00b8, "GCS13b Read GSME block counters" },
    { 0x00b9, "ECS35e Read ESME power event log" },
    { 0x00ba, "ECS35f Read ALCS event log" },
    { 0x00bb, "ECS61a Read HCALCS and ALCS data from ESME" },
    { 0x00bc, "ECS23b Read voltage operational data 3 phase" },
    { 0x00bd, "ECS24b Read ESME tariff data second element" },
    { 0x00be, "ECS26j Read ESME configuration data device information (payment mode)" },
    { 0x00bf, "GCS21f Read GSME configuration data device information (payment mode)" },
    { 0x00c0, "GCS40c Adjust credit mode meter balance on GSME" },
    { 0x00c1, "ECS15c Clear ALCS event log" },
    { 0x00c2, "GCS40d Reset credit mode meter balance on GSME" },
    { 0x00c3, "GCS15b Read GSME billing data log (change of mode / tariff triggered)" },
    { 0x00c4, "GCS15d Read GSME billing data log (payment-based debt payments)" },
    { 0x00c5, "GCS15e Read GSME billing data log (prepayment credits)" },
    { 0x00c6, "ECS26k Read ESME configuration voltage data 3 phase" },
    { 0x00c7, "ECS01d Set prive on ESME secondary" },
    { 0x00c9, "ECS20d Read ESME billing data log (prepayment credits)" },
    { 0x00ca, "Future dated firmware activation alert" },
    { 0x00cb, "Future dated updated security credentials alert" },
    { 0x00cc, "Future dated execution of instruction alert (DLMS/COSEM)" },
    { 0x00cd, "Future dated execution of instruction alert (GBZ)" },
    { 0x00ce, "Firmware distribution receipt alert (ESME)" },
    { 0x00cf, "Firmware distribution receipt alert (GSME)" },
    { 0x00d1, "ECS29c Set voltage configuration on ESME without counter reset" },
    { 0x00d2, "ECS29d Set voltage configuration on polyphase ESME without counter reset" },
    { 0x00d3, "ECS29e Reset RMS voltage counters on ESME" },
    { 0x00d4, "ECS29f Reset RMS voltage counters on polyphase ESME" },
    { 0x00d5, "Failure to deliver remote party message to ESME alert" },
    { 0x00d7, "ECS30a Set billing calendar on ESME all periodicities" },
    { 0x00d8, "GCS25a Set billing calendar on GSME all periodicities" },
    { 0x00d9, "ECS26l Read ESME configuration data device information (billing calendar all periodicities)" },
    { 0x00da, "GCS21k Read GSME configuration data device information (billing calendar all periodicities)" },
    { 0x00db, "ECS48 Configure daily resetting of tariff block counter matrix" },
    { 0x00de, "ECS08a Update prepayment configuration on ESME" },
    { 0x00ea, "ECS25a1 Set event behaviours - ESME to HAN device - supplier" },
    { 0x00eb, "ECS25a2 Set event behaviours - ESME audible alarm - supplier" },
    { 0x00ec, "ECS25a3 Set event behaviours - ESME logging - supplier" },
    { 0x00ed, "ECS25b3 Set event behaviours - ESME logging - network operator" },
    { 0x00ee, "ECS25r1 Read non-critical event and alert behaviours - ESME - supplier" },
    { 0x00ef, "ECS25r2 Read non-critical event and alert behaviours - ESME - network operator" },
    { 0x00f0, "Meter integrity issue warning alert - ESME" },
    { 0x00f1, "GCS20r Read non-critical event and alert behaviours - GSME - supplier" },
    { 0x00f2, "Meter integrity issue warning alert - GSME" },
    { 0x00f9, "ECS26m Read ESME configuration data device information (identity, type and supply tamper state)" },
    { 0x00fa, "ECS26n Read CHF configuration data device information (CH identity and type)" },
    { 0x00fb, "GCS21m Read GSME configuration data device information (identity, type and supply tamper / depletion state)" },
    { 0x0100, "CS02b Update security credentials (rootBySupplier)" },
    { 0x0101, "CS02b Update security credentials (rootByWanProvider)" },
    { 0x0102, "CS02b Update security credentials (supplierBySupplier)" },
    { 0x0103, "CS02b Update security credentials (networkOperatorByNetworkOperator)" },
    { 0x0104, "CS02b Update security credentials (accessControlBrokerByACB)" },
    { 0x0105, "CS02b Update security credentials (wanProviderByWanProvider)" },
    { 0x0106, "CS02b Update security credentials (transCoSByTransCoS)" },
    { 0x0107, "CS02b Update security credentials (supplierByTransCoS)" },
    { 0x0108, "CS02b Update security credentials (anyExceptAbnormalRootByRecovery)" },
    { 0x0109, "CS02b Update security credentials (anyByContingency)" },
    { 0x010a, "DBCH01 Read CHF sub GHz channel" },
    { 0x010b, "DBCH02 Read CHF sub GHz channel log" },
    { 0x010c, "DBCH03 Read CHF sub GHz configuration" },
    { 0x010d, "DBCH04 Set CHF sub GHz configuration" },
    { 0x010e, "DBCH05 Request CHF sub GHz channel scan" },
    { 0x010f, "CCS06 Read CHF device log and check HAN communications" },
    { 0x0110, "DBCH06 Limited duty cycle action taken sub GHz alert" },
    { 0x0111, "DBCH07 Sub GHz channel changed alert" },
    { 0x0112, "DBCH08 Sub GHz channel scan request assessment outcome alert" },
    { 0x0113, "DBCH09 Sub GHz configuration changed alert" },
    { 0x0114, "DBCH10 Message discarded due to duty cycle management sub GHz alert" },
    { 0x0115, "DBCH11 No more sub GHz device capacity alert" },
    { 0x1000, "Generic critical alert" },
    { 0x1001, "Generic non-critical alert" },
    { 0, 0 }
};

/* The DLMS/COSEM APDU tags used by the GBCS MAC Header and Grouping Header */
#define GBCS_GENERAL_CIPHERING 221
#define GBCS_GENERAL_SIGNING 223
static const value_string gbcs_apdu_names[] = {
    { GBCS_GENERAL_CIPHERING, "General-Ciphering" },
    { GBCS_GENERAL_SIGNING, "General-Signing" },
    { 0, 0 }
};

/* The CRA flag values */
#define GBCS_COMMAND 1
#define GBCS_RESPONSE 2
#define GBCS_ALERT 3
static const value_string gbcs_cra_names[] = {
    { GBCS_COMMAND, "Command" },
    { GBCS_RESPONSE, "Response" },
    { GBCS_ALERT, "Alert" },
    { 0, 0 }
};

/* The GBCS protocol handle */
static int gbcs_proto;

/* The GBCS header_field_info (hfi) structures */
static struct {
    header_field_info apdu;
    header_field_info length;
    header_field_info security_header;
    header_field_info mac;
    header_field_info cra;
    header_field_info originator_counter;
    header_field_info originator_id;
    header_field_info recipient_id;
    header_field_info date_time;
    header_field_info message_code;
    header_field_info suppl_remote_id;
    header_field_info suppl_remote_counter;
    header_field_info suppl_originator_counter;
    header_field_info suppl_remote_certificate;
    header_field_info signature;
    /* GBZ payload */
    header_field_info gbz_profile_id;
    header_field_info gbz_components;
    header_field_info gbz_alert_code;
    header_field_info gbz_timestamp;
    header_field_info gbz_control;
    header_field_info gbz_cluster_id;
    header_field_info gbz_length;
    header_field_info gbz_from_date_time;
    header_field_info gbz_additional_control;
    header_field_info gbz_additional_counter;
    header_field_info gbz_zcl_header;
    header_field_info gbz_ciphered_length;
    header_field_info gbz_ciphered_information;
    header_field_info gbz_use_case_specific_content;
    /* ASN.1 payload */
    header_field_info asn1_identifier;
    header_field_info asn1_length;
    header_field_info asn1_contents;
} gbcs_hfi HFI_INIT(gbcs_proto) = {
    { "DLMS/COSEM APDU Tag", "gbcs.apdu", FT_UINT8, BASE_DEC, gbcs_apdu_names, 0, 0, HFILL },
    { "Length", "gbcs.length", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Security Header", "gbcs.security_header", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "MAC", "gbcs.mac", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "CRA Flag", "gbcs.cra", FT_UINT8, BASE_DEC, gbcs_cra_names, 0, 0, HFILL },
    { "Originator Counter", "gbcs.originator_counter", FT_UINT64, BASE_DEC, 0, 0, 0, HFILL },
    { "Business Originator ID", "gbcs.originator_id", FT_UINT64, BASE_HEX, 0, 0, 0, HFILL },
    { "Business Recipient ID", "gbcs.recipient_id", FT_UINT64, BASE_HEX, 0, 0, 0, HFILL },
    { "Date-Time", "gbcs.date_time", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Message Code", "gbcs.message_code", FT_UINT16, BASE_HEX, gbcs_message_code_names, 0, 0, HFILL },
    { "Supplementary Remote Party ID", "gbcs.suppl_remote_id", FT_UINT64, BASE_HEX, 0, 0, 0, HFILL },
    { "Supplementary Remote Party Counter", "gbcs.suppl_remote_counter", FT_UINT64, BASE_DEC, 0, 0, 0, HFILL },
    { "Supplementary Originator ID", "gbcs.suppl_originator_id", FT_UINT64, BASE_HEX, 0, 0, 0, HFILL },
    { "Supplementary Remote Party Key Agreement Certificate", "gbcs.suppl_remote_certificate", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Signature", "gbcs.signature", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    /* GBZ payload */
    { "Profile ID", "gbcs.gbz_profile_id", FT_UINT16, BASE_HEX, 0, 0, 0, HFILL },
    { "Number of GBZ Components", "gbcs.gbz_components", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Alert Code", "gbcs.gbz_alert_code", FT_UINT16, BASE_HEX, 0, 0, 0, HFILL },
    { "Timestamp", "gbcs.gbz_timestamp", FT_UINT32, BASE_HEX, 0, 0, 0, HFILL },
    { "Extended Header Control Field", "gbcs.gbz_control", FT_UINT8, BASE_HEX, 0, 0, 0, HFILL },
    { "Extended Header Cluster ID", "gbcs.gbz_cluster_id", FT_UINT16, BASE_HEX, 0, 0, 0, HFILL },
    { "Extended Header GBZ Length", "gbcs.gbz_length", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { "From Date Time", "gbcs.gbz_from_date_time", FT_UINT32, BASE_HEX, 0, 0, 0, HFILL },
    { "Additional Header Control", "gbcs.gbz_additional_control", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Additional Header Frame Counter", "gbcs.gbz_additional_counter", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "ZCL Header", "gbcs.gbz_zcl_header", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Length of Ciphered Information", "gbcs.gbz_ciphered_length", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { "Ciphered Information", "gbcs.gbz_ciphered_information", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Use Case Specific Content", "gbcs.gbz_use_case_specific_content", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    /* ASN.1 payload */
    { "Identifier", "gbcs.asn1_identifier", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Length", "gbcs.asn1_length", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Contents", "gbcs.asn1_contents", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
};

/* Protocol subtree (ett) indices */
static struct {
    gint gbcs;
    gint mac_header;
    gint grouping_header;
    gint transaction;
    gint originator;
    gint recipient;
    gint date_time;
    gint other_info;
    gint key_info;
    gint payload;
    gint gbz_component;
    gint asn1_encoding;
    gint asn1_contents;
    gint signature;
} gbcs_ett;

/* Expert information (ei) fields */
static struct {
    expert_field alert;
} gbcs_ei;

static gint
gbcs_dissect_encoded_length(tvbuff_t *tvb, proto_tree *tree, header_field_info *hfi, gint *offset)
{
    proto_item *item;
    gint length, i, n;

    item = proto_tree_add_item(tree, hfi, tvb, *offset, 0, ENC_NA);

    length = tvb_get_guint8(tvb, *offset);
    if ((length & 0x80) == 0) {
        *offset += 1;
    } else {
        n = length & 0x7f;
        length = 0;
        for (i = 0; i < n; i++) {
            length = (length << 8) + tvb_get_guint8(tvb, *offset + 1 + i);
        }
        *offset += 1 + n;
    }

    proto_item_append_text(item, ": %d", length);
    proto_item_set_end(item, tvb, *offset);

    return length;
}

static void
gbcs_dissect_dlms_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissector_handle_t dlms_dissector;

    dlms_dissector = find_dissector("dlms");
    if (dlms_dissector) {
        call_dissector(dlms_dissector, tvb, pinfo, tree);
    }
}

static void
gbcs_dissect_gbz_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 cra_flag)
{
    gint offset;
    guint8 i, components, control;
    guint16 alert_code;
    gint length;
    proto_tree *subtree;
    proto_item *gbz_component_item;
    dissector_handle_t zcl_dissector;
    zbee_nwk_packet zcl_data;
    tvbuff_t *zcl_tvb;

    offset = 0;

    /* Profile ID */
    proto_tree_add_item(tree, &gbcs_hfi.gbz_profile_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Total number of GBZ Use Case Specific Components */
    proto_tree_add_item(tree, &gbcs_hfi.gbz_components, tvb, offset, 1, ENC_NA);
    components = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (cra_flag == GBCS_ALERT) {
        /* Alert Code */
        proto_tree_add_item(tree, &gbcs_hfi.gbz_alert_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        alert_code = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* Timestamp */
        proto_tree_add_item(tree, &gbcs_hfi.gbz_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* GBZ Use Case Specific Components (716) */
        if (alert_code == 0x81a0) {
            /*
             * otherInformation (two octet long value)
             * GBCS Section 16.4 Requirements.
             */
            proto_tree_add_item(tree, &gbcs_hfi.gbz_use_case_specific_content, tvb, offset, 2, ENC_NA);
            offset += 2;
            components = 0;
        } else if (alert_code == 0x8f66 || alert_code == 0x8f67) {
            /*
             * 0x0E || Message Code || Originator Counter || Cluster ID || Frame Control || Command
             * GBCS Section 9.2.2.6 Reactions to Future Date Commands.
             */
            proto_tree_add_item(tree, &gbcs_hfi.gbz_use_case_specific_content, tvb, offset, 15, ENC_NA);
            offset += 15;
            components = 0;
        } else if (alert_code == 0x8f1c || alert_code == 0x8f72) {
            /*
             * 0x0920 || Manufacturer Image Hash
             * GBCS Section 11.2.6 Construction of Firmware Distribution Receipt Alert.
             */
            proto_tree_add_item(tree, &gbcs_hfi.gbz_use_case_specific_content, tvb, offset, 34, ENC_NA);
            offset += 34;
            components = 0;
        }
    }

    /* GBZ Use Case Specific Components */
    for (i = 0; i < components; i++) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, gbcs_ett.gbz_component, &gbz_component_item, "GBZ Use Case Specific Component %u", i + 1);

        /* Extended Header Control Field */
        proto_tree_add_item(subtree, &gbcs_hfi.gbz_control, tvb, offset, 1, ENC_NA);
        control = tvb_get_guint8(tvb, offset);
        offset += 1;

        /* Extended Header Cluster ID */
        proto_tree_add_item(subtree, &gbcs_hfi.gbz_cluster_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        zcl_data.cluster_id = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* Extended Header GBZ Command Length */
        proto_tree_add_item(subtree, &gbcs_hfi.gbz_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        length = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* From Date Time */
        if (control & 0x10) {
            proto_tree_add_item(subtree, &gbcs_hfi.gbz_from_date_time, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            length -= 4;
        }

        if (control & 0x02) {
            /* Encrypted content */
            proto_tree_add_item(subtree, &gbcs_hfi.gbz_additional_control, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(subtree, &gbcs_hfi.gbz_additional_counter, tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(subtree, &gbcs_hfi.gbz_zcl_header, tvb, offset + 2, 3, ENC_NA);
            proto_tree_add_item(subtree, &gbcs_hfi.gbz_ciphered_length, tvb, offset + 5, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, &gbcs_hfi.gbz_ciphered_information, tvb, offset + 7, length - 7, ENC_NA);
        } else {
            /* Unencrypted content (standard ZCL Header and Payload) */
            zcl_tvb = tvb_new_subset_length(tvb, offset, length);
            zcl_dissector = find_dissector("zbee_zcl");
            if (zcl_dissector) {
                call_dissector_with_data(zcl_dissector, zcl_tvb, pinfo, subtree, &zcl_data);
            }
        }
        offset += length;

        proto_item_set_end(gbz_component_item, tvb, offset);
    }    
}

/*
 * References:
 * [X680] Chapter 8 Tags
 * [X680] Chapter 37 Definition of restricted character string types
 * [X680] Chapter 42 Generalized time
 * [X680] Chapter 43 Universal time
 */
static gint
gbcs_dissect_asn1_encoding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    static const char *asn1_universal_tag_names[] = {
        /*  0 */ "(reserved)",
        /*  1 */ "BOOLEAN",
        /*  2 */ "INTEGER",
        /*  3 */ "BIT STRING",
        /*  4 */ "OCTET STRING",
        /*  5 */ "NULL",
        /*  6 */ "OBJECT IDENTIFIER",
        /*  7 */ "OBJECT DESCRIPTOR",
        /*  8 */ "EXTERNAL",
        /*  9 */ "REAL",
        /* 10 */ "ENUMERATED",
        /* 11 */ "EMBEDDED-PDV",
        /* 12 */ "UTF8 STRING",
        /* 13 */ "RELATIVE OBJECT IDENTIFIER",
        /* 14 */ "(reserved)",
        /* 15 */ "(reserved)",
        /* 16 */ "SEQUENCE",
        /* 17 */ "SET",
        /* 18 */ "NUMERIC STRING",
        /* 19 */ "PRINTABLE STRING",
        /* 20 */ "TELETEX STRING",
        /* 21 */ "VIDEOTEX STRING",
        /* 22 */ "IA5 STRING",
        /* 23 */ "UTC TIME",
        /* 24 */ "GENERALIZED TIME",
        /* 25 */ "GRAPHIC STRING",
        /* 26 */ "VISIBLE STRING",
        /* 27 */ "GENERAL STRING",
        /* 28 */ "UNIVERSAL STRING",
        /* 29 */ "CHARACTER STRING",
        /* 30 */ "BMP STRING",
        /* 31 */ "(reserved)"
    };
    proto_tree *subtree, *subsubtree;
    proto_item *item;
    guint8 identifier;
    gint length, start, end;

    start = offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, gbcs_ett.asn1_encoding, &item, "ASN.1 Encoding");

    /* Identifier octets */
    proto_tree_add_item(subtree, &gbcs_hfi.asn1_identifier, tvb, offset, 1, ENC_NA);
    identifier = tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_item_set_text(item, "%s", asn1_universal_tag_names[identifier & 31]);

    /* Length octets */
    length = gbcs_dissect_encoded_length(tvb, subtree, &gbcs_hfi.asn1_length, &offset);

    /* Content octets */
    if (identifier & 0x20) { /* constructed */
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, length, gbcs_ett.asn1_contents, 0, "Contents");
        end = offset + length;
        while (offset < end) {
            offset += gbcs_dissect_asn1_encoding(tvb, pinfo, subsubtree, offset);
        }
    } else { /* primitive */
        proto_tree_add_item(subtree, &gbcs_hfi.asn1_contents, tvb, offset, length, ENC_NA);
        offset += length;        
    }

    proto_item_set_end(item, tvb, offset);

    return offset - start;
}

static void
gbcs_dissect_general_signing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree *subtree, *subsubtree;
    proto_item *grouping_header_item;
    proto_item *cra_item;
    proto_item *date_time_item;
    proto_item *other_info_item;
    proto_item *signature_item;
    gint date_time_length, other_info_length, content_length, signature_length;
    guint8 cra_flag;
    guint16 message_code;
    tvbuff_t *payload_tvb;

    /* Start of Grouping Header */
    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, gbcs_ett.grouping_header, &grouping_header_item, "Grouping Header");

    /* General-Signing DLMS/COSEM APDU tag */
    proto_tree_add_item(subtree, &gbcs_hfi.apdu, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Transaction ID */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, 10, gbcs_ett.transaction, 0, "Transaction ID");
    gbcs_dissect_encoded_length(tvb, subsubtree, &gbcs_hfi.length, &offset);
    cra_item = proto_tree_add_item(subsubtree, &gbcs_hfi.cra, tvb, offset, 1, ENC_NA);
    cra_flag = tvb_get_guint8(tvb, offset);
    if (cra_flag == GBCS_ALERT) {
        expert_add_info(pinfo, cra_item, &gbcs_ei.alert);
    }
    offset += 1;
    proto_tree_add_item(subsubtree, &gbcs_hfi.originator_counter, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Originator System Title */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, 9, gbcs_ett.originator, 0, "Originator System Title");
    gbcs_dissect_encoded_length(tvb, subsubtree, &gbcs_hfi.length, &offset);
    proto_tree_add_item(subsubtree, &gbcs_hfi.originator_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Recipient System Title */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, 9, gbcs_ett.recipient, 0, "Recipient System Title");
    gbcs_dissect_encoded_length(tvb, subsubtree, &gbcs_hfi.length, &offset);
    proto_tree_add_item(subsubtree, &gbcs_hfi.recipient_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Date Time */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, 0, gbcs_ett.date_time, &date_time_item, "Date Time");
    date_time_length = gbcs_dissect_encoded_length(tvb, subsubtree, &gbcs_hfi.length, &offset);
    if (date_time_length > 0) {
        proto_tree_add_item(subsubtree, &gbcs_hfi.date_time, tvb, offset, date_time_length, ENC_NA);
        offset += date_time_length;
    }
    proto_item_set_end(date_time_item, tvb, offset);

    /* Other Information */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, 0, gbcs_ett.other_info, &other_info_item, "Other Information");
    other_info_length = gbcs_dissect_encoded_length(tvb, subsubtree, &gbcs_hfi.length, &offset);
    message_code = 0;
    if (other_info_length >= 2) {
        proto_tree_add_item(subsubtree, &gbcs_hfi.message_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        message_code = tvb_get_ntohs(tvb, offset);
        if (other_info_length >= 18) {
            proto_tree_add_item(subsubtree, &gbcs_hfi.suppl_remote_id, tvb, offset + 2, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(subsubtree, &gbcs_hfi.suppl_remote_counter, tvb, offset + 10, 8, ENC_BIG_ENDIAN);
            if (other_info_length >= 26) {
                proto_tree_add_item(subsubtree, &gbcs_hfi.suppl_originator_counter, tvb, offset + 18, 8, ENC_BIG_ENDIAN);
                if (other_info_length > 26) {
                    proto_tree_add_item(subsubtree, &gbcs_hfi.suppl_remote_certificate, tvb, offset + 26, other_info_length - 26, ENC_BIG_ENDIAN);
                }
            }
        }
    }
    offset += other_info_length;
    proto_item_set_end(other_info_item, tvb, offset);

    /* Content Length */
    content_length = gbcs_dissect_encoded_length(tvb, subtree, &gbcs_hfi.length, &offset);

    /* End of the Grouping Header */
    proto_item_set_end(grouping_header_item, tvb, offset);

    /* Payload */
    payload_tvb = tvb_new_subset_length(tvb, offset, content_length);
    switch (tvb_get_guint8(payload_tvb, 0)) {
    case 217: /* DLMS access request APDU tag */
    case 218: /* DLMS access response APDU tag*/
    case 15: /* DLMS data notification APDU tag */
        subtree = proto_tree_add_subtree(tree, tvb, offset, content_length, gbcs_ett.payload, 0, "DLMS Payload");
        gbcs_dissect_dlms_payload(payload_tvb, pinfo, subtree);
        break;
    case 1: /* GBZ ZSE Profile ID (0x0109) */
        subtree = proto_tree_add_subtree(tree, tvb, offset, content_length, gbcs_ett.payload, 0, "GBZ Payload");
        gbcs_dissect_gbz_payload(payload_tvb, pinfo, subtree, cra_flag);
        break;
    default: /* ASN.1 */
        subtree = proto_tree_add_subtree(tree, tvb, offset, content_length, gbcs_ett.payload, 0, "ASN.1 Payload");
        gbcs_dissect_asn1_encoding(payload_tvb, pinfo, subtree, 0);
        break;
    }
    offset += content_length;

    /* Signature */
    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, gbcs_ett.signature, &signature_item, "Signature");
    signature_length = gbcs_dissect_encoded_length(tvb, subtree, &gbcs_hfi.length, &offset);
    if (signature_length > 0) {
        proto_tree_add_item(subtree, &gbcs_hfi.signature, tvb, offset, signature_length, ENC_NA);
        offset += signature_length;
    }
    proto_item_set_end(signature_item, tvb, offset);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                 val_to_str_const(message_code, gbcs_message_code_names, "(Unknwon Message Code)"),
                 val_to_str_const(cra_flag, gbcs_cra_names, "(Invalid CRA Flag)"));
}

static void
gbcs_dissect_general_ciphering(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint ciphered_service_length;
    gint apdu_length;
    tvbuff_t *apdu_tvb;

    /* Start of MAC Header */
    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, gbcs_ett.mac_header, &item, "MAC Header");

    /* General-Ciphering DLMS/COSEM APDU tag */
    proto_tree_add_item(subtree, &gbcs_hfi.apdu, tvb, offset, 1, ENC_NA);

    /* Six zero-length fields (TODO: GBT Message Routing Header) */
    proto_tree_add_subtree(subtree, tvb, offset + 1, 1, gbcs_ett.transaction, 0, "Transaction ID");
    proto_tree_add_subtree(subtree, tvb, offset + 2, 1, gbcs_ett.originator, 0, "Originator System Title");
    proto_tree_add_subtree(subtree, tvb, offset + 3, 1, gbcs_ett.recipient, 0, "Recipient System Title");
    proto_tree_add_subtree(subtree, tvb, offset + 4, 1, gbcs_ett.date_time, 0, "Date Time");
    proto_tree_add_subtree(subtree, tvb, offset + 5, 1, gbcs_ett.other_info, 0, "Other Information");
    proto_tree_add_subtree(subtree, tvb, offset + 6, 1, gbcs_ett.key_info, 0, "Key Information");
    offset += 7;

    /* Ciphered-service length */
    ciphered_service_length = gbcs_dissect_encoded_length(tvb, subtree, &gbcs_hfi.length, &offset);

    /* Security header */
    proto_tree_add_item(subtree, &gbcs_hfi.security_header, tvb, offset, 5, ENC_NA);
    offset += 5;

    /* End of MAC Header */
    proto_item_set_end(item, tvb, offset);

    /* The DLMS APDU being protected (General-Signing APDU) */
    apdu_length = ciphered_service_length - 5 /* security header */ - 12 /* MAC */;
    apdu_tvb = tvb_new_subset_length(tvb, offset, apdu_length);
    gbcs_dissect_general_signing(apdu_tvb, pinfo, tree, 0);
    offset += apdu_length;

    /* MAC */
    proto_tree_add_item(tree, &gbcs_hfi.mac, tvb, offset, 12, ENC_NA);
}

static int
gbcs_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    header_field_info *hfi;
    proto_item *item;
    proto_tree *subtree;
    int offset;
    int tag;

    hfi = proto_registrar_get_nth(gbcs_proto);

    for (offset = 0; offset + 11 < tvb_captured_length(tvb); offset++) {
        tag = tvb_get_guint8(tvb, offset);
        if (tag == GBCS_GENERAL_CIPHERING) {
            /* 0xdd 0x00 0x00 0x00 0x00 0x00 0x00 ... (TODO: Message Routing Header (GBT)) */
            if (tvb_get_letoh48(tvb, offset + 1) == 0) {
                item = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
                subtree = proto_item_add_subtree(item, gbcs_ett.gbcs);
                gbcs_dissect_general_ciphering(tvb, pinfo, subtree, offset);
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "GBCS");
                return tvb_captured_length(tvb);
            }
        } else if (tag == GBCS_GENERAL_SIGNING) {
            /* 0xdf 0x09 <1-byte CRA flag and 8-byte counter> 0x08 ... */
            if (tvb_get_guint8(tvb, offset + 1) == 9 && tvb_get_guint8(tvb, offset + 11) == 8) {
                item = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
                subtree = proto_item_add_subtree(item, gbcs_ett.gbcs);
                gbcs_dissect_general_signing(tvb, pinfo, subtree, offset);
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "GBCS");
                return tvb_captured_length(tvb);
            }
        }
    }

    return 0;
}

static void
gbcs_register_protoinfo(void)
{
    gbcs_proto = proto_register_protocol("Great Britain Companion Specification", "GBCS", "gbcs");

    /* Register the gbcs_hfi header field info structures */
    {
        header_field_info *hfi[sizeof(gbcs_hfi) / sizeof(header_field_info)];
        unsigned i;
        for (i = 0; i < array_length(hfi); i++) {
            hfi[i] = (header_field_info *)&gbcs_hfi + i;
        }
        proto_register_fields(gbcs_proto, hfi, array_length(hfi));
    }

    /* Initialise and register the gbcs_ett protocol subtree indices */
    {
        gint *ett[sizeof(gbcs_ett) / sizeof(gint)];
        unsigned i;
        for (i = 0; i < array_length(ett); i++) {
            ett[i] = (gint *)&gbcs_ett + i;
            *ett[i] = -1;
        }
        proto_register_subtree_array(ett, array_length(ett));
    }

    /* Register the gbcs_ei expert info fields */
    {
        static ei_register_info ei[] = {
            { &gbcs_ei.alert, { "gbcs.alert", PI_RESPONSE_CODE, PI_NOTE, "Alert", EXPFILL } },
        };
        expert_module_t *em = expert_register_protocol(gbcs_proto);
        expert_register_field_array(em, ei, array_length(ei));
    }

    /* Register the GBCS dissector and the UDP handler on the DLMS/COSEM port */
    {
        dissector_handle_t dh = register_dissector("gbcs", gbcs_dissect, gbcs_proto);
        dissector_add_uint("udp.port", 4059, dh);
    }
}

/*
 * The symbols that a Wireshark plugin is required to export.
 */

#define GBCS_PLUGIN_VERSION "0.0.1"

#ifdef VERSION_RELEASE /* wireshark >= 2.6 */

WS_DLL_PUBLIC_DEF const gchar plugin_release[] = VERSION_RELEASE;
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = GBCS_PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF void
plugin_register(void)
{
    static proto_plugin p;
    p.register_protoinfo = gbcs_register_protoinfo;
    proto_register_plugin(&p);
}

#else /* wireshark < 2.6 */

WS_DLL_PUBLIC_DEF const gchar version[] = GBCS_PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF void
plugin_register(void)
{
    gbcs_register_protoinfo();
}

#endif
