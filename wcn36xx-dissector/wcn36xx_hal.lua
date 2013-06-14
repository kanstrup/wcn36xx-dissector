-- Protocol dissector for wcn36xx HAL (host to firmware communication)

-- Install instructions
-- add dofile("wcn36xx_hal.lua") to end of wireshark init.lua
-- Enable fw dbg dump
-- Run the following from a shell
--   mkfifo /tmp/wireshark
--   wireshark -k -i /tmp/wireshark &
--   adb shell cat /proc/kmsg | grep MSG | text2pcap -o hex -u 3660,3660 - /tmp/wireshark

local wcn36xx = Proto("wcn36xx", "wcn36xx HAL dissector")

function wcn36xx.init()
end

local msg_type_strings = {}
msg_type_strings[0] = "START_REQ"
msg_type_strings[1] = "START_RSP"
msg_type_strings[2] = "STOP_REQ"
msg_type_strings[3] = "STOP_RSP"
msg_type_strings[4] = "INIT_SCAN_REQ"
msg_type_strings[5] = "INIT_SCAN_RSP"
msg_type_strings[6] = "START_SCAN_REQ"
msg_type_strings[7] = "START_SCAN_RSP"
msg_type_strings[8] = "END_SCAN_REQ"
msg_type_strings[9] = "END_SCAN_RSP"
msg_type_strings[10] = "FINISH_SCAN_REQ"
msg_type_strings[11] = "FINISH_SCAN_RSP"
msg_type_strings[12] = "CONFIG_STA_REQ"
msg_type_strings[13] = "CONFIG_STA_RSP"
msg_type_strings[14] = "DELETE_STA_REQ"
msg_type_strings[15] = "DELETE_STA_RSP"
msg_type_strings[16] = "CONFIG_BSS_REQ"
msg_type_strings[17] = "CONFIG_BSS_RSP"
msg_type_strings[18] = "DELETE_BSS_REQ"
msg_type_strings[19] = "DELETE_BSS_RSP"
msg_type_strings[20] = "JOIN_REQ"
msg_type_strings[21] = "JOIN_RSP"
msg_type_strings[22] = "POST_ASSOC_REQ"
msg_type_strings[23] = "POST_ASSOC_RSP"
msg_type_strings[24] = "SET_BSSKEY_REQ"
msg_type_strings[25] = "SET_BSSKEY_RSP"
msg_type_strings[26] = "SET_STAKEY_REQ"
msg_type_strings[27] = "SET_STAKEY_RSP"
msg_type_strings[28] = "RMV_BSSKEY_REQ"
msg_type_strings[29] = "RMV_BSSKEY_RSP"
msg_type_strings[30] = "RMV_STAKEY_REQ"
msg_type_strings[31] = "RMV_STAKEY_RSP"
msg_type_strings[32] = "ADD_TS_REQ"
msg_type_strings[33] = "ADD_TS_RSP"
msg_type_strings[34] = "DEL_TS_REQ"
msg_type_strings[35] = "DEL_TS_RSP"
msg_type_strings[36] = "UPD_EDCA_PARAMS_REQ"
msg_type_strings[37] = "UPD_EDCA_PARAMS_RSO"
msg_type_strings[38] = "ADD_BA_REQ"
msg_type_strings[39] = "ADD_BA_RSP"
msg_type_strings[40] = "DEL_BA_REQ"
msg_type_strings[41] = "DEL_BA_RSP"
msg_type_strings[42] = "CH_SWITCH_REQ"
msg_type_strings[43] = "CH_SWITCH_RSP"
msg_type_strings[44] = "SET_LINK_ST_REQ"
msg_type_strings[45] = "SET_LINK_ST_RSP"
msg_type_strings[46] = "GET_STATS_REQ"
msg_type_strings[47] = "GET_STATS_RSP"
msg_type_strings[48] = "UPDATE_CFG_REQ"
msg_type_strings[49] = "UPDATE_CFG_RSP"
msg_type_strings[50] = "MISSED_BEACON_IND"
msg_type_strings[51] = "UNKNOWN_ADDR2_FRAME_RX_IND"
msg_type_strings[52] = "MIC_FAILURE_IND"
msg_type_strings[53] = "FATAL_ERROR_IND"
msg_type_strings[54] = "SET_KEYDONE_MSG"
msg_type_strings[55] = "DOWNLOAD_NV_REQ"
msg_type_strings[56] = "DOWNLOAD_NV_RSP"
msg_type_strings[57] = "ADD_BA_SESSION_REQ"
msg_type_strings[58] = "ADD_BA_SESSION_RSP"
msg_type_strings[59] = "TRIGGER_BA_REQ"
msg_type_strings[60] = "TRIGGER_BA_RSP"
msg_type_strings[61] = "UPDATE_BEACON_REQ"
msg_type_strings[62] = "UPDATE_BEACON_RSP"
msg_type_strings[63] = "SEND_BEACON_REQ"
msg_type_strings[64] = "SEND_BEACON_RSP"
msg_type_strings[65] = "SET_BCASTKEY_REQ"
msg_type_strings[66] = "SET_BCASTKEY_RSP"
msg_type_strings[67] = "DELETE_STA_CONTEXT_IND"
msg_type_strings[68] = "UPDATE_PROBE_RSP_TEMPLATE_REQ"
msg_type_strings[69] = "UPDATE_PROBE_RSP_TEMPLATE_RSP"
msg_type_strings[70] = "PROCESS_PTT_REQ"
msg_type_strings[71] = "PROCESS_PTT_RSP"
msg_type_strings[72] = "SIGNAL_BTAMP_EVENT_REQ"
msg_type_strings[73] = "SIGNAL_BTAMP_EVENT_RSP"
msg_type_strings[74] = "TL_HAL_FLUSH_AC_REQ"
msg_type_strings[75] = "TL_HAL_FLUSH_AC_RSP"
msg_type_strings[76] = "ENTER_IMPS_REQ"
msg_type_strings[77] = "EXIT_IMPS_REQ"
msg_type_strings[78] = "ENTER_BMPS_REQ"
msg_type_strings[79] = "EXIT_BMPS_REQ"
msg_type_strings[80] = "ENTER_UAPSD_REQ"
msg_type_strings[81] = "EXIT_UAPSD_REQ"
msg_type_strings[82] = "UPDATE_UAPSD_PARAM_REQ"
msg_type_strings[83] = "CONFIGURE_RXP_FILTER_REQ"
msg_type_strings[84] = "ADD_BCN_FILTER_REQ"
msg_type_strings[85] = "REM_BCN_FILTER_REQ"
msg_type_strings[86] = "ADD_WOWL_BCAST_PTRN"
msg_type_strings[87] = "DEL_WOWL_BCAST_PTRN"
msg_type_strings[88] = "ENTER_WOWL_REQ"
msg_type_strings[89] = "EXIT_WOWL_REQ"
msg_type_strings[90] = "HOST_OFFLOAD_REQ"
msg_type_strings[91] = "SET_RSSI_THRESH_REQ"
msg_type_strings[92] = "GET_RSSI_REQ"
msg_type_strings[93] = "SET_UAPSD_AC_PARAMS_REQ"
msg_type_strings[94] = "CONFIGURE_APPS_CPU_WAKEUP_STATE_REQ"
msg_type_strings[95] = "ENTER_IMPS_RSP"
msg_type_strings[96] = "EXIT_IMPS_RSP"
msg_type_strings[97] = "ENTER_BMPS_RSP"
msg_type_strings[98] = "EXIT_BMPS_RSP"
msg_type_strings[99] = "ENTER_UAPSD_RSP"
msg_type_strings[100] = "EXIT_UAPSD_RSP"
msg_type_strings[101] = "SET_UAPSD_AC_PARAMS_RSP"
msg_type_strings[102] = "UPDATE_UAPSD_PARAM_RSP"
msg_type_strings[103] = "CONFIGURE_RXP_FILTER_RSP"
msg_type_strings[104] = "ADD_BCN_FILTER_RSP"
msg_type_strings[105] = "REM_BCN_FILTER_RSP"
msg_type_strings[106] = "SET_RSSI_THRESH_RSP"
msg_type_strings[107] = "HOST_OFFLOAD_RSP"
msg_type_strings[108] = "ADD_WOWL_BCAST_PTRN_RSP"
msg_type_strings[109] = "DEL_WOWL_BCAST_PTRN_RSP"
msg_type_strings[110] = "ENTER_WOWL_RSP"
msg_type_strings[111] = "EXIT_WOWL_RSP"
msg_type_strings[112] = "RSSI_NOTIFICATION_IND"
msg_type_strings[113] = "GET_RSSI_RSP"
msg_type_strings[114] = "CONFIGURE_APPS_CPU_WAKEUP_STATE_RSP"
msg_type_strings[115] = "SET_MAX_TX_POWER_REQ"
msg_type_strings[116] = "SET_MAX_TX_POWER_RSP"
msg_type_strings[117] = "AGGR_ADD_TS_REQ"
msg_type_strings[118] = "AGGR_ADD_TS_RSP"
msg_type_strings[119] = "SET_P2P_GONOA_REQ"
msg_type_strings[120] = "SET_P2P_GONOA_RSP"
msg_type_strings[121] = "DUMP_COMMAND_REQ"
msg_type_strings[122] = "DUMP_COMMAND_RSP"
msg_type_strings[123] = "START_OEM_DATA_REQ"
msg_type_strings[124] = "START_OEM_DATA_RSP"
msg_type_strings[125] = "ADD_STA_SELF_REQ"
msg_type_strings[126] = "ADD_STA_SELF_RSP"
msg_type_strings[127] = "DEL_STA_SELF_REQ"
msg_type_strings[128] = "DEL_STA_SELF_RSP"
msg_type_strings[129] = "COEX_IND"
msg_type_strings[130] = "OTA_TX_COMPL_IND"
msg_type_strings[131] = "HOST_SUSPEND_IND"
msg_type_strings[132] = "HOST_RESUME_REQ"
msg_type_strings[133] = "HOST_RESUME_RSP"
msg_type_strings[134] = "SET_TX_POWER_REQ"
msg_type_strings[135] = "SET_TX_POWER_RSP"
msg_type_strings[136] = "GET_TX_POWER_REQ"
msg_type_strings[137] = "GET_TX_POWER_RSP"
msg_type_strings[138] = "P2P_NOA_ATTR_IND"
msg_type_strings[139] = "ENABLE_RADAR_DETECT_REQ"
msg_type_strings[140] = "ENABLE_RADAR_DETECT_RSP"
msg_type_strings[141] = "GET_TPC_REPORT_REQ"
msg_type_strings[142] = "GET_TPC_REPORT_RSP"
msg_type_strings[143] = "RADAR_DETECT_IND"
msg_type_strings[144] = "RADAR_DETECT_INTR_IND"
msg_type_strings[145] = "KEEP_ALIVE_REQ"
msg_type_strings[146] = "KEEP_ALIVE_RSP"
msg_type_strings[147] = "SET_PREF_NETWORK_REQ"
msg_type_strings[148] = "SET_PREF_NETWORK_RSP"
msg_type_strings[149] = "SET_RSSI_FILTER_REQ"
msg_type_strings[150] = "SET_RSSI_FILTER_RSP"
msg_type_strings[151] = "UPDATE_SCAN_PARAM_REQ"
msg_type_strings[152] = "UPDATE_SCAN_PARAM_RSP"
msg_type_strings[153] = "PREF_NETW_FOUND_IND"
msg_type_strings[154] = "SET_TX_PER_TRACKING_REQ"
msg_type_strings[155] = "SET_TX_PER_TRACKING_RSP"
msg_type_strings[156] = "TX_PER_HIT_IND"
msg_type_strings[157] = "8023_MULTICAST_LIST_REQ"
msg_type_strings[158] = "8023_MULTICAST_LIST_RSP"
msg_type_strings[159] = "8023_MULTICAST_LIST_REQ"
msg_type_strings[160] = "8023_MULTICAST_LIST_RSP"
msg_type_strings[161] = "PACKET_FILTER_MATCH_COUNT_REQ"
msg_type_strings[162] = "PACKET_FILTER_MATCH_COUNT_RSP"
msg_type_strings[163] = "CLEAR_PACKET_FILTER_REQ"
msg_type_strings[164] = "CLEAR_PACKET_FILTER_RSP"
msg_type_strings[165] = "INIT_SCAN_CON_REQ"
msg_type_strings[166] = "SET_POWER_PARAMS_REQ"
msg_type_strings[167] = "SET_POWER_PARAMS_RSP"
msg_type_strings[168] = "TSM_STATS_REQ"
msg_type_strings[169] = "TSM_STATS_RSP"
msg_type_strings[170] = "WAKE_REASON_IND"
msg_type_strings[171] = "GTK_OFFLOAD_REQ"
msg_type_strings[172] = "GTK_OFFLOAD_RSP"
msg_type_strings[173] = "GTK_OFFLOAD_GETINFO_REQ"
msg_type_strings[174] = "GTK_OFFLOAD_GETINFO_RSP"
msg_type_strings[175] = "FEATURE_CAPS_EXCHANGE_REQ"
msg_type_strings[176] = "FEATURE_CAPS_EXCHANGE_RSP"
msg_type_strings[177] = "EXCLUDE_UNENCRYPTED_IND"
msg_type_strings[178] = "SET_THERMAL_MITIGATION_REQ"
msg_type_strings[179] = "SET_THERMAL_MITIGATION_RSP"
msg_type_strings[180] = "undefined"
msg_type_strings[181] = "undefined"
msg_type_strings[182] = "UPDATE_VHT_OP_MODE_REQ"
msg_type_strings[183] = "UPDATE_VHT_OP_MODE_RSP"
msg_type_strings[184] = "P2P_NOA_START_IND"
msg_type_strings[185] = "GET_ROAM_RSSI_REQ"
msg_type_strings[186] = "GET_ROAM_RSSI_RSP"
msg_type_strings[187] = "CLASS_B_STATS_IND"
msg_type_strings[188] = "DEL_BA_IND"
msg_type_strings[189] = "DHCP_START_IND"
msg_type_strings[190] = "DHCP_STOP_IND"


local f = wcn36xx.fields
f.msg_type = ProtoField.uint16("wcn36xx.msg_type", "msg_type", base.DEC, msg_type_strings)
f.msg_version = ProtoField.uint16("wcn36xx.msg_version", "msg_version")
f.len = ProtoField.uint32("wcn36xx.len", "len")
f.data = ProtoField.bytes("wcn36xx.data", "data")
f.scan_channel = ProtoField.uint8("wcn36xx.scan_channel", "scan_channel")

function wcn36xx.dissector(buffer, pinfo, tree)
	local offset = 0
	pinfo.cols.protocol = "wcn36xx"
	pinfo.cols.info = ""

	local subtree = tree:add(wcn36xx, buffer(), "wcn36xx HAL protocol data")
	local header = subtree:add(wcn36xx, buffer(offset, 8), "header")

	local msg_type = buffer(offset, 2); offset = offset + 2
	header:add_le(f.msg_type, msg_type)
	header:add_le(f.msg_version, buffer(offset, 2)); offset = offset + 2
	header:add_le(f.len, buffer(offset, 4)); offset = offset +  4

	local msg_type_str
	if msg_type_strings[msg_type:le_uint()] ~= nil then
		msg_type_str = msg_type_strings[msg_type:le_uint()]:lower()
	else
		msg_type_str = msg_type
	end
	pinfo.cols.info:append(msg_type_str)

	-- data
	if buffer:len() > offset then
		local data = buffer(offset)
		local params = subtree:add(wcn36xx, buffer(offset), msg_type_str)
		if ((msg_type:le_uint() == 6) or
                    (msg_type:le_uint() == 8)) then
			-- start/end scan command
			params:add(f.scan_channel, buffer(offset, 1)); offset = offset + 1
		else
			params:add(f.data, data)
		end
	end
end

local udp_table = DissectorTable.get("udp.port")
local pattern = 3660
udp_table:add(pattern, wcn36xx)
