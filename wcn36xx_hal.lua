-- Copyright (C) 2013 Mikael Kanstrup (mikael.kanstrup@gmail.com)
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

local bit = require("bit")
local wcn36xx = Proto("wcn36xx", "wcn36xx HAL dissector")
local f = wcn36xx.fields
local msg_type_strings = {}
local driver_type_strings = {}
local bond_state_strings = {}
local cfg_strings = {}
local offload_type_strings = {}
local sys_mode_strings = {}
local link_state_strings = {}
local filter_type_strings = {}
local filter_protocol_type_strings = {}
local filter_cmp_type_strings = {}
local del_ba_direction_strings = {}
local ani_ed_type_strings = {}
local ani_wep_type_strings = {}
local bss_type_strings = {}
local oper_mode_strings = {}
local ht_oper_mode_strings = {}
local nw_type_strings = {}
local sta_type_strings = {}
local tx_channel_width_set_strings = {}
local stop_reason_strings = {}
local bt_amp_event_type_strings = {}
local thermal_mit_mode_strings = {}
local thermal_mit_level_strings = {}
local fw_caps_strings = {}
local rsp_status_strings = {}
local coex_ind_type_strings = {}
local keep_alive_packet_type_strings = {}

-- Firmware version
local fw_major = 0
local fw_minor = 0
local fw_version = 0
local fw_revision = 0

function wcn36xx.init()
	-- Hook into ethertype parser
	-- Bogus value 0x3660 used together with textpcap dummy header generation
	local udp_table = DissectorTable.get("ethertype")
	local pattern = 0x3660
	udp_table:add(pattern, wcn36xx)
end

function parse_cfg(buffer, pinfo, tree)
	local n = 0
	local id
	local len
	local pad
	local elements
	while buffer:len() > n do
		id = buffer(n, 2):le_uint()
		len = buffer(n + 2, 2):le_uint()
		pad = buffer(n + 4, 2):le_uint()
		local str
		if (cfg_strings[id] ~= nil) then
			str = cfg_strings[id]:lower()
		else
			str = id
		end
		elements = tree:add(wcn36xx, buffer(n, len + 8), str)
		elements:add_le(f.cfg_id, buffer(n, 2)); n = n + 2
		elements:add_le(f.cfg_len, buffer(n, 2)); n = n + 2
		elements:add_le(f.cfg_pad_bytes, buffer(n, 2)); n = n + 2
		elements:add_le(f.cfg_reserve, buffer(n, 2)); n = n + 2
		if (len == 4) then
			-- Value likely a uint32 so parse it like one
			elements:add_le(f.cfg_value, buffer(n, len)); n = n + len
		else
			elements:add(f.cfg_body, buffer(n, len)); n = n + len
		end
		n = n + pad
	end
	return n
end

function parse_config_sta(buffer, pinfo, tree)
	local n = 0
	if (buffer:len() == 106) then
		tree:add_le(f.CONFIG_STA_REQ_bssId, buffer(n, 6)); n = n + 6
		tree:add_le(f.CONFIG_STA_REQ_assocId, buffer(n, 2)); n = n + 2
		tree:add_le(f.CONFIG_STA_REQ_staType, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_shortPreambleSupported, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_staMac, buffer(n, 6)); n = n + 6
		tree:add_le(f.CONFIG_STA_REQ_listenInterval, buffer(n, 2)); n = n + 2
		tree:add_le(f.CONFIG_STA_REQ_wmmEnabled, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_htCapable, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_txChannelWidthSet, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_rifsMode, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_lsigTxopProtection, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_maxAmpduSize, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_maxAmpduDensity, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_maxAmsduSize, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_fShortGI40Mhz, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_fShortGI20Mhz, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_rmfEnabled, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_encryptType, buffer(n, 4)); n = n + 4
		tree:add_le(f.CONFIG_STA_REQ_action, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_uAPSD, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_maxSPLen, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_greenFieldCapable, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_mimoPS, buffer(n, 4)); n = n + 4
		tree:add_le(f.CONFIG_STA_REQ_delayedBASupport, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_us32MaxAmpduDuration, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_fDsssCckMode40Mhz, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_staIdx, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_bssIdx, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_p2pCapableSta, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_reserved, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_supportedRates, buffer(n, 58)); n = n + 58
	else
		-- V1
		tree:add_le(f.CONFIG_STA_REQ_V1_bssId, buffer(n, 6)); n = n + 6
		tree:add_le(f.CONFIG_STA_REQ_V1_assocId, buffer(n, 2)); n = n + 2
		tree:add_le(f.CONFIG_STA_REQ_V1_staType, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_shortPreambleSupported, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_staMac, buffer(n, 6)); n = n + 6
		tree:add_le(f.CONFIG_STA_REQ_V1_listenInterval, buffer(n, 2)); n = n + 2
		tree:add_le(f.CONFIG_STA_REQ_V1_wmmEnabled, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_htCapable, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_txChannelWidthSet, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_rifsMode, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_lsigTxopProtection, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_maxAmpduSize, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_maxAmpduDensity, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_maxAmsduSize, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_fShortGI40Mhz, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_fShortGI20Mhz, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_rmfEnabled, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_encryptType, buffer(n, 4)); n = n + 4
		tree:add_le(f.CONFIG_STA_REQ_V1_action, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_uAPSD, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_maxSPLen, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_greenFieldCapable, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_mimoPS, buffer(n, 4)); n = n + 4
		tree:add_le(f.CONFIG_STA_REQ_V1_delayedBASupport, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_us32MaxAmpduDuration, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_fDsssCckMode40Mhz, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_staIdx, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_bssIdx, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_p2pCapableSta, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_misc_flags, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_supportedRates, buffer(n, 66)); n = n + 66
		tree:add_le(f.CONFIG_STA_REQ_V1_vhtCapable, buffer(n, 1)); n = n + 1
		tree:add_le(f.CONFIG_STA_REQ_V1_vhtTxChannelWidthSet, buffer(n, 1)); n = n + 1
	end
	return n
end

function parse_update_edca(buffer, pinfo, tree)
	local n = 0

	local aci = buffer(n, 1):uint()
	local aci_aifsn = bit.rshift(bit.band(aci, 0xF0), 4)
	local aci_acm = bit.rshift(bit.band(aci, 0x8), 3)
	local aci_aci = bit.rshift(bit.band(aci, 0x6), 1)

	tree:add_le(f.EDCA_PARAM_RECORD_aci_aifsn, buffer(n,1), aci_aifsn)
	tree:add_le(f.EDCA_PARAM_RECORD_aci_acm, buffer(n,1), aci_acm)
	tree:add_le(f.EDCA_PARAM_RECORD_aci_aci, buffer(n,1), aci_aci)
	n = n + 1

	local cw = buffer(n, 1):uint()
	local cw_max = bit.band(cw, 0x0F)
	local cw_min = bit.rshift(bit.band(cw, 0xF0), 4)
	tree:add_le(f.EDCA_PARAM_RECORD_cw_max, buffer(n,1), cw_max)
	tree:add_le(f.EDCA_PARAM_RECORD_cw_min, buffer(n,1), cw_min)
	n = n + 1

	tree:add_le(f.EDCA_PARAM_RECORD_txoplimit, buffer(n, 2)); n = n + 2
	return n
end

function parse_caps_bits(buffer, pinfo, tree)
	for i = 0,127 do
		local by = math.floor(i / 8)
		local bi = (i % 8)
		local b = buffer(by,1):uint()

		if (bit.band(b, bit.lshift(1, bi)) > 0) then
			tree:add(f.FW_CAP, buffer(by, 1), i);
		end

	end
	return 16
end

function parse_stats_cnt(buffer, pinfo, tree)
	local n = 0

	tree:add_le(f.GET_STATS_RSP_summary_cnt0, buffer(n, 4)); n = n + 4
	tree:add_le(f.GET_STATS_RSP_summary_cnt1, buffer(n, 4)); n = n + 4
	tree:add_le(f.GET_STATS_RSP_summary_cnt2, buffer(n, 4)); n = n + 4
	tree:add_le(f.GET_STATS_RSP_summary_cnt3, buffer(n, 4)); n = n + 4
	return n
end

function wcn36xx.dissector(inbuffer, pinfo, tree)
	local n = 0
	local buffer = inbuffer
	pinfo.cols.protocol = "wcn36xx"
	pinfo.cols.info = ""

	local msg_type = buffer(0, 2):le_uint();
	local cmd_len = buffer(4, 4):le_uint()

	if (buffer:len() <= 46) then
		-- Ethernet frames are 64 (60) bytes minimum. Remove dummy
		-- trailing data if commands are smaller than that.
		buffer = buffer(0, cmd_len)
	end
	if (cmd_len == 0) then
		pinfo.cols.info:append("zero length command!")
		return
	end

	local subtree = tree:add(wcn36xx, buffer(), "wcn36xx HAL protocol data")
	local header = subtree:add(wcn36xx, buffer(n, 8), "header")

	if (buffer:len() <= 46) then
		tree:add(wcn36xx, inbuffer(cmd_len), "Ethernet frame dummy data")
	end

	header:add_le(f.msg_type, buffer(n, 2)); n = n + 2
	header:add_le(f.msg_version, buffer(n, 2)); n = n + 2
	header:add_le(f.len, buffer(n, 4)); n = n + 4

	local msg_type_str
	if msg_type_strings[msg_type] ~= nil then
		msg_type_str = msg_type_strings[msg_type]:lower()
	else
		msg_type_str = msg_type
	end
	pinfo.cols.info:append(msg_type_str)

	-- data
	if buffer:len() > n then
		local params = subtree:add(wcn36xx, buffer(n), msg_type_str)

		if (msg_type == 0) then
			-- START_REQ
			params:add_le(f.start_driver_type, buffer(n, 4)); n = n + 4
			local start_len = buffer(n, 4):le_uint()
			params:add_le(f.start_len, buffer(n, 4)); n = n + 4
			while ((buffer:len() > n) and
				(start_len > (n - 8))) do
				n = n + parse_cfg(buffer(n):tvb(), pinfo, params)
			end
		elseif (msg_type == 2) then
			-- STOP_REQ
			params:add_le(f.STOP_REQ_reason, buffer(n, 4)); n = n + 4
		elseif (msg_type == 4) then
			-- INIT_SCAN_REQ
			params:add_le(f.init_scan_mode, buffer(n, 4)); n = n + 4
			params:add_le(f.bssid, buffer(n, 6)); n = n + 6
			params:add(f.init_scan_notify, buffer(n, 1)); n = n + 1
			params:add(f.init_scan_frame_type, buffer(n, 1)); n = n + 1
			params:add(f.init_scan_frame_len, buffer(n, 1)); n = n + 1
			local hdr = params:add(wcn36xx, buffer(n, 24), "msg_mgmt_hdr")
			hdr:add_le(f.hal_mac_frame_ctl, buffer(n, 2)); n = n + 2
			hdr:add(f.hal_mac_mgmt_hdr_duration_lo, buffer(n, 1)); n = n + 1
			hdr:add(f.hal_mac_mgmt_hdr_duration_hi, buffer(n, 1)); n = n + 1
			hdr:add_le(f.hal_mac_mgmt_hdr_da, buffer(n, 6)); n = n + 6
			hdr:add_le(f.hal_mac_mgmt_hdr_sa, buffer(n, 6)); n = n + 6
			hdr:add_le(f.bssid, buffer(n, 6)); n = n + 6
			hdr:add_le(f.hal_mac_mgmt_hdr_seq_ctl, buffer(n, 2)); n = n + 2
			local scan_entry = params:add(wcn36xx, buffer(n, 3), "scan_entry")
			scan_entry:add(f.hal_scan_entry_bss_index, buffer(n, 2)); n = n + 2
			scan_entry:add(f.hal_scan_entry_active_bss_count, buffer(n, 1)); n = n + 1
		elseif ((msg_type == 6) or
			(msg_type == 8)) then
			-- START_SCAN_REQ/END_SCAN_REQ
			local channel = buffer(n, 1); n = n + 1
			pinfo.cols.info:append(", channel "..channel:uint())
			params:add(f.scan_channel, channel)
		elseif (msg_type == 10) then
			-- FINISH_SCAN_REQ
			params:add_le(f.FINISH_SCAN_REQ_scanMode, buffer(n, 4)); n = n + 4
			params:add_le(f.FINISH_SCAN_REQ_currentOperChannel, buffer(n, 1)); n = n + 1
			params:add_le(f.FINISH_SCAN_REQ_cbState, buffer(n, 4)); n = n + 4
			params:add_le(f.FINISH_SCAN_REQ_bssid, buffer(n, 6)); n = n + 6
			params:add_le(f.FINISH_SCAN_REQ_notifyBss, buffer(n, 1)); n = n + 1
			params:add_le(f.FINISH_SCAN_REQ_frameType, buffer(n, 1)); n = n + 1
			params:add_le(f.FINISH_SCAN_REQ_frameLength, buffer(n, 1)); n = n + 1
			params:add_le(f.FINISH_SCAN_REQ_macMgmtHdr, buffer(n, 24)); n = n + 24
			params:add_le(f.FINISH_SCAN_REQ_scanEntry, buffer(n, 3)); n = n + 3
		elseif (msg_type == 12) then
			-- CONFIG_STA_REQ
			n = n + parse_config_sta(buffer(n):tvb(), pinfo, params)
		elseif (msg_type == 14) then
			-- DELETE_STA_REQ
			params:add(f.sta_index, buffer(n, 1)); n = n + 1
		elseif (msg_type == 16 and cmd_len == 470) then
			-- CONFIG_BSS
			params:add_le(f.CONFIG_BSS_bssId, buffer(n, 6)); n = n + 6
			params:add_le(f.CONFIG_BSS_selfMacAddr, buffer(n, 6)); n = n + 6
			params:add_le(f.CONFIG_BSS_bssType, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_operMode, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_nwType, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_shortSlotTimeSupported, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_llaCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_llbCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_llgCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_ht20Coexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_llnNonGFCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_fLsigTXOPProtectionFullSupport, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_fRIFSMode, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_beaconInterval, buffer(n, 2)); n = n + 2
			params:add_le(f.CONFIG_BSS_dtimPeriod, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_txChannelWidthSet, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_currentOperChannel, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_currentExtChannel, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_reserved, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_ssId, buffer(n, 33)); n = n + 33
			params:add_le(f.CONFIG_BSS_action, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_rateSet, buffer(n, 13)); n = n + 13
			params:add_le(f.CONFIG_BSS_htCapable, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_obssProtEnabled, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_rmfEnabled, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_htOperMode, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_dualCTSProtection, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_ucMaxProbeRespRetryLimit, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_bHiddenSSIDEn, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_bProxyProbeRespEn, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_edcaParamsValid, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_acbe, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_acbk, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_acvi, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_acvo, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_extSetStaKeyParamValid, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_extSetStaKeyParam, buffer(n, 240)); n = n + 240
			params:add_le(f.CONFIG_BSS_halPersona, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_bSpectrumMgtEnable, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_txMgmtPower, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_maxTxPower, buffer(n, 1)); n = n + 1

			local staContext = params:add(buffer(n, 106), "staContext")
			n = n + parse_config_sta(buffer(n, 106):tvb(), pinfo, staContext)
		elseif (msg_type == 16 and cmd_len == 482) then
			-- CONFIG_BSS_V1
			params:add_le(f.CONFIG_BSS_V1_bssId, buffer(n, 6)); n = n + 6
			params:add_le(f.CONFIG_BSS_V1_selfMacAddr, buffer(n, 6)); n = n + 6
			params:add_le(f.CONFIG_BSS_V1_bssType, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_V1_operMode, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_nwType, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_V1_shortSlotTimeSupported, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_llaCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_llbCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_llgCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_ht20Coexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_llnNonGFCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_fLsigTXOPProtectionFullSupport, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_fRIFSMode, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_beaconInterval, buffer(n, 2)); n = n + 2
			params:add_le(f.CONFIG_BSS_V1_dtimPeriod, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_txChannelWidthSet, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_currentOperChannel, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_currentExtChannel, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_reserved, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_ssId, buffer(n, 33)); n = n + 33
			params:add_le(f.CONFIG_BSS_V1_action, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_rateSet, buffer(n, 13)); n = n + 13
			params:add_le(f.CONFIG_BSS_V1_htCapable, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_obssProtEnabled, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_rmfEnabled, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_htOperMode, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_V1_dualCTSProtection, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_ucMaxProbeRespRetryLimit, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_bHiddenSSIDEn, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_bProxyProbeRespEn, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_edcaParamsValid, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_acbe, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_V1_acbk, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_V1_acvi, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_V1_acvo, buffer(n, 4)); n = n + 4
			params:add_le(f.CONFIG_BSS_V1_extSetStaKeyParamValid, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_extSetStaKeyParam, buffer(n, 240)); n = n + 240
			params:add_le(f.CONFIG_BSS_V1_halPersona, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_bSpectrumMgtEnable, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_txMgmtPower, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_maxTxPower, buffer(n, 1)); n = n + 1

			local staContext = params:add(buffer(n, 116), "staContext")
			n = n + parse_config_sta(buffer(n, 116):tvb(), pinfo, staContext)

			params:add_le(f.CONFIG_BSS_V1_vhtCapable, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIG_BSS_V1_vhtTxChannelWidthSet, buffer(n, 1)); n = n + 1
		elseif (msg_type == 18) then
			-- DELETE_BSS_REQ
			params:add_le(f.DELETE_BSS_REQ_bssIdx, buffer(n, 1)); n = n + 1
		elseif (msg_type == 20) then
			-- JOIN_REQ
			params:add_le(f.bssid, buffer(n, 6)); n = n + 6
			params:add(f.join_channel, buffer(n, 1)); n = n + 1
			params:add_le(f.join_self_sta_mac_addr, buffer(n, 6)); n = n + 6
			params:add(f.join_local_power_constraint, buffer(n, 1)); n = n + 1
			params:add_le(f.join_secondary_channel_offset, buffer(n, 4)); n = n + 4
			params:add_le(f.join_link_state, buffer(n, 4)); n = n + 4
			params:add(f.join_max_tx_power, buffer(n, 1)); n = n + 1
		elseif (msg_type == 24) then
			-- SET_BSSKEY_REQ
			params:add_le(f.SET_BSSKEY_REQ_bssIdx, buffer(n, 1)); n = n + 1
			params:add_le(f.SET_BSSKEY_REQ_encType, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_BSSKEY_REQ_numKeys, buffer(n, 1)); n = n + 1
			params:add_le(f.SET_BSSKEY_REQ_key, buffer(n, 228)); n = n + 228
			params:add_le(f.SET_BSSKEY_REQ_singleTidRc, buffer(n, 1)); n = n + 1
		elseif (msg_type == 26) then
			-- SET_STAKEY_REQ
			params:add_le(f.SET_STAKEY_REQ_staIdx, buffer(n, 2)); n = n + 2
			params:add_le(f.SET_STAKEY_REQ_encType, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_STAKEY_REQ_wepType, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_STAKEY_REQ_defWEPIdx, buffer(n, 1)); n = n + 1
			params:add_le(f.SET_STAKEY_REQ_key, buffer(n, 228)); n = n + 228
			params:add_le(f.SET_STAKEY_REQ_singleTidRc, buffer(n, 1)); n = n + 1
		elseif (msg_type == 28) then
			-- RMV_BSSKEY_REQ
			params:add(f.bss_index, buffer(n, 1)); n = n + 1
			params:add_le(f.ani_ed_enc_type, buffer(n, 4)); n = n + 4
			params:add(f.rmv_bsskey_key_id, buffer(n, 1)); n = n + 1
			params:add_le(f.rmv_bsskey_wep_type, buffer(n, 4)); n = n + 4
		elseif (msg_type == 30) then
			-- RMV_STAKEY_REQ
			params:add_le(f.rmv_stakey_sta_index, buffer(n, 2)); n = n + 2
			params:add_le(f.ani_ed_enc_type, buffer(n, 4)); n = n + 4
			params:add(f.rmv_stakey_key_id, buffer(n, 1)); n = n + 1
			params:add(f.rmv_stakey_unicast, buffer(n, 1)); n = n + 1
		elseif (msg_type == 36) then
			-- UPD_EDCA_PARAMS_REQ
			params:add_le(f.UPD_EDCA_PARAMS_REQ_bssIdx, buffer(n, 2)); n = n + 2
			local e = params:add(buffer(n, 4), "acbe")
			n = n + parse_update_edca(buffer(n, 4):tvb(), pinfo, e)
			e = params:add(buffer(n, 4), "acbk")
			n = n + parse_update_edca(buffer(n, 4):tvb(), pinfo, e)
			e = params:add(buffer(n, 4), "acvi")
			n = n + parse_update_edca(buffer(n, 4):tvb(), pinfo, e)
			e = params:add(buffer(n, 4), "acvo")
			n = n + parse_update_edca(buffer(n, 4):tvb(), pinfo, e)

		elseif (msg_type == 38) then
			-- ADD_BA_REQ
			params:add(f.add_ba_session_id, buffer(n, 1)); n = n + 1
			params:add(f.add_ba_win_size, buffer(n, 1)); n = n + 1
			if buffer:len() > n then
				params:add(f.add_ba_reorder_on_chip, buffer(n, 1)); n = n + 1
			end
		elseif (msg_type == 40) then
			-- DEL_BA_REQ
			params:add_le(f.del_ba_sta_id, buffer(n, 2)); n = n + 2
			params:add(f.tid, buffer(n, 1)); n = n + 1
			params:add(f.del_ba_direction, buffer(n, 1)); n = n + 1
		elseif (msg_type == 42) then
			-- CH_SWITCH_REQ
			local channel = buffer(n, 1); n = n + 1
			pinfo.cols.info:append(", channel "..channel:uint())
			params:add(f.ch_switch_channel_number, channel)
			params:add(f.ch_switch_local_power_constraint, buffer(n, 1)); n = n + 1
			params:add_le(f.ch_switch_secondary_channel_offset, buffer(n, 4)); n = n + 4
			params:add(f.ch_switch_tx_mgmt_power, buffer(n, 1)); n = n + 1
			params:add(f.ch_switch_max_tx_power, buffer(n, 1)); n = n + 1
			params:add_le(f.ch_switch_self_sta_mac_addr, buffer(n, 6)); n = n + 6
			params:add_le(f.bssid, buffer(n, 6)); n = n + 6
		elseif (msg_type == 44) then
			-- SET_LINK_ST_REQ
			params:add_le(f.bssid, buffer(n, 6)); n = n + 6
			params:add_le(f.set_link_st_state, buffer(n, 4)); n = n + 4
			params:add_le(f.set_link_st_self_mac_addr, buffer(n, 6)); n = n + 6
		elseif (msg_type == 46) then
			-- GET_STATS_REQ
			params:add_le(f.get_stats_sta_id, buffer(n, 4)); n = n + 4
			params:add_le(f.get_stats_stats_mask, buffer(n, 4)); n = n + 4
		elseif (msg_type == 48) then
			-- UPDATE_CFG_REQ
			params:add_le(f.update_cfg_len, buffer(n, 4)); n = n + 4
			while buffer:len() > n do
				n = n + parse_cfg(buffer(n):tvb(), pinfo, params)
			end
		elseif (msg_type == 55) then
			-- DOWNLOAD_NV_REQ
			params:add_le(f.nv_frag_number, buffer(n, 2)); n = n + 2
			params:add_le(f.nv_last_fragment, buffer(n, 2)); n = n + 2
			local size = buffer(n, 4):le_uint()
			params:add_le(f.nv_img_buffer_size, buffer(n, 4)); n = n + 4
			params:add_le(f.nv_buffer, buffer(n, size)); n = n + size
		elseif (msg_type == 57) then
			-- ADD_BA_SESSION_REQ
			params:add_le(f.add_ba_session_sta_index, buffer(n, 2)); n = n + 2
			params:add_le(f.add_ba_session_mac_addr, buffer(n, 6)); n = n + 6
			params:add(f.add_ba_session_dialog_token, buffer(n, 1)); n = n + 1
			params:add(f.tid, buffer(n, 1)); n = n + 1
			params:add(f.add_ba_session_policy, buffer(n, 1)); n = n + 1
			params:add_le(f.add_ba_session_buffer_size, buffer(n, 2)); n = n + 2
			params:add_le(f.add_ba_session_timeout, buffer(n, 2)); n = n + 2
			params:add_le(f.add_ba_session_ssn, buffer(n, 2)); n = n + 2
			params:add(f.add_ba_session_direction, buffer(n, 1)); n = n + 1
		elseif (msg_type == 59) then
			-- TRIGGER_BA_REQ
			params:add_le(f.TRIGGER_BA_REQ_baSessionID, buffer(n, 1)); n = n + 1
			params:add_le(f.TRIGGER_BA_REQ_baCandidateCnt, buffer(n, 2)); n = n + 2
		elseif (msg_type == 61) then
			-- UPDATE_BEACON_REQ
			params:add_le(f.UPDATE_BEACON_REQ_bssIdx, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_fShortPreamble, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_fShortSlotTime, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_beaconInterval, buffer(n, 2)); n = n + 2
			params:add_le(f.UPDATE_BEACON_REQ_llaCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_llbCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_llgCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_ht20MhzCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_llnNonGFCoexist, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_fLsigTXOPProtectionFullSupport, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_fRIFSMode, buffer(n, 1)); n = n + 1
			params:add_le(f.UPDATE_BEACON_REQ_paramChangeBitmap, buffer(n, 2)); n = n + 2
		elseif (msg_type == 63) then
			-- SEND_BEACON_REQ
			params:add_le(f.SEND_BEACON_REQ_beaconLength, buffer(n, 4)); n = n + 4
			params:add_le(f.SEND_BEACON_REQ_beacon, buffer(n, 384)); n = n + 384
			params:add_le(f.SEND_BEACON_REQ_bssId, buffer(n, 6)); n = n + 6
			params:add_le(f.SEND_BEACON_REQ_timIeOffset, buffer(n, 4)); n = n + 4
			params:add_le(f.SEND_BEACON_REQ_p2pIeOffset, buffer(n, 2)); n = n + 2
		elseif (msg_type == 68) then
			-- UPDATE_PROBE_RSP_TEMPLATE_REQ
			params:add_le(f.UPDATE_PROBE_RSP_TEMPLATE_REQ_pProbeRespTemplate, buffer(n, 384)); n = n + 384
			params:add_le(f.UPDATE_PROBE_RSP_TEMPLATE_REQ_probeRespTemplateLen, buffer(n, 4)); n = n + 4
			params:add_le(f.UPDATE_PROBE_RSP_TEMPLATE_REQ_ucProxyProbeReqValidIEBmap, buffer(n, 32)); n = n + 32
			params:add_le(f.UPDATE_PROBE_RSP_TEMPLATE_REQ_bssId, buffer(n, 6)); n = n + 6
		elseif (msg_type == 72) then
			-- SIGNAL_BTAMP_EVENT_REQ
			params:add_le(f.SIGNAL_BTAMP_EVENT_REQ_btAmpEventType, buffer(n, 4)); n = n + 4
		elseif (msg_type == 78) then
			-- ENTER_BMPS_REQ
			params:add(f.bss_index, buffer(n, 1)); n = n + 1
			params:add_le(f.enter_bmps_tbtt, buffer(n, 8)); n = n + 8
			params:add(f.enter_bmps_dtim_count, buffer(n, 1)); n = n + 1
			params:add(f.enter_bmps_dtim_period, buffer(n, 1)); n = n + 1
			params:add_le(f.enter_bmps_rssi_filter_period, buffer(n, 4)); n = n + 4
			params:add_le(f.enter_bmps_num_beacon_per_rssi_average, buffer(n, 4)); n = n + 4
			params:add(f.enter_bmps_rssi_filter_enable, buffer(n, 1)); n = n + 1
		elseif (msg_type == 79) then
			-- EXIT_BMPS_REQ
			params:add(f.exit_bmps_send_data_null, buffer(n, 1)); n = n + 1
			params:add(f.bss_index, buffer(n, 1)); n = n + 1
		elseif (msg_type == 83) then
			-- CONFIGURE_RXP_FILTER_REQ
			params:add_le(f.CONFIGURE_RXP_FILTER_REQ_setMcstBcstFilterSetting, buffer(n, 1)); n = n + 1
			params:add_le(f.CONFIGURE_RXP_FILTER_REQ_setMcstBcstFilter, buffer(n, 1)); n = n + 1
		elseif (msg_type == 84) then
			-- ADD_BCN_FILTER_REQ
			params:add_le(f.beacon_filter_capability_info, buffer(n, 2)); n = n + 2
			params:add_le(f.beacon_filter_capability_mask, buffer(n, 2)); n = n + 2
			params:add_le(f.beacon_filter_beacon_interval, buffer(n, 2)); n = n + 2
			local num = buffer(n, 2):le_uint()
			params:add_le(f.beacon_filter_ie_num, buffer(n, 2)); n = n + 2
			params:add(f.bss_index, buffer(n, 1)); n = n + 1
			params:add(f.beacon_filter_reserved, buffer(n, 1)); n = n + 1
			local elements
			for i = 1,num do
				elements = params:add(wcn36xx, buffer(n, 6), i)
				elements:add(f.beacon_filter_element_id, buffer(n, 1)); n = n + 1
				elements:add(f.beacon_filter_check_ie_presence, buffer(n, 1)); n = n + 1
				elements:add(f.beacon_filter_n, buffer(n, 1)); n = n + 1
				elements:add(f.beacon_filter_value, buffer(n, 1)); n = n + 1
				elements:add(f.beacon_filter_bitmask, buffer(n, 1)); n = n + 1
				elements:add(f.beacon_filter_ref, buffer(n, 1)); n = n + 1
			end
		elseif (msg_type == 86) then
			-- ADD_WOWL_BCAST_PTRN
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPatternId, buffer(n, 1)); n = n + 1
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPatternByteOffset, buffer(n, 1)); n = n + 1
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPatternSize, buffer(n, 1)); n = n + 1
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPattern, buffer(n, 128)); n = n + 128
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPatternMaskSize, buffer(n, 1)); n = n + 1
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPatternMask, buffer(n, 128)); n = n + 128
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPatternExt, buffer(n, 128)); n = n + 128
			params:add_le(f.ADD_WOWL_BCAST_PTRN_ucPatternMaskExt, buffer(n, 128)); n = n + 128
			params:add_le(f.ADD_WOWL_BCAST_PTRN_bssIdx, buffer(n, 1)); n = n + 1
		elseif (msg_type == 87) then
			-- DEL_WOWL_BCAST_PTRN
			params:add_le(f.DEL_WOWL_BCAST_PTRN_ucPatternId, buffer(n, 1)); n = n + 1
			params:add_le(f.DEL_WOWL_BCAST_PTRN_bssIdx, buffer(n, 1)); n = n + 1
		elseif (msg_type == 88) then
			-- ENTER_WOWL_REQ
			params:add_le(f.ENTER_WOWL_REQ_ucMagicPktEnable, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_magicPtrn, buffer(n, 6)); n = n + 6
			params:add_le(f.ENTER_WOWL_REQ_ucPatternFilteringEnable, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucUcastPatternFilteringEnable, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWowChnlSwitchRcv, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWowDeauthRcv, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWowDisassocRcv, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWowMaxMissedBeacons, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWowMaxSleepUsec, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWoWEAPIDRequestEnable, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWoWEAPOL4WayEnable, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWowNetScanOffloadMatch, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWowGTKRekeyError, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_ucWoWBSSConnLoss, buffer(n, 1)); n = n + 1
			params:add_le(f.ENTER_WOWL_REQ_bssIdx, buffer(n, 1)); n = n + 1
		elseif (msg_type == 89) then
			-- EXIT_WOWL_REQ
			params:add_le(f.EXIT_WOWL_REQ_bssIdx, buffer(n, 1)); n = n + 1
		elseif (msg_type == 90) then
			-- HOST_OFFLOAD_REQ
			local type = buffer(n, 1):uint()
			params:add(f.host_offload_type, buffer(n, 1)); n = n + 1
			params:add(f.host_offload_enable, buffer(n, 1)); n = n + 1
			if (type == 0) then
				-- arp reply offload
				params:add(f.host_offload_ipv4, buffer(n, 4)); n = n + 16
			elseif (type == 1) then
				-- ipv6 neighbor discovery offload
				params:add(f.host_offload_ipv6, buffer(n, 16)); n = n + 16
			else
				-- ipv6 ns offload
				params:add(f.ns_offload_src_ipv6, buffer(n, 16)); n = n + 16
				params:add(f.ns_offload_self_ipv6, buffer(n, 16)); n = n + 16
				params:add(f.ns_offload_target_ipv6, buffer(n, 16)); n = n + 16
				params:add(f.ns_offload_target_ipv6_2, buffer(n, 16)); n = n + 16
				params:add_le(f.ns_offload_self_addr, buffer(n, 6)); n = n + 6
				params:add(f.ns_offload_valid, buffer(n, 1)); n = n + 1
				params:add(f.ns_offload_reserved2, buffer(n, 1)); n = n + 1
				params:add(f.bss_index, buffer(n, 1)); n = n + 1
				params:add_le(f.ns_offload_slot_index, buffer(n, 4)); n = n + 4
			end
		elseif (msg_type == 91) then
			-- SET_RSSI_THRESH_REQ
			params:add(f.set_rssi_threshold_t1, buffer(n, 1)); n = n + 1
			params:add(f.set_rssi_threshold_t2, buffer(n, 1)); n = n + 1
			params:add(f.set_rssi_threshold_t3, buffer(n, 1)); n = n + 1
			params:add(f.set_rssi_threshold_t1pos, buffer(n, 1):bitfield(7));
			params:add(f.set_rssi_threshold_t1neg, buffer(n, 1):bitfield(6));
			params:add(f.set_rssi_threshold_t2pos, buffer(n, 1):bitfield(5));
			params:add(f.set_rssi_threshold_t2neg, buffer(n, 1):bitfield(4));
			params:add(f.set_rssi_threshold_t3pos, buffer(n, 1):bitfield(3));
			params:add(f.set_rssi_threshold_t3neg, buffer(n, 1):bitfield(2));
			n = n + 1
		elseif (msg_type == 119) then
			-- SET_P2P_GONOA_REQ
			params:add_le(f.SET_P2P_GONOA_REQ_opp_ps, buffer(n, 1)); n = n + 1
			params:add_le(f.SET_P2P_GONOA_REQ_ctWindow, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_P2P_GONOA_REQ_count, buffer(n, 1)); n = n + 1
			params:add_le(f.SET_P2P_GONOA_REQ_duration, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_P2P_GONOA_REQ_interval, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_P2P_GONOA_REQ_single_noa_duration, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_P2P_GONOA_REQ_psSelection, buffer(n, 1)); n = n + 1
		elseif (msg_type == 125) then
			-- HAL_ADD_STA_SELF_REQ
			params:add_le(f.add_sta_self_addr, buffer(n, 6)); n = n + 6
			params:add_le(f.add_sta_self_status, buffer(n, 4)); n = n + 4
		elseif (msg_type == 127) then
			-- DEL_STA_SELF_REQ
			status = 0;
			params:add_le(f.DEL_STA_SELF_REQ_selfMacAddr, buffer(n, 6)); n = n + 6
		elseif (msg_type == 129) then
			-- COEX_IND
			local coextype = buffer(n, 4)
			params:add_le(f.COEX_IND_coexIndType, coextype); n = n + 4
			local coexind = params:add_le(wcn36xx, buffer(n, 16), "coexIndData")
			if (coextype:le_uint() == 4 or
				coextype:le_uint() == 5) then
				coexind:add_le(f.COEX_IND_Bssfordisableaggr, buffer(n, 6)); n = n + 6
				coexind:add_le(f.COEX_IND_Unused, buffer(n, 10)); n = n + 10
			else
				coexind:add_le(f.COEX_IND_Unused, buffer(n, 16)); n = n + 16
			end
		elseif (msg_type == 130) then
			-- OTA_TX_COMPL_IND
			params:add_le(f.OTA_TX_COMPL_IND_status, buffer(n, 4)); n = n + 4
		elseif (msg_type == 145) then
			-- KEEP_ALIVE_REQ
			params:add_le(f.KEEP_ALIVE_REQ_packetType, buffer(n, 1)); n = n + 1
			params:add_le(f.KEEP_ALIVE_REQ_timePeriod, buffer(n, 4)); n = n + 4
			params:add_le(f.KEEP_ALIVE_REQ_hostIpv4Addr, buffer(n, 4)); n = n + 4
			params:add_le(f.KEEP_ALIVE_REQ_destIpv4Addr, buffer(n, 4)); n = n + 4
			params:add_le(f.KEEP_ALIVE_REQ_destMacAddr, buffer(n, 6)); n = n + 6
			params:add_le(f.KEEP_ALIVE_REQ_bssIdx, buffer(n, 1)); n = n + 1
		elseif (msg_type == 151) then
			-- UPDATE_SCAN_PARAM_REQ
			params:add(f.scan_dot11d_enabled, buffer(n, 1)); n = n + 1
			params:add(f.scan_dot11d_resolved, buffer(n, 1)); n = n + 1
			local channel_count = buffer(n, 1):uint()
			params:add(f.scan_channel_count, buffer(n, 1)); n = n + 1
			local elements = params:add(wcn36xx, buffer(n, channel_count), "channels")
			local index = n
			for i = 1,channel_count do
				elements:add(f.scan_channels_i, buffer(index, 1)); index = index + 1
			end
			n = n + 60
			params:add_le(f.scan_active_min_ch_time, buffer(n, 2)); n = n + 2
			params:add_le(f.scan_active_max_ch_time, buffer(n, 2)); n = n + 2
			params:add_le(f.scan_passive_min_ch_time, buffer(n, 2)); n = n + 2
			params:add_le(f.scan_passive_max_ch_time, buffer(n, 2)); n = n + 2
			params:add_le(f.scan_phy_chan_bond_state, buffer(n, 4)); n = n + 4
		elseif (msg_type == 157) then
			-- 8023_MULTICAST_LIST_REQ
			params:add(f.multicast_list_data_offset, buffer(n, 1)); n = n + 1
			local addr_count = buffer(n, 4):le_uint()
			params:add_le(f.multicast_list_addr_count, buffer(n, 4)); n = n + 4
			for i = 1,addr_count do
				params:add_le(f.multicast_list_address, buffer(n, 6)); n = n + 6
			end
			local unused = cmd_len - n - 1
			params:add(f.multicast_list_unused, buffer(n, unused)); n = n + unused
			params:add(f.bss_index, buffer(n, 1)) n = n + 1
		elseif (msg_type == 159) then
			-- SET_PACKET_FILTER_REQ
			params:add(f.rcv_packet_filter_id, buffer(n, 1)); n = n + 1
			params:add(f.rcv_packet_filter_type, buffer(n, 1)); n = n + 1
			local count = buffer(n, 1):uint()
			params:add(f.rcv_packet_filter_params_count, buffer(n, 1)); n = n + 1
			params:add_le(f.rcv_packet_filter_coalesce_time, buffer(n, 4)); n = n + 4
			params:add(f.bss_index, buffer(n, 1)); n = n + 1
			for i = 1,count do
				local fltparams = subtree:add(wcn36xx, buffer(n, 22), i)
				fltparams:add(f.rcv_packet_filter_param_protocol_layer, buffer(n, 1)); n = n + 1
				fltparams:add(f.rcv_packet_filter_param_cmp_flag, buffer(n, 1)); n = n + 1
				fltparams:add_le(f.rcv_packet_filter_param_data_length, buffer(n, 2)); n = n + 2
				fltparams:add(f.rcv_packet_filter_param_data_offset, buffer(n, 1)); n = n + 1
				fltparams:add(f.rcv_packet_filter_param_reserved, buffer(n, 1)); n = n + 1
				fltparams:add(f.rcv_packet_filter_param_compare_data, buffer(n, 8)); n = n + 8
				fltparams:add(f.rcv_packet_filter_param_data_mask, buffer(n, 8)); n = n + 8
			end
		elseif (msg_type == 166) then
			-- SET_POWER_PARAMS_REQ
			params:add_le(f.set_power_params_ignore_dtim, buffer(n, 4)); n = n + 4
			params:add_le(f.set_power_params_dtim_period, buffer(n, 4)); n = n + 4
			params:add_le(f.set_power_params_listen_interval, buffer(n, 4)); n = n + 4
			params:add_le(f.set_power_params_bcast_mcast_filter, buffer(n, 4)); n = n + 4
			params:add_le(f.set_power_params_enable_bet, buffer(n, 4)); n = n + 4
			params:add_le(f.set_power_params_bet_interval, buffer(n, 4)); n = n + 4
		elseif (msg_type == 171) then
			-- GTK_OFFLOAD_REQ
			params:add_le(f.GTK_OFFLOAD_REQ_ulFlags, buffer(n, 4)); n = n + 4
			params:add_le(f.GTK_OFFLOAD_REQ_aKCK, buffer(n, 16)); n = n + 16
			params:add_le(f.GTK_OFFLOAD_REQ_aKEK, buffer(n, 16)); n = n + 16
			params:add_le(f.GTK_OFFLOAD_REQ_ullKeyReplayCounter, buffer(n, 8)); n = n + 8
			params:add_le(f.GTK_OFFLOAD_REQ_bssIdx, buffer(n, 1)); n = n + 1
		elseif (msg_type == 175) then
			-- FEATURE_CAPS_EXCHANGE_REQ
			local caps = params:add(buffer(n, 16), "caps")
			n = n + parse_caps_bits(buffer(n, 16):tvb(), pinfo, caps)
		elseif (msg_type == 178) then
			-- SET_THERMAL_MITIGATION_REQ
			params:add_le(f.SET_THERMAL_MITIGATION_REQ_thermalMitMode, buffer(n, 4)); n = n + 4
			params:add_le(f.SET_THERMAL_MITIGATION_REQ_thermalMitLevel, buffer(n, 4)); n = n + 4
		elseif (msg_type == 182) then
			-- UPDATE_VHT_OP_MODE_REQ
			params:add_le(f.UPDATE_VHT_OP_MODE_REQ_opMode, buffer(n, 2)); n = n + 2
			params:add_le(f.UPDATE_VHT_OP_MODE_REQ_staId, buffer(n, 2)); n = n + 2
		elseif (msg_type == 185) then
			-- GET_ROAM_RSSI_REQ
			params:add_le(f.GET_ROAM_RSSI_REQ_staId, buffer(n, 4)); n = n + 4
		elseif (msg_type == 191) then
			-- WLAN_ROAM_SCAN_OFFLOAD_REQ
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_RoamScanOffloadEnabled, buffer(n, 4)); n = n + 4
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_LookupThreshold, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_RoamRssiDiff, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ChannelCacheType, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_Command, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_StartScanReason, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanTimerPeriod, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborRoamScanRefreshPeriod, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanChannelMinTime, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanChannelMaxTime, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_EmptyRefreshScanPeriod, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ValidChannelCount, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ValidChannelList, buffer(n, 80)); n = n + 80
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_IsCCXEnabled, buffer(n, 4)); n = n + 4
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_us24GProbeSize, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_a24GProbeTemplate, buffer(n, 450)); n = n + 450
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_us5GProbeSize, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_a5GProbeTemplate, buffer(n, 450)); n = n + 450
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_nProbes, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_HomeAwayTime, buffer(n, 2)); n = n + 2
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_MAWCEnabled, buffer(n, 4)); n = n + 4
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ReservedBytes, buffer(n, 57)); n = n + 57

			-- connected network member
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ssId, buffer(n, 33)); n = n + 33
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_currAPbssid, buffer(n, 6)); n = n + 6
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_authentication, buffer(n, 4)); n = n + 4
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_encryption, buffer(n, 4)); n = n + 4
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_mcencryption, buffer(n, 4)); n = n + 4
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ChannelCount, buffer(n, 1)); n = n + 1
			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ChannelCache, buffer(n, 80)); n = n + 80

			params:add_le(f.WLAN_ROAM_SCAN_OFFLOAD_REQ_MDID, buffer(n, 3)); n = n + 3
		elseif ((msg_type_strings[msg_type] ~= nil) and
			(string.find(msg_type_strings[msg_type], "RSP") ~= nil)) then
			-- parse responses
			local status
			if (msg_type == 1) then
				-- START_RSP
				status = buffer(n, 2):le_uint()
				params:add_le(f.rsp_status, buffer(n, 2)); n = n + 2
				params:add_le(f.START_RSP_ucMaxStations, buffer(n, 1)); n = n + 1
				params:add_le(f.START_RSP_ucMaxBssids, buffer(n, 1)); n = n + 1
				fw_revision = buffer(n, 1)
				fw_version = buffer(n + 1, 1)
				fw_minor = buffer(n + 2, 1)
				fw_major = buffer(n + 3, 1)
				params:add_le(f.START_RSP_wcnssWlanVersion, buffer(n, 4)); n = n + 4
				params:add_le(f.START_RSP_wcnssCrmVersionString, buffer(n, 64)); n = n + 64
				params:add_le(f.START_RSP_wcnssWlanVersionString, buffer(n, 64)); n = n + 64
			elseif (msg_type == 7) then
				-- START_SCAN_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.START_SCAN_RSP_startTSF, buffer(n, 8)); n = n + 8
				params:add_le(f.START_SCAN_RSP_txMgmtPower, buffer(n, 1)); n = n + 1
			elseif (msg_type == 13) then
				-- CONFIG_STA_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.CONFIG_STA_RSP_staIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_bssIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_dpuIndex, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_bcastDpuIndex, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_bcastMgmtDpuIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_ucUcastSig, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_ucBcastSig, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_ucMgmtSig, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_STA_RSP_p2pCapableSta, buffer(n, 1)); n = n + 1
			elseif (msg_type == 15) then
				-- DELETE_STA_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.DELETE_STA_RSP_staId, buffer(n, 1)); n = n + 1
			elseif (msg_type == 17) then
				-- CONFIG_BSS_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.CONFIG_BSS_RSP_bssIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_dpuDescIndx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_ucastDpuSignature, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_bcastDpuDescIndx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_bcastDpuSignature, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_mgmtDpuDescIndx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_mgmtDpuSignature, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_bssStaIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_bssSelfStaIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_bssBcastStaIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.CONFIG_BSS_RSP_staMac, buffer(n, 6)); n = n + 6
				params:add_le(f.CONFIG_BSS_RSP_txMgmtPower, buffer(n, 1)); n = n + 1
			elseif (msg_type == 19) then
				-- DELETE_BSS_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.DELETE_BSS_RSP_bssIdx, buffer(n, 1)); n = n + 1
			elseif (msg_type == 21) then
				-- JOIN_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.JOIN_RSP_txMgmtPower, buffer(n, 1)); n = n + 1
			elseif (msg_type == 43) then
				-- CH_SWITCH_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.CH_SWITCH_RSP_channelNumber, buffer(n, 1)); n = n + 1
				params:add_le(f.CH_SWITCH_RSP_txMgmtPower, buffer(n, 1)); n = n + 1
				params:add_le(f.CH_SWITCH_RSP_bssId, buffer(n, 6)); n = n + 6
			elseif (msg_type == 47) then
				-- GET_STATS_RSP
				status = 0
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.GET_STATS_RSP_staId, buffer(n, 4)); n = n + 4
				params:add_le(f.GET_STATS_RSP_statsMask, buffer(n, 4)); n = n + 4
				params:add_le(f.GET_STATS_RSP_msgType, buffer(n, 2)); n = n + 2
				params:add_le(f.GET_STATS_RSP_msgLen, buffer(n, 2)); n = n + 2

				-- GET_STATS_RSP_summary
				local summary = params:add(buffer(n, 96), "Summary")
				local e = summary:add(buffer(n, 4), "retry_cnt")
				n = n + parse_stats_cnt(buffer(n, 16):tvb(), pinfo, e)
				--summary:add_le(f.GET_STATS_RSP_summary_retry_cnt, buffer(n, 16)); n = n + 16

				e = summary:add(buffer(n, 4), "multiple_retry_cnt")
				n = n + parse_stats_cnt(buffer(n, 16):tvb(), pinfo, e)
				--summary:add_le(f.GET_STATS_RSP_summary_multiple_retry_cnt, buffer(n, 16)); n = n + 16

				e = summary:add(buffer(n, 4), "tx_frm_cnt")
				n = n + parse_stats_cnt(buffer(n, 16):tvb(), pinfo, e)

				-- summary:add_le(f.GET_STATS_RSP_summary_tx_frm_cnt, buffer(n, 16)); n = n + 16
				summary:add_le(f.GET_STATS_RSP_summary_rx_frm_cnt, buffer(n, 4)); n = n + 4
				summary:add_le(f.GET_STATS_RSP_summary_frm_dup_cnt, buffer(n, 4)); n = n + 4

				--summary:add_le(f.GET_STATS_RSP_summary_fail_cnt, buffer(n, 16)); n = n + 16
				e = summary:add(buffer(n, 4), "fail_cnt")
				n = n + parse_stats_cnt(buffer(n, 16):tvb(), pinfo, e)

				summary:add_le(f.GET_STATS_RSP_summary_rts_fail_cnt, buffer(n, 4)); n = n + 4
				summary:add_le(f.GET_STATS_RSP_summary_ack_fail_cnt, buffer(n, 4)); n = n + 4
				summary:add_le(f.GET_STATS_RSP_summary_rts_succ_cnt, buffer(n, 4)); n = n + 4
				summary:add_le(f.GET_STATS_RSP_summary_rx_discard_cnt, buffer(n, 4)); n = n + 4
				summary:add_le(f.GET_STATS_RSP_summary_rx_error_cnt, buffer(n, 4)); n = n + 4
				summary:add_le(f.GET_STATS_RSP_summary_tx_byte_cnt, buffer(n, 4)); n = n + 4

				-- GET_STATS_RSP_ClassA
				local classA = params:add(buffer(n, 32), "ClassA")
				classA:add_le(f.GET_STATS_RSP_classA_rx_frag_cnt, buffer(n, 4)); n = n + 4
				classA:add_le(f.GET_STATS_RSP_classA_promiscuous_rx_frag_cnt, buffer(n, 4)); n = n + 4
				classA:add_le(f.GET_STATS_RSP_classA_rx_input_sensitivity, buffer(n, 4)); n = n + 4
				classA:add_le(f.GET_STATS_RSP_classA_max_pwr, buffer(n, 4)); n = n + 4
				classA:add_le(f.GET_STATS_RSP_classA_sync_fail_cnt, buffer(n, 4)); n = n + 4
				classA:add_le(f.GET_STATS_RSP_classA_tx_rate, buffer(n, 4)); n = n + 4
				classA:add_le(f.GET_STATS_RSP_classA_mcs_index, buffer(n, 4)); n = n + 4
				classA:add_le(f.GET_STATS_RSP_classA_tx_rate_flags, buffer(n, 4)); n = n + 4

			elseif (msg_type == 58) then
				-- ADD_BA_SESSION_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.ADD_BA_SESSION_RSP_baDialogToken, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_BA_SESSION_RSP_baTID, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_BA_SESSION_RSP_baBufferSize, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_BA_SESSION_RSP_baSessionID, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_BA_SESSION_RSP_winSize, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_BA_SESSION_RSP_STAID, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_BA_SESSION_RSP_SSN, buffer(n, 2)); n = n + 2
			elseif (msg_type == 60) then
				-- TRIGGER_BA_RSP
				params:add_le(f.bssid, buffer(n, 6)); n = n + 6
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				local num = buffer(n, 2):le_uint()
				params:add_le(f.trigger_ba_rsp_candidate_cnt, buffer(n, 2)); n = n + 2
				for i = 0, num-1 do
					local cand = subtree:add(wcn36xx, buffer(n, 22), i)
					cand:add_le(f.TRIGGER_BA_RSP_Cand_staAddr, buffer(n, 6)); n = n + 6
					for j = 0, 7 do
						cand:add_le(f.TRIGGER_BA_RSP_Cand_baInfo, buffer(n, 2)); n = n + 2
					end
				end
			elseif (msg_type == 75) then
				-- TL_HAL_FLUSH_AC_RSP
				params:add(f.tl_flush_ac_sta_id, buffer(n, 1)); n = n + 1
				params:add(f.tid, buffer(n, 1)); n = n + 1
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
			elseif (msg_type == 97) then
				-- ENTER_BMPS_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.ENTER_BMPS_RSP_bssIdx, buffer(n, 1)); n = n + 1
			elseif (msg_type == 116) then
				-- SET_MAX_TX_POWER_RSP
				params:add(f.set_max_tx_power_rsp_power, buffer(n, 1)); n = n + 1
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
			elseif (msg_type == 124) then
				-- START_OEM_DATA_RSP
				params:add(f.start_oem_data_data, buffer(n))
				status = 0
			elseif (msg_type == 126) then
				-- ADD_STA_SELF_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.ADD_STA_SELF_RSP_selfStaIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_STA_SELF_RSP_dpuIdx, buffer(n, 1)); n = n + 1
				params:add_le(f.ADD_STA_SELF_RSP_dpuSignature, buffer(n, 1)); n = n + 1
			elseif (msg_type == 128) then
				-- DEL_STA_SELF_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.DEL_STA_SELF_RSP_selfMacAddr, buffer(n, 6)); n = n + 6
			elseif (msg_type == 152) then
				-- UPDATE_SCAN_PARAM_RSP
				status = 0
			elseif (msg_type == 158) then
				-- 8023_MULTICAST_LIST_RSP
				params:add_le(f.MULTICAST_LIST_RSP_bssIdx, buffer(n, 1)); n = n + 1
			elseif (msg_type == 167) then
				status = 0
			elseif (msg_type == 176) then
				-- FEATURE_CAPS_EXCHANGE_RSP
				local caps = params:add(buffer(n, 16), "caps")
				n = n + parse_caps_bits(buffer(n, 16):tvb(), pinfo, caps)
				status = 0
			elseif (msg_type == 140) then
				-- ENABLE_RADAR_DETECT_RSP
				params:add_le(f.bssid, buffer(n, 6)); n = n + 6
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
			elseif (msg_type == 186) then
				-- GET_ROAM_RSSI_RSP
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
				params:add_le(f.GET_ROAM_RSSI_RSP_staId, buffer(n, 1)); n = n + 1
				params:add_le(f.GET_ROAM_RSSI_RSP_rssi, buffer(n, 1)); n = n + 1
			else
				-- all others
				status = buffer(n, 4):le_uint()
				params:add_le(f.rsp_status, buffer(n, 4)); n = n + 4
			end

			if (status == 0) then
				pinfo.cols.info:append(" success")
			else
				local failure_str
				if rsp_status_strings[status] ~= nil then
					failure_str = rsp_status_strings[status]:lower()
				else
					failure_str = status
				end
				pinfo.cols.info:append(" failed "..failure_str);
			end
			if (msg_type == 1) then
				pinfo.cols.info:append(", fw_version "..fw_major.."."..fw_minor.."."..fw_version.."."..fw_revision)
			end
		else
			-- unknown command
		end

		-- add data not parsed above
		if (buffer:len() > n) then
			params:add(f.data, buffer(n))
		end
	end
end

function get_fw_version()
	if (fw_major == 0) then
		version = 0
	elseif (not (fw_major == 1 and
		fw_minor == 4 and
		fw_version == 1 and
		fw_revision == 2)) then
		version = 1
	else
		version = 2
	end
	return version
end
-- Lookup strings
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
msg_type_strings[37] = "UPD_EDCA_PARAMS_RSP"
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
msg_type_strings[159] = "SET_PACKET_FILTER_REQ"
msg_type_strings[160] = "SET_PACKET_FILTER_RSP"
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

msg_type_strings[191] = "ROAM_SCAN_OFFLOAD_REQ"
msg_type_strings[192] = "ROAM_SCAN_OFFLOAD_RSP"
msg_type_strings[193] = "WIFI_PROXIMITY_REQ"
msg_type_strings[194] = "WIFI_PROXIMITY_RSP"
msg_type_strings[195] = "START_SPECULATIVE_PS_POLLS_REQ"
msg_type_strings[196] = "START_SPECULATIVE_PS_POLLS_RSP"
msg_type_strings[197] = "STOP_SPECULATIVE_PS_POLLS_IND"

msg_type_strings[198] = "TDLS_LINK_ESTABLISHED_REQ"
msg_type_strings[199] = "TDLS_LINK_ESTABLISHED_RSP"
msg_type_strings[200] = "TDLS_LINK_TEARDOWN_REQ"
msg_type_strings[201] = "TDLS_LINK_TEARDOWN_RSP"
msg_type_strings[202] = "TDLS_IND"
msg_type_strings[203] = "IBSS_PEER_INACTIVITY_IND"

msg_type_strings[211] = "LPHB_CFG_REQ "
msg_type_strings[212] = "LPHB_CFG_RSP"
msg_type_strings[213] = "LPHB_IND"
msg_type_strings[214] = "ADD_PERIODIC_TX_PTRN_IND"
msg_type_strings[215] = "DEL_PERIODIC_TX_PTRN_IND"
msg_type_strings[216] = "PERIODIC_TX_PTRN_FW_IND"
msg_type_strings[217] = "SET_MAX_TX_POWER_PER_BAND_REQ"
msg_type_strings[218] = "SET_MAX_TX_POWER_PER_BAND_RSP"
msg_type_strings[219] = "LBP_LEADER_REQ"
msg_type_strings[220] = "LBP_LEADER_RSP"
msg_type_strings[221] = "LBP_UPDATE_IND"
msg_type_strings[222] = "BATCHSCAN_SET_REQ"
msg_type_strings[223] = "BATCHSCAN_SET_RSP"
msg_type_strings[224] = "BATCHSCAN_TRIGGER_RESULT_IND"
msg_type_strings[225] = "BATCHSCAN_RESULT_IND"
msg_type_strings[226] = "BATCHSCAN_STOP_IND"
msg_type_strings[227] = "GET_IBSS_PEER_INFO_REQ"
msg_type_strings[228] = "GET_IBSS_PEER_INFO_RSP"
msg_type_strings[229] = "RATE_UPDATE_IND"
msg_type_strings[230] = "TX_FAIL_MONITOR_IND"
msg_type_strings[231] = "TX_FAIL_IND"
msg_type_strings[232] = "IP_FORWARD_TABLE_UPDATE_IND"
msg_type_strings[233] = "AVOID_FREQ_RANGE_IND"

msg_type_strings[254] = "START_HT40_OBSS_SCAN_IND"
msg_type_strings[255] = "STOP_HT40_OBSS_SCAN_IND"

driver_type_strings[0] = "production"
driver_type_strings[1] = "mfg"
driver_type_strings[2] = "dvt"

bond_state_strings[0] = "SINGLE_CHANNEL_CENTERED"
bond_state_strings[1] = "DOUBLE_CHANNEL_LOW_PRIMARY"
bond_state_strings[2] = "DOUBLE_CHANNEL_CENTERED"
bond_state_strings[3] = "DOUBLE_CHANNEL_HIGH_PRIMARY"
bond_state_strings[4] = "QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_CENTERED"
bond_state_strings[5] = "QUADRUPLE_CHANNEL_20MHZ_CENTERED_40MHZ_CENTERED"
bond_state_strings[6] = "QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_CENTERED"
bond_state_strings[7] = "QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_LOW"
bond_state_strings[8] = "QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_LOW"
bond_state_strings[9] = "QUADRUPLE_CHANNEL_20MHZ_LOW_40MHZ_HIGH "
bond_state_strings[10] = "QUADRUPLE_CHANNEL_20MHZ_HIGH_40MHZ_HIGH"

cfg_strings[0] = "STA_ID"
cfg_strings[1] = "CURRENT_TX_ANTENNA"
cfg_strings[2] = "CURRENT_RX_ANTENNA"
cfg_strings[3] = "LOW_GAIN_OVERRIDE"
cfg_strings[4] = "POWER_STATE_PER_CHAIN"
cfg_strings[5] = "CAL_PERIOD"
cfg_strings[6] = "CAL_CONTROL"
cfg_strings[7] = "PROXIMITY"
cfg_strings[8] = "NETWORK_DENSITY"
cfg_strings[9] = "MAX_MEDIUM_TIME"
cfg_strings[10] = "MAX_MPDUS_IN_AMPDU"
cfg_strings[11] = "RTS_THRESHOLD"
cfg_strings[12] = "SHORT_RETRY_LIMIT"
cfg_strings[13] = "LONG_RETRY_LIMIT"
cfg_strings[14] = "FRAGMENTATION_THRESHOLD"
cfg_strings[15] = "DYNAMIC_THRESHOLD_ZERO"
cfg_strings[16] = "DYNAMIC_THRESHOLD_ONE"
cfg_strings[17] = "DYNAMIC_THRESHOLD_TWO"
cfg_strings[18] = "FIXED_RATE"
cfg_strings[19] = "RETRYRATE_POLICY"
cfg_strings[20] = "RETRYRATE_SECONDARY"
cfg_strings[21] = "RETRYRATE_TERTIARY"
cfg_strings[22] = "FORCE_POLICY_PROTECTION"
cfg_strings[23] = "FIXED_RATE_MULTICAST_24GHZ"
cfg_strings[24] = "FIXED_RATE_MULTICAST_5GHZ"
cfg_strings[25] = "DEFAULT_RATE_INDEX_24GHZ"
cfg_strings[26] = "DEFAULT_RATE_INDEX_5GHZ"
cfg_strings[27] = "MAX_BA_SESSIONS"
cfg_strings[28] = "PS_DATA_INACTIVITY_TIMEOUT"
cfg_strings[29] = "PS_ENABLE_BCN_FILTER"
cfg_strings[30] = "PS_ENABLE_RSSI_MONITOR"
cfg_strings[31] = "NUM_BEACON_PER_RSSI_AVERAGE"
cfg_strings[32] = "STATS_PERIOD"
cfg_strings[33] = "CFP_MAX_DURATION"
cfg_strings[34] = "FRAME_TRANS_ENABLED"
cfg_strings[35] = "DTIM_PERIOD"
cfg_strings[36] = "EDCA_WMM_ACBK"
cfg_strings[37] = "EDCA_WMM_ACBE"
cfg_strings[38] = "EDCA_WMM_ACVO"
cfg_strings[39] = "EDCA_WMM_ACVI"
cfg_strings[40] = "BA_THRESHOLD_HIGH"
cfg_strings[41] = "MAX_BA_BUFFERS"
cfg_strings[42] = "RPE_POLLING_THRESHOLD"
cfg_strings[43] = "RPE_AGING_THRESHOLD_FOR_AC0_REG"
cfg_strings[44] = "RPE_AGING_THRESHOLD_FOR_AC1_REG"
cfg_strings[45] = "RPE_AGING_THRESHOLD_FOR_AC2_REG"
cfg_strings[46] = "RPE_AGING_THRESHOLD_FOR_AC3_REG"
cfg_strings[47] = "NO_OF_ONCHIP_REORDER_SESSIONS"
cfg_strings[48] = "PS_LISTEN_INTERVAL"
cfg_strings[49] = "PS_HEART_BEAT_THRESHOLD"
cfg_strings[50] = "PS_NTH_BEACON_FILTER"
cfg_strings[51] = "PS_MAX_PS_POLL"
cfg_strings[52] = "PS_MIN_RSSI_THRESHOLD"
cfg_strings[53] = "PS_RSSI_FILTER_PERIOD"
cfg_strings[54] = "PS_BROADCAST_FRAME_FILTER_ENABLE"
cfg_strings[55] = "PS_IGNORE_DTIM"
cfg_strings[56] = "PS_ENABLE_BCN_EARLY_TERM"
cfg_strings[57] = "DYNAMIC_PS_POLL_VALUE"
cfg_strings[58] = "PS_NULLDATA_AP_RESP_TIMEOUT"
cfg_strings[59] = "TELE_BCN_WAKEUP_EN"
cfg_strings[60] = "TELE_BCN_TRANS_LI"
cfg_strings[61] = "TELE_BCN_TRANS_LI_IDLE_BCNS"
cfg_strings[62] = "TELE_BCN_MAX_LI"
cfg_strings[63] = "TELE_BCN_MAX_LI_IDLE_BCNS"
cfg_strings[64] = "TX_PWR_CTRL_ENABLE"
cfg_strings[65] = "VALID_RADAR_CHANNEL_LIST"
cfg_strings[66] = "TX_POWER_24_20"
cfg_strings[67] = "TX_POWER_24_40"
cfg_strings[68] = "TX_POWER_50_20"
cfg_strings[69] = "TX_POWER_50_40"
cfg_strings[70] = "MCAST_BCAST_FILTER_SETTING"
cfg_strings[71] = "BCN_EARLY_TERM_WAKEUP_INTERVAL"
cfg_strings[72] = "MAX_TX_POWER_2_4"
cfg_strings[73] = "MAX_TX_POWER_5"
cfg_strings[74] = "INFRA_STA_KEEP_ALIVE_PERIOD"
cfg_strings[75] = "ENABLE_CLOSE_LOOP"
cfg_strings[76] = "BTC_EXECUTION_MODE"
cfg_strings[77] = "BTC_DHCP_BT_SLOTS_TO_BLOCK"
cfg_strings[78] = "BTC_A2DP_DHCP_BT_SUB_INTERVALS"
cfg_strings[79] = "PS_TX_INACTIVITY_TIMEOUT"
cfg_strings[80] = "WCNSS_API_VERSION"
cfg_strings[81] = "AP_KEEPALIVE_TIMEOUT"
cfg_strings[82] = "GO_KEEPALIVE_TIMEOUT"
cfg_strings[83] = "ENABLE_MC_ADDR_LIST"
cfg_strings[84] = "BTC_STATIC_LEN_INQ_BT"
cfg_strings[85] = "BTC_STATIC_LEN_PAGE_BT"
cfg_strings[86] = "BTC_STATIC_LEN_CONN_BT"
cfg_strings[87] = "BTC_STATIC_LEN_LE_BT"
cfg_strings[88] = "BTC_STATIC_LEN_INQ_WLAN"
cfg_strings[89] = "BTC_STATIC_LEN_PAGE_WLAN"
cfg_strings[90] = "BTC_STATIC_LEN_CONN_WLAN"
cfg_strings[91] = "BTC_STATIC_LEN_LE_WLAN"
cfg_strings[92] = "BTC_DYN_MAX_LEN_BT"
cfg_strings[93] = "BTC_DYN_MAX_LEN_WLAN"
cfg_strings[94] = "BTC_MAX_SCO_BLOCK_PERC"
cfg_strings[95] = "BTC_DHCP_PROT_ON_A2DP"
cfg_strings[96] = "BTC_DHCP_PROT_ON_SCO"
cfg_strings[97] = "ENABLE_UNICAST_FILTER"
cfg_strings[98] = "MAX_ASSOC_LIMIT"
cfg_strings[99] = "ENABLE_LPWR_IMG_TRANSITION"
cfg_strings[100] = "ENABLE_MCC_ADAPTIVE_SCHEDULER"
cfg_strings[101] = "ENABLE_DETECT_PS_SUPPORT"
cfg_strings[102] = "AP_LINK_MONITOR_TIMEOUT"
cfg_strings[103] = "BTC_DWELL_TIME_MULTIPLIER"
cfg_strings[103] = "BTC_DWELL_TIME_MULTIPLIER"
cfg_strings[104] = "ENABLE_TDLS_OXYGEN_MODE"
cfg_strings[105] = "ENABLE_NAT_KEEP_ALIVE_FILTER"
cfg_strings[106] = "ENABLE_SAP_OBSS_PROT"
cfg_strings[107] = "PSPOLL_DATA_RECEP_TIMEOUT"
cfg_strings[108] = "TDLS_PUAPSD_BUFFER_STA_CAPABLE"
cfg_strings[109] = "TDLS_PUAPSD_MASK"
cfg_strings[110] = "TDLS_PUAPSD_INACTIVITY_TIME"
cfg_strings[111] = "TDLS_PUAPSD_RX_FRAME_THRESHOLD_IN_SP"
cfg_strings[112] = "ANTENNA_DIVERSITY"
cfg_strings[113] = "ATH_DISABLE"
cfg_strings[114] = "FLEXCONNECT_POWER_FACTOR"
cfg_strings[115] = "ENABLE_ADAPTIVE_RX_DRAIN_FEATURE"
cfg_strings[116] = "TDLS_OFF_CHANNEL_CAPABLE"
cfg_strings[117] = "MWS_COEX_V1_WAN_FREQ"
cfg_strings[118] = "MWS_COEX_V1_WLAN_FREQ"
cfg_strings[119] = "MWS_COEX_V1_CONFIG"
cfg_strings[120] = "MWS_COEX_V1_CONFIG2"
cfg_strings[121] = "MWS_COEX_V2_WAN_FREQ"
cfg_strings[122] = "MWS_COEX_V2_WLAN_FREQ"
cfg_strings[123] = "MWS_COEX_V2_CONFIG"
cfg_strings[124] = "MWS_COEX_V2_CONFIG2"
cfg_strings[125] = "MWS_COEX_V3_WAN_FREQ"
cfg_strings[126] = "MWS_COEX_V3_WLAN_FREQ"
cfg_strings[127] = "MWS_COEX_V3_CONFIG"
cfg_strings[128] = "MWS_COEX_V3_CONFIG2"
cfg_strings[129] = "MWS_COEX_V4_WAN_FREQ"
cfg_strings[130] = "MWS_COEX_V4_WLAN_FREQ"
cfg_strings[131] = "MWS_COEX_V4_CONFIG"
cfg_strings[132] = "MWS_COEX_V4_CONFIG2"
cfg_strings[133] = "MWS_COEX_V5_WAN_FREQ"
cfg_strings[134] = "MWS_COEX_V5_WLAN_FREQ"
cfg_strings[135] = "MWS_COEX_V5_CONFIG"
cfg_strings[136] = "MWS_COEX_V5_CONFIG2"
cfg_strings[137] = "MWS_COEX_V6_WAN_FREQ"
cfg_strings[138] = "MWS_COEX_V6_WLAN_FREQ"
cfg_strings[139] = "MWS_COEX_V6_CONFIG"
cfg_strings[140] = "MWS_COEX_V6_CONFIG2"
cfg_strings[141] = "MWS_COEX_V7_WAN_FREQ"
cfg_strings[142] = "MWS_COEX_V7_WLAN_FREQ"
cfg_strings[143] = "MWS_COEX_V7_CONFIG"
cfg_strings[144] = "MWS_COEX_V7_CONFIG2"
cfg_strings[145] = "MWS_COEX_V8_WAN_FREQ"
cfg_strings[146] = "MWS_COEX_V8_WLAN_FREQ"
cfg_strings[147] = "MWS_COEX_V8_CONFIG"
cfg_strings[148] = "MWS_COEX_V8_CONFIG2"
cfg_strings[149] = "MWS_COEX_V9_WAN_FREQ"
cfg_strings[150] = "MWS_COEX_V9_WLAN_FREQ"
cfg_strings[151] = "MWS_COEX_V9_CONFIG"
cfg_strings[152] = "MWS_COEX_V9_CONFIG2"
cfg_strings[153] = "MWS_COEX_V10_WAN_FREQ"
cfg_strings[154] = "MWS_COEX_V10_WLAN_FREQ"
cfg_strings[155] = "MWS_COEX_V10_CONFIG"
cfg_strings[156] = "MWS_COEX_V10_CONFIG2"
cfg_strings[157] = "MWS_COEX_MODEM_BACKOFF"
cfg_strings[158] = "MWS_COEX_CONFIG1"
cfg_strings[159] = "MWS_COEX_CONFIG2"
cfg_strings[160] = "MWS_COEX_CONFIG3"
cfg_strings[161] = "MWS_COEX_CONFIG4"
cfg_strings[162] = "MWS_COEX_CONFIG5"
cfg_strings[163] = "MWS_COEX_CONFIG6"
cfg_strings[164] = "SAR_POWER_BACKOFF"
cfg_strings[165] = "GO_LINK_MONITOR_TIMEOUT"
cfg_strings[166] = "BTC_STATIC_OPP_WLAN_ACTIVE_WLAN_LEN"
cfg_strings[167] = "BTC_STATIC_OPP_WLAN_ACTIVE_BT_LEN"
cfg_strings[168] = "BTC_SAP_STATIC_OPP_WLAN_ACTIVE_WLAN_LEN"
cfg_strings[169] = "BTC_SAP_STATIC_OPP_WLAN_ACTIVE_BT_LEN"
cfg_strings[170] = "RMCAST_FIXED_RATE"
cfg_strings[171] = "ASD_PROBE_INTERVAL"
cfg_strings[172] = "ASD_TRIGGER_THRESHOLD"
cfg_strings[173] = "ASD_RTT_RSSI_HYST_THRESHOLD"
cfg_strings[174] = "BTC_CTS2S_ON_STA_DURING_SCO"

offload_type_strings[0] = "IPV4_ARP_REPLY_OFFLOAD"
offload_type_strings[1] = "IPV6_NEIGHBOR_DISCOVERY_OFFLOAD"
offload_type_strings[2] = "IPV6_NS_OFFLOAD"

sys_mode_strings[0] = "NORMAL"
sys_mode_strings[1] = "LEARN"
sys_mode_strings[2] = "SCAN"
sys_mode_strings[3] = "PROMISC"
sys_mode_strings[4] = "SUSPEND_LINK"
sys_mode_strings[5] = "ROAM_SCAN"
sys_mode_strings[6] = "ROAM_SUSPEND_LINK"

link_state_strings[0] = "IDLE"
link_state_strings[1] = "PREASSOC"
link_state_strings[2] = "POSTASSOC"
link_state_strings[3] = "AP"
link_state_strings[4] = "IBSS"
link_state_strings[5] = "BTAMP_PREASSOC"
link_state_strings[6] = "BTAMP_POSTASSOC"
link_state_strings[7] = "LINK_BTAMP_AP"
link_state_strings[8] = "BTAMP_STA"
link_state_strings[9] = "LEARN"
link_state_strings[10] = "SCAN"
link_state_strings[11] = "FINISH_SCAN"
link_state_strings[12] = "INIT_CAL"
link_state_strings[13] = "FINISH_CAL"
link_state_strings[14] = "LISTEN"

filter_type_strings[0] = "INVALID"
filter_type_strings[1] = "FILTER_PKT"
filter_type_strings[2] = "BUFFER_PKT"

filter_protocol_type_strings[0] = "INVALID"
filter_protocol_type_strings[1] = "MAC"
filter_protocol_type_strings[2] = "ARP"
filter_protocol_type_strings[3] = "IPV4"
filter_protocol_type_strings[4] = "IPV6"
filter_protocol_type_strings[5] = "UDP"

filter_cmp_type_strings[0] = "INVALID"
filter_cmp_type_strings[1] = "EQUAL"
filter_cmp_type_strings[2] = "MASK_EQUAL"
filter_cmp_type_strings[3] = "NOT_EQUAL"

del_ba_direction_strings[0] = "RECIPIENT"
del_ba_direction_strings[1] = "ORIGINATOR"

ani_ed_type_strings[0] = "NONE"
ani_ed_type_strings[1] = "WEP40"
ani_ed_type_strings[2] = "WEP104"
ani_ed_type_strings[3] = "TKIP"
ani_ed_type_strings[4] = "CCMP"
ani_ed_type_strings[5] = "WPI"
ani_ed_type_strings[6] = "AES_128_CMAC"
ani_ed_type_strings[7] = "NOT_IMPLEMENTED"

ani_wep_type_strings[0] = "WEP_STATIC"
ani_wep_type_strings[1] = "WEP_DYNAMIC"

bss_type_strings[0] = "INFRASTRUCTURE_MODE"
bss_type_strings[1] = "INFRA_AP_MODE"
bss_type_strings[2] = "IBSS_MODE"
bss_type_strings[3] = "BTAMP_STA_MODE"
bss_type_strings[4] = "BTAMP_AP_MODE"
bss_type_strings[5] = "AUTO_MODE"
bss_type_strings[6] = "DONOT_USE"

oper_mode_strings[0] = "AP"
oper_mode_strings[1] = "STA"

ht_oper_mode_strings[0] = "PURE"
ht_oper_mode_strings[1] = "OVERLAY_LEGACY"
ht_oper_mode_strings[2] = "NO_LEGACY_20MHZ_HT"
ht_oper_mode_strings[2] = "MIXED"

nw_type_strings[0] = "11A"
nw_type_strings[1] = "11B"
nw_type_strings[2] = "11G"
nw_type_strings[3] = "11N"
nw_type_strings[4] = "DONOT_USE"

sta_type_strings[0] = "SELF"
sta_type_strings[1] = "OTHER/PEER"
sta_type_strings[2] = "BSSID"
sta_type_strings[3] = "BCAST"

tx_channel_width_set_strings[0] = "20MHZ ONLY"
tx_channel_width_set_strings[1] = "20/40MHZ"

stop_reason_strings[0] = "SYS_RESET"
stop_reason_strings[1] = "DEEP_SLEEP"
stop_reason_strings[2] = "RF_KILL"

bt_amp_event_type_strings[0] = "START"
bt_amp_event_type_strings[1] = "STOP"
bt_amp_event_type_strings[2] = "TERMINATED"

thermal_mit_mode_strings[0] = "MODE_0"
thermal_mit_mode_strings[1] = "MODE_1"
thermal_mit_mode_strings[2] = "MODE_2"

thermal_mit_level_strings[0] = "LEVEL_0"
thermal_mit_level_strings[1] = "LEVEL_1"
thermal_mit_level_strings[2] = "LEVEL_2"
thermal_mit_level_strings[3] = "LEVEL_3"
thermal_mit_level_strings[4] = "LEVEL_4"

fw_caps_strings[0]  = "MCC"
fw_caps_strings[1]  = "P2P"
fw_caps_strings[2]  = "DOT11AC"
fw_caps_strings[3]  = "SLM_SESSIONIZATION"
fw_caps_strings[4]  = "DOT11AC_OPMODE"
fw_caps_strings[5]  = "SAP32STA"
fw_caps_strings[6]  = "TDLS"
fw_caps_strings[7]  = "P2P_GO_NOA_DECOUPLE_INIT_SCAN"
fw_caps_strings[8]  = "WLANACTIVE_OFFLOAD"
fw_caps_strings[9]  = "BEACON_OFFLOAD"
fw_caps_strings[10] = "SCAN_OFFLOAD"
fw_caps_strings[11] = "ROAM_OFFLOAD"
fw_caps_strings[12] = "BCN_MISS_OFFLOAD"
fw_caps_strings[13] = "STA_POWERSAVE"
fw_caps_strings[14] = "STA_ADVANCED_PWRSAVE"
fw_caps_strings[15] = "AP_UAPSD"
fw_caps_strings[16] = "AP_DFS"
fw_caps_strings[17] = "BLOCKACK"
fw_caps_strings[18] = "PHY_ERR"
fw_caps_strings[19] = "BCN_FILTER"
fw_caps_strings[20] = "RTT"
fw_caps_strings[21] = "RATECTRL"
fw_caps_strings[22] = "WOW"
fw_caps_strings[23] = "WLAN_ROAM_SCAN_OFFLOAD"
fw_caps_strings[24] = "SPECULATIVE_PS_POLL"
fw_caps_strings[25] = "SCAN_SCH"
fw_caps_strings[26] = "IBSS_HEARTBEAT_OFFLOAD"
fw_caps_strings[27] = "WLAN_SCAN_OFFLOAD"
fw_caps_strings[28] = "WLAN_PERIODIC_TX_PTRN"
fw_caps_strings[29] = "ADVANCE_TDLS"
fw_caps_strings[30] = "BATCH_SCAN"

rsp_status_strings[0] = "SUCCESS"
rsp_status_strings[1] = "INVAL"
rsp_status_strings[2] = "ALREADY"
rsp_status_strings[3] = "EMPTY"
rsp_status_strings[4] = "FAILURE"
rsp_status_strings[5] = "FAILURE"
rsp_status_strings[6] = "INVALID_PARAMETER"
rsp_status_strings[7] = "INVALID_STAIDX"
rsp_status_strings[8] = "DPU_DESCRIPTOR_TABLE_FULL"
rsp_status_strings[9] = "NO_INTERRUPTS"
rsp_status_strings[10] = "INTERRUPT_PRESENT"
rsp_status_strings[11] = "STA_TABLE_FULL"
rsp_status_strings[12] = "DUPLICATE_STA"
rsp_status_strings[13] = "BSSID_INVALID"
rsp_status_strings[14] = "STA_INVALID"
rsp_status_strings[15] = "DUPLICATE_BSSID"
rsp_status_strings[16] = "INVALID_BSSIDX"
rsp_status_strings[17] = "BSSID_TABLE_FULL"
rsp_status_strings[18] = "INVALID_SIGNATURE"
rsp_status_strings[19] = "INVALID_KEYID"
rsp_status_strings[20] = "SET_CHAN_ALREADY_ON_REQUESTED_CHAN"
rsp_status_strings[21] = "UMA_DESCRIPTOR_TABLE_FULL"
rsp_status_strings[22] = "DPU_MICKEY_TABLE_FULL"
rsp_status_strings[23] = "BA_RX_BUFFERS_FULL"
rsp_status_strings[24] = "BA_RX_MAX_SESSIONS_REACHED"
rsp_status_strings[25] = "BA_RX_INVALID_SESSION_ID"
rsp_status_strings[26] = "TIMER_START_FAILED"
rsp_status_strings[27] = "TIMER_STOP_FAILED"
rsp_status_strings[28] = "FAILED_ALLOC"
rsp_status_strings[29] = "NOTIFY_BSS_FAIL"
rsp_status_strings[30] = "DEL_STA_SELF_IGNORED_REF_COUNT_NOT_ZERO"
rsp_status_strings[31] = "ADD_STA_SELF_IGNORED_REF_COUNT_NOT_ZERO"
rsp_status_strings[32] = "FW_SEND_MSG_FAILED"
rsp_status_strings[33] = "BSS_DISCONN_BEACON_MISS"
rsp_status_strings[34] = "BSS_DISCONN_DEAUTH"
rsp_status_strings[35] = "BSS_DISCONN_DISASSOC"
rsp_status_strings[36] = "PHY_DATA_ABORT"
rsp_status_strings[37] = "PHY_INVALID_NV_FIELD"
rsp_status_strings[38] = "WLAN_BOOT_TEST_FAILURE"

coex_ind_type_strings[0] = "DISABLE_HB_MONITOR"
coex_ind_type_strings[1] = "ENABLE_HB_MONITOR"
coex_ind_type_strings[2] = "SCANS_ARE_COMPROMISED_BY_COEX"
coex_ind_type_strings[3] = "SCANS_ARE_NOT_COMPROMISED_BY_COEX"
coex_ind_type_strings[4] = "DISABLE_AGGREGATION_IN_2P4"
coex_ind_type_strings[5] = "ENABLE_AGGREGATION_IN_2P4"

keep_alive_packet_type_strings[0] = "NULL_PKT"
keep_alive_packet_type_strings[1] = "UNSOLICIT_ARP_RSP"

-- Protocol fields
f.msg_type = ProtoField.uint16("wcn36xx.msg_type", "msg_type", base.DEC, msg_type_strings)
f.msg_version = ProtoField.uint16("wcn36xx.msg_version", "msg_version")
f.len = ProtoField.uint32("wcn36xx.len", "len")
f.data = ProtoField.bytes("wcn36xx.data", "data")

f.bss_index = ProtoField.uint8("wcn36xx.bss_index", "bss_index", base.DEC)
f.bssid = ProtoField.ether("wcn36xx.bssid", "bssid")
f.sta_index = ProtoField.uint8("wcn36xx.sta_index", "sta_index")
f.tid = ProtoField.uint8("wcn36xx.tid", "tid")
f.ani_ed_enc_type = ProtoField.uint32("wcn36xx.ani_ed_enc_type", "enc_type", base.DEC, ani_ed_type_strings)

f.scan_channel = ProtoField.uint8("wcn36xx.scan_channel", "scan_channel")
f.scan_dot11d_enabled = ProtoField.bool("wcn36xx.scan_dot11d_enabled", "dot11d_enabled")
f.scan_dot11d_resolved = ProtoField.bool("wcn36xx.scan_dot11d_resolved", "dot11d_resolved")
f.scan_channel_count = ProtoField.uint8("wcn36xx.scan_channel_count", "channel_count", base.DEC)
f.scan_channels_i = ProtoField.uint8("wcn36xx.scan_channel", "scan_channel", base.DEC)
f.scan_active_min_ch_time = ProtoField.uint16("wcn36xx.scan_active_min_ch_time", "scan_active_min_ch_time", base.DEC)
f.scan_active_max_ch_time = ProtoField.uint16("wcn36xx.scan_active_max_ch_time", "scan_active_max_ch_time", base.DEC)
f.scan_passive_min_ch_time = ProtoField.uint16("wcn36xx.scan_active_min_ch_time", "scan_active_min_ch_time", base.DEC)
f.scan_passive_max_ch_time = ProtoField.uint16("wcn36xx.scan_active_max_ch_time", "scan_active_max_ch_time", base.DEC)
f.scan_phy_chan_bond_state = ProtoField.uint16("wcn36xx.scan_phy_chan_bond_state", "scan_phy_chan_bond_state", base.DEC, bond_state_strings)

f.nv_frag_number = ProtoField.uint16("wcn36xx.nv_frag_number", "frag_number", base.DEC)
f.nv_last_fragment = ProtoField.bool("wcn36xx.nv_last_fragment", "last_fragment")
f.nv_img_buffer_size = ProtoField.uint32("wcn36xx.nv_img_buffer_size", "nv_img_buffer_size", base.DEC)
f.nv_buffer = ProtoField.bytes("wcn36xx.nv_buffer", "nv_buffer")

f.CONFIGURE_RXP_FILTER_REQ_setMcstBcstFilterSetting = ProtoField.uint8("wcn36xx.CONFIGURE_RXP_FILTER_REQ_setMcstBcstFilterSetting", "setMcstBcstFilterSetting")
f.CONFIGURE_RXP_FILTER_REQ_setMcstBcstFilter = ProtoField.uint8("wcn36xx.CONFIGURE_RXP_FILTER_REQ_setMcstBcstFilter", "setMcstBcstFilter")

f.beacon_filter_capability_info = ProtoField.uint16("wcn36xx.beacon_filter_capability_info", "capability_info", base.HEX)
f.beacon_filter_capability_mask = ProtoField.uint16("wcn36xx.beacon_filter_capability_mask", "capability_mask", base.HEX)
f.beacon_filter_beacon_interval = ProtoField.uint16("wcn36xx.beacon_filter_beacon_interval", "beacon_interval", base.DEC)
f.beacon_filter_ie_num = ProtoField.uint16("wcn36xx.beacon_filter_ie_num", "ie_num", base.DEC)
f.beacon_filter_reserved = ProtoField.uint8("wcn36xx.beacon_filter_reserved", "reserved", base.HEX)

f.beacon_filter_element_id = ProtoField.uint8("wcn36xx.beacon_filter_element_id", "element_id", base.DEC)
f.beacon_filter_check_ie_presence = ProtoField.uint8("wcn36xx.beacon_filter_check_ie_presence", "check_ie_presence", base.DEC)
f.beacon_filter_n = ProtoField.uint8("wcn36xx.beacon_filter_n", "offset", base.DEC)
f.beacon_filter_value = ProtoField.uint8("wcn36xx.beacon_filter_value", "value", base.HEX)
f.beacon_filter_bitmask = ProtoField.uint8("wcn36xx.beacon_bitmask", "bitmask", base.HEX)
f.beacon_filter_ref = ProtoField.uint8("wcn36xx.beacon_filter_ref", "ref", base.HEX)

f.update_cfg_len = ProtoField.uint32("wcn36xx.update_cfg_len", "len")
f.cfg_id = ProtoField.uint16("wcn36xx.cfg_id", "id", base.DEC, cfg_strings)
f.cfg_len = ProtoField.uint32("wcn36xx.update_cfg_len", "len")
f.cfg_pad_bytes = ProtoField.bytes("wcn36xx.cfg_pad_bytes", "pad_bytes")
f.cfg_reserve = ProtoField.bytes("wcn36xx.cfg_reserve", "reserve")
f.cfg_body = ProtoField.bytes("wcn36xx.cfg_body", "body")
f.cfg_value = ProtoField.uint32("wcn36xx.cfg_value", "value")

f.start_driver_type = ProtoField.uint32("wcn36xx.start_driver_type", "type", base.DEC, msg_type_strings)
f.start_len = ProtoField.uint32("wcn36xx.start_len", "len")

f.STOP_REQ_reason = ProtoField.uint32("wcn36xx.STOP_REQ_reason", "reason", base.DEC, stop_reason_strings)

f.add_sta_self_addr = ProtoField.ether("wcn36xx.add_sta_self_addr", "addr")
f.add_sta_self_status = ProtoField.uint32("wcn36xx.add_sta_self_status", "status", base.HEX)

f.SIGNAL_BTAMP_EVENT_REQ_btAmpEventType = ProtoField.uint32("wcn36xx.SIGNAL_BTAMP_EVENT_REQ_btAmpEventType", "btAmpEventType", base.DEC, bt_amp_event_type_strings)

f.enter_bmps_tbtt = ProtoField.uint64("wcn36xx.enter_bmps_tbtt", "tbtt", base.HEX)
f.enter_bmps_dtim_count = ProtoField.uint8("wcn36xx.enter_bmps_dtim_count", "dtim_count")
f.enter_bmps_dtim_period = ProtoField.uint8("wcn36xx.enter_bmps_dtim_period", "dtim_period")
f.enter_bmps_rssi_filter_period = ProtoField.uint32("wcn36xx.enter_bmps_rssi_filter_period", "rssi_filter_period")
f.enter_bmps_num_beacon_per_rssi_average = ProtoField.uint32("wcn36xx.enter_bmps_num_beacon_per_rssi_average", "num_beacon_per_rssi_average")
f.enter_bmps_rssi_filter_enable = ProtoField.bool("wcn36xx.enter_bmps_rssi_filter_enable", "rssi_filter_enable")

f.exit_bmps_send_data_null = ProtoField.bool("wcn36xx.exit_bmps_send_data_null", "send_data_null")

f.add_ba_session_sta_index = ProtoField.uint16("wcn36xx.add_ba_session_sta_index", "sta_index")
f.add_ba_session_mac_addr = ProtoField.ether("wcn36xx.add_ba_session_mac_addr", "mac_addr", base.HEX)
f.add_ba_session_dialog_token = ProtoField.uint8("wcn36xx.add_ba_session_dialog_token", "dialog_token")
f.add_ba_session_policy = ProtoField.uint8("wcn36xx.add_ba_session_policy", "policy")
f.add_ba_session_buffer_size = ProtoField.uint16("wcn36xx.add_ba_session_buffer_size", "buffer_size")
f.add_ba_session_timeout = ProtoField.uint16("wcn36xx.add_ba_session_timeout", "timeout")
f.add_ba_session_ssn = ProtoField.uint16("wcn36xx.add_ba_session_ssn", "ssn", base.HEX)
f.add_ba_session_direction = ProtoField.uint8("wcn36xx.add_ba_session_direction", "direction")

f.add_ba_session_id = ProtoField.uint8("wcn36xx.add_ba_session_id", "session_id")
f.add_ba_win_size = ProtoField.uint8("wcn36xx.add_ba_win_size", "win_size")
f.add_ba_reorder_on_chip = ProtoField.uint8("wcn36xx.add_ba_reorder_on_chip", "reorder_on_chip", base.DEC)

f.del_ba_sta_id = ProtoField.uint16("wcn36xx.del_ba_sta_id", "sta_id")
f.del_ba_direction = ProtoField.uint8("wcn36xx.del_ba_direction", "direction", base.DEC, del_ba_direction_strings)

f.ADD_WOWL_BCAST_PTRN_ucPatternId = ProtoField.uint8("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPatternId", "ucPatternId")
f.ADD_WOWL_BCAST_PTRN_ucPatternByteOffset = ProtoField.uint8("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPatternByteOffset", "ucPatternByteOffset")
f.ADD_WOWL_BCAST_PTRN_ucPatternSize = ProtoField.uint8("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPatternSize", "ucPatternSize")
f.ADD_WOWL_BCAST_PTRN_ucPattern = ProtoField.bytes("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPattern", "ucPattern")
f.ADD_WOWL_BCAST_PTRN_ucPatternMaskSize = ProtoField.uint8("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPatternMaskSize", "ucPatternMaskSize")
f.ADD_WOWL_BCAST_PTRN_ucPatternMask = ProtoField.bytes("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPatternMask", "ucPatternMask")
f.ADD_WOWL_BCAST_PTRN_ucPatternExt = ProtoField.bytes("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPatternExt", "ucPatternExt")
f.ADD_WOWL_BCAST_PTRN_ucPatternMaskExt = ProtoField.bytes("wcn36xx.ADD_WOWL_BCAST_PTRN_ucPatternMaskExt", "ucPatternMaskExt")
f.ADD_WOWL_BCAST_PTRN_bssIdx = ProtoField.uint8("wcn36xx.ADD_WOWL_BCAST_PTRN_bssIdx", "bssIdx")

f.DEL_WOWL_BCAST_PTRN_ucPatternId = ProtoField.uint8("wcn36xx.DEL_WOWL_BCAST_PTRN_ucPatternId", "ucPatternId")
f.DEL_WOWL_BCAST_PTRN_bssIdx = ProtoField.uint8("wcn36xx.DEL_WOWL_BCAST_PTRN_bssIdx", "bssIdx")

f.ENTER_WOWL_REQ_ucMagicPktEnable = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucMagicPktEnable", "ucMagicPktEnable")
f.ENTER_WOWL_REQ_magicPtrn = ProtoField.ether("wcn36xx.ENTER_WOWL_REQ_magicPtrn", "magicPtrn")
f.ENTER_WOWL_REQ_ucPatternFilteringEnable = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucPatternFilteringEnable", "ucPatternFilteringEnable")
f.ENTER_WOWL_REQ_ucUcastPatternFilteringEnable = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucUcastPatternFilteringEnable", "ucUcastPatternFilteringEnable")
f.ENTER_WOWL_REQ_ucWowChnlSwitchRcv = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWowChnlSwitchRcv", "ucWowChnlSwitchRcv")
f.ENTER_WOWL_REQ_ucWowDeauthRcv = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWowDeauthRcv", "ucWowDeauthRcv")
f.ENTER_WOWL_REQ_ucWowDisassocRcv = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWowDisassocRcv", "ucWowDisassocRcv")
f.ENTER_WOWL_REQ_ucWowMaxMissedBeacons = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWowMaxMissedBeacons", "ucWowMaxMissedBeacons")
f.ENTER_WOWL_REQ_ucWowMaxSleepUsec = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWowMaxSleepUsec", "ucWowMaxSleepUsec")
f.ENTER_WOWL_REQ_ucWoWEAPIDRequestEnable = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWoWEAPIDRequestEnable", "ucWoWEAPIDRequestEnable")
f.ENTER_WOWL_REQ_ucWoWEAPOL4WayEnable = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWoWEAPOL4WayEnable", "ucWoWEAPOL4WayEnable")
f.ENTER_WOWL_REQ_ucWowNetScanOffloadMatch = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWowNetScanOffloadMatch", "ucWowNetScanOffloadMatch")
f.ENTER_WOWL_REQ_ucWowGTKRekeyError = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWowGTKRekeyError", "ucWowGTKRekeyError")
f.ENTER_WOWL_REQ_ucWoWBSSConnLoss = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_ucWoWBSSConnLoss", "ucWoWBSSConnLoss")
f.ENTER_WOWL_REQ_bssIdx = ProtoField.uint8("wcn36xx.ENTER_WOWL_REQ_bssIdx", "bssIdx")

f.EXIT_WOWL_REQ_bssIdx = ProtoField.uint8("wcn36xx.EXIT_WOWL_REQ_bssIdx", "bssIdx")

f.host_offload_type = ProtoField.uint8("wcn36xx.host_offload_type", "type", base.DEC, offload_type_strings)
f.host_offload_enable = ProtoField.bool("wcn36xx.host_offload_enable", "enable")
f.host_offload_ipv4 = ProtoField.ipv4("wcn36xx.host_offload_ipv4", "ipv4")
f.host_offload_ipv6 = ProtoField.ipv6("wcn36xx.host_offload_ipv6", "ipv6")
f.ns_offload_src_ipv6 = ProtoField.ipv6("wcn36xx.ns_offload_src_ipv6", "src_ipv6")
f.ns_offload_self_ipv6 = ProtoField.ipv6("wcn36xx.ns_offload_self_ipv6", "self_ipv6")
f.ns_offload_target_ipv6 = ProtoField.ipv6("wcn36xx.ns_offload_target_ipv6", "target_ipv6")
f.ns_offload_target_ipv6_2 = ProtoField.ipv6("wcn36xx.ns_offload_target_ipv6_2", "target_ipv6_2")
f.ns_offload_self_addr = ProtoField.ether("wcn36xx.ns_offload_target_self_addr", "self_addr")
f.ns_offload_valid = ProtoField.uint8("wcn36xx.ns_offload_valud", "valid", base.HEX)
f.ns_offload_reserved2 = ProtoField.uint8("wcn36xx.ns_offload_reserved2", "reserved2")
f.ns_offload_slot_index = ProtoField.uint32("wcn36xx.ns_offload_slot_index", "slot_index")

f.set_rssi_threshold_t1 = ProtoField.int8("wcn36xx.set_rssi_threshold_t1", "t1")
f.set_rssi_threshold_t2 = ProtoField.int8("wcn36xx.set_rssi_threshold_t2", "t2")
f.set_rssi_threshold_t3 = ProtoField.int8("wcn36xx.set_rssi_threshold_t3", "t3")
f.set_rssi_threshold_t1pos = ProtoField.bool("wcn36xx.set_rssi_threshold_t1pos", "t1posnotify")
f.set_rssi_threshold_t1neg = ProtoField.bool("wcn36xx.set_rssi_threshold_t1neg", "t1negnotify")
f.set_rssi_threshold_t2pos = ProtoField.bool("wcn36xx.set_rssi_threshold_t2pos", "t2posnotify")
f.set_rssi_threshold_t2neg = ProtoField.bool("wcn36xx.set_rssi_threshold_t2neg", "t2negnotify")
f.set_rssi_threshold_t3pos = ProtoField.bool("wcn36xx.set_rssi_threshold_t3pos", "t3posnotify")
f.set_rssi_threshold_t3neg = ProtoField.bool("wcn36xx.set_rssi_threshold_t3ned", "t3negnotify")

f.multicast_list_data_offset = ProtoField.uint8("wcn36xx.multicast_list_data_offset", "data_offset")
f.multicast_list_addr_count = ProtoField.uint32("wcn36xx.multicast_list_addr_count", "addr_count")
f.multicast_list_address = ProtoField.ether("wcn36xx.multicast_list_address", "address")
f.multicast_list_unused = ProtoField.bytes("wcn36xx.multicast_list_unused", "unused")

f.rcv_packet_filter_id = ProtoField.uint8("wcn36xx.rcv_packet_filter_id", "id")
f.rcv_packet_filter_type = ProtoField.uint8("wcn36xx.rcv_packet_filter_type", "type", base.HEX, filter_type_strings)
f.rcv_packet_filter_params_count = ProtoField.uint8("wcn36xx.rcv_packet_filter_id", "params_count")
f.rcv_packet_filter_coalesce_time = ProtoField.uint32("wcn36xx.rcv_packet_filter_coalesce_time", "coalesce_time")
f.rcv_packet_filter_param_protocol_layer = ProtoField.uint8("wcn36xx.rcv_packet_filter_param_protocol_layer", "protocol_layer", base.HEX, filter_protocol_type_strings)
f.rcv_packet_filter_param_cmp_flag = ProtoField.uint8("wcn36xx.rcv_packet_filter_param_cmp_flag", "cmp_flag", base.HEX, filter_cmp_type_strings)
f.rcv_packet_filter_param_data_length = ProtoField.uint16("wcn36xx.rcv_packet_filter_param_data_length", "data_length")
f.rcv_packet_filter_param_data_offset = ProtoField.uint8("wcn36xx.rcv_packet_filter_param_data_offset", "data_offset")
f.rcv_packet_filter_param_reserved = ProtoField.uint8("wcn36xx.rcv_packet_filter_param_reserved", "reserved")
f.rcv_packet_filter_param_compare_data = ProtoField.bytes("wcn36xx.rcv_packet_filter_param_compare_data", "compare_data")
f.rcv_packet_filter_param_data_mask = ProtoField.bytes("wcn36xx.rcv_packet_filter_param_data_mask", "data_mask")

f.set_power_params_ignore_dtim = ProtoField.bool("wcn36xx.set_power_params_ignore_dtim", "ignore_dtim")
f.set_power_params_dtim_period = ProtoField.uint32("wcn36xx.set_power_params_dtim_period", "dtim_period")
f.set_power_params_listen_interval = ProtoField.uint32("wcn36xx.set_power_params_listen_interval", "listen_interval")
f.set_power_params_bcast_mcast_filter = ProtoField.uint32("wcn36xx.set_power_params_mcast_filter", "mcast_filter")
f.set_power_params_enable_bet = ProtoField.bool("wcn36xx.set_power_params_enable_bet", "enable_bet")
f.set_power_params_bet_interval = ProtoField.uint32("wcn36xx.set_power_params_bet_interval", "bet_interval")

f.ch_switch_channel_number = ProtoField.uint8("wcn36xx.ch_switch_channel_number", "channel")
f.ch_switch_local_power_constraint = ProtoField.uint8("wcn36xx.ch_switch_power_constraint", "power_constraint")
f.ch_switch_secondary_channel_offset = ProtoField.uint32("wcn36xx.ch_switch_secondary_channel_offset", "secondary_channel_offset", base.DEC, bond_state_strings)
f.ch_switch_tx_mgmt_power = ProtoField.uint8("wcn36xx.ch_switch_tx_mgmt_power", "tx_mgmt_power")
f.ch_switch_max_tx_power = ProtoField.uint8("wcn36xx.ch_switch_max_tx_power", "max_tx_power")
f.ch_switch_self_sta_mac_addr = ProtoField.ether("wcn36xx.ch_switch_self_sta_mac_addr", "self_sta_mac_addr")

f.init_scan_mode = ProtoField.uint32("wcn36xx.init_scan_mode", "mode", base.DEC, sys_mode_strings)
f.init_scan_notify = ProtoField.uint8("wcn36xx.init_scan_notify", "notify")
f.init_scan_frame_type = ProtoField.uint8("wcn36xx.init_scan_frame_type", "frame_type")
f.init_scan_frame_len = ProtoField.uint8("wcn36xx.init_scan_frame_len", "frame_len")

f.hal_mac_frame_ctl = ProtoField.uint16("wcn36xx.hal_mac_frame_ctl", "frame_ctl")
f.hal_mac_mgmt_hdr_duration_lo = ProtoField.uint8("wcn36xx.hal_mac_mgmt_hdr_duration_lo", "duration_lo")
f.hal_mac_mgmt_hdr_duration_hi = ProtoField.uint8("wcn36xx.hal_mac_mgmt_hdr_duration_hi", "duration_hi")
f.hal_mac_mgmt_hdr_da = ProtoField.bytes("wcn36xx.hal_mac_mgmt_hdr_da", "hdr_da")
f.hal_mac_mgmt_hdr_sa = ProtoField.bytes("wcn36xx.hal_mac_mgmt_hdr_sa", "hdr_sa")
f.hal_mac_mgmt_hdr_seq_ctl = ProtoField.uint16("wcn36xx.hal_mac_mgmt_hdr_seq_ctl", "seq_ctl")

f.hal_scan_entry_bss_index = ProtoField.bytes("wcn36xx.hal_scan_entry_bss_index", "bss_index")
f.hal_scan_entry_active_bss_count = ProtoField.uint8("wcn36xx.hal_scan_entry_active_bss_count", "active_bss_count")

f.set_link_st_state = ProtoField.uint32("wcn36xx.set_link_st_state", "state", base.DEC, link_state_strings)
f.set_link_st_self_mac_addr = ProtoField.ether("wcn36xx.set_link_st_self_mac_addr", "self_mac_addr")

f.get_stats_sta_id = ProtoField.uint32("wcn36xx.get_stats_sta_id", "sta_id", base.DEC)
f.get_stats_stats_mask = ProtoField.uint32("wcn36xx.get_stats_stats_mask", "stats_mask", base.HEX)

f.join_channel = ProtoField.uint8("wcn36xx.join_channel", "channel")
f.join_self_sta_mac_addr = ProtoField.ether("wcn36xx.join_self_sta_mac_addr", "self_sta_mac_addr")
f.join_local_power_constraint = ProtoField.uint8("wcn36xx.join_local_power_constraint", "local_power_constraint")
f.join_secondary_channel_offset = ProtoField.uint32("wcn36xx.join_secondary_channel_offset", "secondary_channel_offset", base.DEC, bond_state_strings)
f.join_link_state = ProtoField.uint32("wcn36xx.join_link_st_state", "state", base.DEC, link_state_strings)
f.join_max_tx_power = ProtoField.int8("wcn36xx.join_max_tx_power", "max_tx_power")

f.rmv_bsskey_key_id = ProtoField.int8("wcn36xx.rmv_bsskey_key_id", "key_id")
f.rmv_bsskey_wep_type = ProtoField.uint32("wcn36xx.rmv_bsskey_wep_type", "wep_type", base.DEC, ani_wep_type_strings)

f.rmv_stakey_sta_index = ProtoField.int16("wcn36xx.rmv_stakey_sta_index", "sta_index")
f.rmv_stakey_key_id = ProtoField.int8("wcn36xx.rmv_stakey_key_id", "key_id")
f.rmv_stakey_unicast= ProtoField.bool("wcn36xx.rmv_stakey_unicast", "unicast")

f.rsp_status = ProtoField.uint32("wcn36xx.rsp_status", "status", base.HEX, rsp_status_strings)
f.start_rsp_fw_major = ProtoField.uint8("wcn36xx.start_rsp_fw_major", "fw_major")
f.start_rsp_fw_minor = ProtoField.uint8("wcn36xx.start_rsp_fw_minor", "fw_minor")
f.start_rsp_fw_version = ProtoField.uint8("wcn36xx.start_rsp_fw_version", "fw_version")
f.start_rsp_fw_revision = ProtoField.uint8("wcn36xx.start_rsp_fw_revision", "fw_revision")

f.tl_flush_ac_sta_id = ProtoField.uint8("wcn36xx.tl_flush_ac_sta_id", "sta_id")

f.set_max_tx_power_rsp_power = ProtoField.uint8("wcn36xx.set_max_tx_power_rsp_power", "power")

f.trigger_ba_rsp_candidate_cnt = ProtoField.uint16("wcn36xx.trigger_ba_rsp_candidate_cnt", "candidate_cnt")

f.CONFIG_STA_REQ_bssId = ProtoField.ether("wcn36xx.CONFIG_STA_REQ_bssId", "bssId")
f.CONFIG_STA_REQ_assocId = ProtoField.uint16("wcn36xx.CONFIG_STA_REQ_assocId", "assocId")
f.CONFIG_STA_REQ_staType = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_staType", "staType", base.DEC, sta_type_strings)
f.CONFIG_STA_REQ_shortPreambleSupported = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_shortPreambleSupported", "shortPreambleSupported")
f.CONFIG_STA_REQ_staMac = ProtoField.ether("wcn36xx.CONFIG_STA_REQ_staMac", "staMac")
f.CONFIG_STA_REQ_listenInterval = ProtoField.uint16("wcn36xx.CONFIG_STA_REQ_listenInterval", "listenInterval")
f.CONFIG_STA_REQ_wmmEnabled = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_wmmEnabled", "wmmEnabled")
f.CONFIG_STA_REQ_htCapable = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_htCapable", "htCapable")
f.CONFIG_STA_REQ_txChannelWidthSet = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_txChannelWidthSet", "txChannelWidthSet", base.DEC, tx_channel_width_set_strings)
f.CONFIG_STA_REQ_rifsMode = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_rifsMode", "rifsMode")
f.CONFIG_STA_REQ_lsigTxopProtection = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_lsigTxopProtection", "lsigTxopProtection")
f.CONFIG_STA_REQ_maxAmpduSize = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_maxAmpduSize", "maxAmpduSize")
f.CONFIG_STA_REQ_maxAmpduDensity = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_maxAmpduDensity", "maxAmpduDensity")
f.CONFIG_STA_REQ_maxAmsduSize = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_maxAmsduSize", "maxAmsduSize")
f.CONFIG_STA_REQ_fShortGI40Mhz = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_fShortGI40Mhz", "fShortGI40Mhz")
f.CONFIG_STA_REQ_fShortGI20Mhz = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_fShortGI20Mhz", "fShortGI20Mhz")
f.CONFIG_STA_REQ_rmfEnabled = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_rmfEnabled", "rmfEnabled")
f.CONFIG_STA_REQ_encryptType = ProtoField.uint32("wcn36xx.CONFIG_STA_REQ_encryptType", "encryptType")
f.CONFIG_STA_REQ_action = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_action", "action")
f.CONFIG_STA_REQ_uAPSD = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_uAPSD", "uAPSD")
f.CONFIG_STA_REQ_maxSPLen = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_maxSPLen", "maxSPLen")
f.CONFIG_STA_REQ_greenFieldCapable = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_greenFieldCapable", "greenFieldCapable")
f.CONFIG_STA_REQ_mimoPS = ProtoField.uint32("wcn36xx.CONFIG_STA_REQ_mimoPS", "mimoPS")
f.CONFIG_STA_REQ_delayedBASupport = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_delayedBASupport", "delayedBASupport")
f.CONFIG_STA_REQ_us32MaxAmpduDuration = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_us32MaxAmpduDuration", "us32MaxAmpduDuration")
f.CONFIG_STA_REQ_fDsssCckMode40Mhz = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_fDsssCckMode40Mhz", "fDsssCckMode40Mhz")
f.CONFIG_STA_REQ_staIdx = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_staIdx", "staIdx")
f.CONFIG_STA_REQ_bssIdx = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_bssIdx", "bssIdx")
f.CONFIG_STA_REQ_p2pCapableSta = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_p2pCapableSta", "p2pCapableSta")
f.CONFIG_STA_REQ_reserved = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_reserved", "reserved")
f.CONFIG_STA_REQ_supportedRates = ProtoField.bytes("wcn36xx.CONFIG_STA_REQ_supportedRates", "supportedRates")

f.CONFIG_STA_REQ_V1_bssId = ProtoField.ether("wcn36xx.CONFIG_STA_REQ_V1_bssId", "bssId")
f.CONFIG_STA_REQ_V1_assocId = ProtoField.uint16("wcn36xx.CONFIG_STA_REQ_V1_assocId", "assocId")
f.CONFIG_STA_REQ_V1_staType = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_staType", "staType", base.DEC, sta_type_strings)
f.CONFIG_STA_REQ_V1_shortPreambleSupported = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_shortPreambleSupported", "shortPreambleSupported")
f.CONFIG_STA_REQ_V1_staMac = ProtoField.ether("wcn36xx.CONFIG_STA_REQ_V1_staMac", "staMac")
f.CONFIG_STA_REQ_V1_listenInterval = ProtoField.uint16("wcn36xx.CONFIG_STA_REQ_V1_listenInterval", "listenInterval")
f.CONFIG_STA_REQ_V1_wmmEnabled = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_wmmEnabled", "wmmEnabled")
f.CONFIG_STA_REQ_V1_htCapable = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_htCapable", "htCapable")
f.CONFIG_STA_REQ_V1_txChannelWidthSet = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_txChannelWidthSet", "txChannelWidthSet", base.DEC, tx_channel_width_set_strings)
f.CONFIG_STA_REQ_V1_rifsMode = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_rifsMode", "rifsMode")
f.CONFIG_STA_REQ_V1_lsigTxopProtection = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_lsigTxopProtection", "lsigTxopProtection")
f.CONFIG_STA_REQ_V1_maxAmpduSize = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_maxAmpduSize", "maxAmpduSize")
f.CONFIG_STA_REQ_V1_maxAmpduDensity = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_maxAmpduDensity", "maxAmpduDensity")
f.CONFIG_STA_REQ_V1_maxAmsduSize = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_maxAmsduSize", "maxAmsduSize")
f.CONFIG_STA_REQ_V1_fShortGI40Mhz = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_fShortGI40Mhz", "fShortGI40Mhz")
f.CONFIG_STA_REQ_V1_fShortGI20Mhz = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_fShortGI20Mhz", "fShortGI20Mhz")
f.CONFIG_STA_REQ_V1_rmfEnabled = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_rmfEnabled", "rmfEnabled")
f.CONFIG_STA_REQ_V1_encryptType = ProtoField.uint32("wcn36xx.CONFIG_STA_REQ_V1_encryptType", "encryptType")
f.CONFIG_STA_REQ_V1_action = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_action", "action")
f.CONFIG_STA_REQ_V1_uAPSD = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_uAPSD", "uAPSD")
f.CONFIG_STA_REQ_V1_maxSPLen = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_maxSPLen", "maxSPLen")
f.CONFIG_STA_REQ_V1_greenFieldCapable = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_greenFieldCapable", "greenFieldCapable")
f.CONFIG_STA_REQ_V1_mimoPS = ProtoField.uint32("wcn36xx.CONFIG_STA_REQ_V1_mimoPS", "mimoPS")
f.CONFIG_STA_REQ_V1_delayedBASupport = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_delayedBASupport", "delayedBASupport")
f.CONFIG_STA_REQ_V1_us32MaxAmpduDuration = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_us32MaxAmpduDuration", "us32MaxAmpduDuration")
f.CONFIG_STA_REQ_V1_fDsssCckMode40Mhz = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_fDsssCckMode40Mhz", "fDsssCckMode40Mhz")
f.CONFIG_STA_REQ_V1_staIdx = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_staIdx", "staIdx")
f.CONFIG_STA_REQ_V1_bssIdx = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_bssIdx", "bssIdx")
f.CONFIG_STA_REQ_V1_p2pCapableSta = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_p2pCapableSta", "p2pCapableSta")
f.CONFIG_STA_REQ_V1_misc_flags = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_misc_flags", "misc_flags")
f.CONFIG_STA_REQ_V1_supportedRates = ProtoField.bytes("wcn36xx.CONFIG_STA_REQ_V1_supportedRates", "supportedRates")
f.CONFIG_STA_REQ_V1_vhtCapable = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_vhtCapable", "vhtCapable")
f.CONFIG_STA_REQ_V1_vhtTxChannelWidthSet = ProtoField.uint8("wcn36xx.CONFIG_STA_REQ_V1_vhtTxChannelWidthSet", "vhtTxChannelWidthSet")

f.CONFIG_BSS_bssId = ProtoField.ether("wcn36xx.CONFIG_BSS_bssId", "bssId")
f.CONFIG_BSS_selfMacAddr = ProtoField.ether("wcn36xx.CONFIG_BSS_selfMacAddr", "selfMacAddr")
f.CONFIG_BSS_bssType = ProtoField.uint32("wcn36xx.CONFIG_BSS_bssType", "bssType", base.DEC, bss_type_strings)
f.CONFIG_BSS_operMode = ProtoField.uint8("wcn36xx.CONFIG_BSS_operMode", "operMode", base.DEC, oper_mode_strings)
f.CONFIG_BSS_nwType = ProtoField.uint32("wcn36xx.CONFIG_BSS_nwType", "nwType", base.DEC, nw_type_strings)
f.CONFIG_BSS_shortSlotTimeSupported = ProtoField.uint8("wcn36xx.CONFIG_BSS_shortSlotTimeSupported", "shortSlotTimeSupported")
f.CONFIG_BSS_llaCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_llaCoexist", "llaCoexist")
f.CONFIG_BSS_llbCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_llbCoexist", "llbCoexist")
f.CONFIG_BSS_llgCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_llgCoexist", "llgCoexist")
f.CONFIG_BSS_ht20Coexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_ht20Coexist", "ht20Coexist")
f.CONFIG_BSS_llnNonGFCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_llnNonGFCoexist", "llnNonGFCoexist")
f.CONFIG_BSS_fLsigTXOPProtectionFullSupport = ProtoField.uint8("wcn36xx.CONFIG_BSS_fLsigTXOPProtectionFullSupport", "fLsigTXOPProtectionFullSupport")
f.CONFIG_BSS_fRIFSMode = ProtoField.uint8("wcn36xx.CONFIG_BSS_fRIFSMode", "fRIFSMode")
f.CONFIG_BSS_beaconInterval = ProtoField.uint16("wcn36xx.CONFIG_BSS_beaconInterval", "beaconInterval")
f.CONFIG_BSS_dtimPeriod = ProtoField.uint8("wcn36xx.CONFIG_BSS_dtimPeriod", "dtimPeriod")
f.CONFIG_BSS_txChannelWidthSet = ProtoField.uint8("wcn36xx.CONFIG_BSS_txChannelWidthSet", "txChannelWidthSet", base.DEC, tx_channel_width_set_strings)
f.CONFIG_BSS_currentOperChannel = ProtoField.uint8("wcn36xx.CONFIG_BSS_currentOperChannel", "currentOperChannel")
f.CONFIG_BSS_currentExtChannel = ProtoField.uint8("wcn36xx.CONFIG_BSS_currentExtChannel", "currentExtChannel")
f.CONFIG_BSS_reserved = ProtoField.uint8("wcn36xx.CONFIG_BSS_reserved", "reserved")
f.CONFIG_BSS_ssId = ProtoField.bytes("wcn36xx.CONFIG_BSS_ssId", "ssId")
f.CONFIG_BSS_action = ProtoField.uint8("wcn36xx.CONFIG_BSS_action", "action")
f.CONFIG_BSS_rateSet = ProtoField.bytes("wcn36xx.CONFIG_BSS_rateSet", "rateSet")
f.CONFIG_BSS_htCapable = ProtoField.uint8("wcn36xx.CONFIG_BSS_htCapable", "htCapable")
f.CONFIG_BSS_obssProtEnabled = ProtoField.uint8("wcn36xx.CONFIG_BSS_obssProtEnabled", "obssProtEnabled")
f.CONFIG_BSS_rmfEnabled = ProtoField.uint8("wcn36xx.CONFIG_BSS_rmfEnabled", "rmfEnabled")
f.CONFIG_BSS_htOperMode = ProtoField.uint32("wcn36xx.CONFIG_BSS_htOperMode", "htOperMode", base.DEC, ht_oper_mode_strings)
f.CONFIG_BSS_dualCTSProtection = ProtoField.uint8("wcn36xx.CONFIG_BSS_dualCTSProtection", "dualCTSProtection")
f.CONFIG_BSS_ucMaxProbeRespRetryLimit = ProtoField.uint8("wcn36xx.CONFIG_BSS_ucMaxProbeRespRetryLimit", "ucMaxProbeRespRetryLimit")
f.CONFIG_BSS_bHiddenSSIDEn = ProtoField.uint8("wcn36xx.CONFIG_BSS_bHiddenSSIDEn", "bHiddenSSIDEn")
f.CONFIG_BSS_bProxyProbeRespEn = ProtoField.uint8("wcn36xx.CONFIG_BSS_bProxyProbeRespEn", "bProxyProbeRespEn")
f.CONFIG_BSS_edcaParamsValid = ProtoField.uint8("wcn36xx.CONFIG_BSS_edcaParamsValid", "edcaParamsValid")
f.CONFIG_BSS_acbe = ProtoField.uint32("wcn36xx.CONFIG_BSS_acbe", "acbe")
f.CONFIG_BSS_acbk = ProtoField.uint32("wcn36xx.CONFIG_BSS_acbk", "acbk")
f.CONFIG_BSS_acvi = ProtoField.uint32("wcn36xx.CONFIG_BSS_acvi", "acvi")
f.CONFIG_BSS_acvo = ProtoField.uint32("wcn36xx.CONFIG_BSS_acvo", "acvo")
f.CONFIG_BSS_extSetStaKeyParamValid = ProtoField.uint8("wcn36xx.CONFIG_BSS_extSetStaKeyParamValid", "extSetStaKeyParamValid")
f.CONFIG_BSS_extSetStaKeyParam = ProtoField.bytes("wcn36xx.CONFIG_BSS_extSetStaKeyParam", "extSetStaKeyParam")
f.CONFIG_BSS_halPersona = ProtoField.uint8("wcn36xx.CONFIG_BSS_halPersona", "halPersona")
f.CONFIG_BSS_bSpectrumMgtEnable = ProtoField.uint8("wcn36xx.CONFIG_BSS_bSpectrumMgtEnable", "bSpectrumMgtEnable")
f.CONFIG_BSS_txMgmtPower = ProtoField.uint8("wcn36xx.CONFIG_BSS_txMgmtPower", "txMgmtPower")
f.CONFIG_BSS_maxTxPower = ProtoField.uint8("wcn36xx.CONFIG_BSS_maxTxPower", "maxTxPower")

f.CONFIG_BSS_V1_bssId = ProtoField.ether("wcn36xx.CONFIG_BSS_V1_bssId", "bssId")
f.CONFIG_BSS_V1_selfMacAddr = ProtoField.ether("wcn36xx.CONFIG_BSS_V1_selfMacAddr", "selfMacAddr")
f.CONFIG_BSS_V1_bssType = ProtoField.uint32("wcn36xx.CONFIG_BSS_V1_bssType", "bssType", base.DEC, bss_type_strings)
f.CONFIG_BSS_V1_operMode = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_operMode", "operMode", base.DEC, oper_mode_strings)
f.CONFIG_BSS_V1_nwType = ProtoField.uint32("wcn36xx.CONFIG_BSS_V1_nwType", "nwType", base.DEC, nw_type_strings)
f.CONFIG_BSS_V1_shortSlotTimeSupported = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_shortSlotTimeSupported", "shortSlotTimeSupported")
f.CONFIG_BSS_V1_llaCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_llaCoexist", "llaCoexist")
f.CONFIG_BSS_V1_llbCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_llbCoexist", "llbCoexist")
f.CONFIG_BSS_V1_llgCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_llgCoexist", "llgCoexist")
f.CONFIG_BSS_V1_ht20Coexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_ht20Coexist", "ht20Coexist")
f.CONFIG_BSS_V1_llnNonGFCoexist = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_llnNonGFCoexist", "llnNonGFCoexist")
f.CONFIG_BSS_V1_fLsigTXOPProtectionFullSupport = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_fLsigTXOPProtectionFullSupport", "fLsigTXOPProtectionFullSupport")
f.CONFIG_BSS_V1_fRIFSMode = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_fRIFSMode", "fRIFSMode")
f.CONFIG_BSS_V1_beaconInterval = ProtoField.uint16("wcn36xx.CONFIG_BSS_V1_beaconInterval", "beaconInterval")
f.CONFIG_BSS_V1_dtimPeriod = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_dtimPeriod", "dtimPeriod")
f.CONFIG_BSS_V1_txChannelWidthSet = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_txChannelWidthSet", "txChannelWidthSet")
f.CONFIG_BSS_V1_currentOperChannel = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_currentOperChannel", "currentOperChannel")
f.CONFIG_BSS_V1_currentExtChannel = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_currentExtChannel", "currentExtChannel")
f.CONFIG_BSS_V1_reserved = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_reserved", "reserved")
f.CONFIG_BSS_V1_ssId = ProtoField.bytes("wcn36xx.CONFIG_BSS_V1_ssId", "ssId")
f.CONFIG_BSS_V1_action = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_action", "action")
f.CONFIG_BSS_V1_rateSet = ProtoField.bytes("wcn36xx.CONFIG_BSS_V1_rateSet", "rateSet")
f.CONFIG_BSS_V1_htCapable = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_htCapable", "htCapable")
f.CONFIG_BSS_V1_obssProtEnabled = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_obssProtEnabled", "obssProtEnabled")
f.CONFIG_BSS_V1_rmfEnabled = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_rmfEnabled", "rmfEnabled")
f.CONFIG_BSS_V1_htOperMode = ProtoField.uint32("wcn36xx.CONFIG_BSS_V1_htOperMode", "htOperMode", base.DEC, ht_oper_mode_strings)
f.CONFIG_BSS_V1_dualCTSProtection = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_dualCTSProtection", "dualCTSProtection")
f.CONFIG_BSS_V1_ucMaxProbeRespRetryLimit = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_ucMaxProbeRespRetryLimit", "ucMaxProbeRespRetryLimit")
f.CONFIG_BSS_V1_bHiddenSSIDEn = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_bHiddenSSIDEn", "bHiddenSSIDEn")
f.CONFIG_BSS_V1_bProxyProbeRespEn = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_bProxyProbeRespEn", "bProxyProbeRespEn")
f.CONFIG_BSS_V1_edcaParamsValid = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_edcaParamsValid", "edcaParamsValid")
f.CONFIG_BSS_V1_acbe = ProtoField.uint32("wcn36xx.CONFIG_BSS_V1_acbe", "acbe")
f.CONFIG_BSS_V1_acbk = ProtoField.uint32("wcn36xx.CONFIG_BSS_V1_acbk", "acbk")
f.CONFIG_BSS_V1_acvi = ProtoField.uint32("wcn36xx.CONFIG_BSS_V1_acvi", "acvi")
f.CONFIG_BSS_V1_acvo = ProtoField.uint32("wcn36xx.CONFIG_BSS_V1_acvo", "acvo")
f.CONFIG_BSS_V1_extSetStaKeyParamValid = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_extSetStaKeyParamValid", "extSetStaKeyParamValid")
f.CONFIG_BSS_V1_extSetStaKeyParam = ProtoField.bytes("wcn36xx.CONFIG_BSS_V1_extSetStaKeyParam", "extSetStaKeyParam")
f.CONFIG_BSS_V1_halPersona = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_halPersona", "halPersona")
f.CONFIG_BSS_V1_bSpectrumMgtEnable = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_bSpectrumMgtEnable", "bSpectrumMgtEnable")
f.CONFIG_BSS_V1_txMgmtPower = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_txMgmtPower", "txMgmtPower")
f.CONFIG_BSS_V1_maxTxPower = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_maxTxPower", "maxTxPower")
f.CONFIG_BSS_V1_vhtCapable = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_vhtCapable", "vhtCapable")
f.CONFIG_BSS_V1_vhtTxChannelWidthSet = ProtoField.uint8("wcn36xx.CONFIG_BSS_V1_vhtTxChannelWidthSet", "vhtTxChannelWidthSet")

f.DELETE_BSS_REQ_bssIdx = ProtoField.uint8("wcn36xx.DELETE_BSS_REQ_bssIdx", "bssIdx")

f.DELETE_BSS_RSP_bssIdx = ProtoField.uint8("wcn36xx.DELETE_BSS_RSP_bssIdx", "bssIdx")

f.SEND_BEACON_REQ_beaconLength = ProtoField.uint32("wcn36xx.SEND_BEACON_REQ_beaconLength", "beaconLength")
f.SEND_BEACON_REQ_beacon = ProtoField.bytes("wcn36xx.SEND_BEACON_REQ_beacon", "beacon")
f.SEND_BEACON_REQ_bssId = ProtoField.ether("wcn36xx.SEND_BEACON_REQ_bssId", "bssId")
f.SEND_BEACON_REQ_timIeOffset = ProtoField.uint32("wcn36xx.SEND_BEACON_REQ_timIeOffset", "timIeOffset")
f.SEND_BEACON_REQ_p2pIeOffset = ProtoField.uint16("wcn36xx.SEND_BEACON_REQ_p2pIeOffset", "p2pIeOffset")

f.UPDATE_PROBE_RSP_TEMPLATE_REQ_pProbeRespTemplate = ProtoField.bytes("wcn36xx.UPDATE_PROBE_RSP_TEMPLATE_REQ_pProbeRespTemplate", "pProbeRespTemplate")
f.UPDATE_PROBE_RSP_TEMPLATE_REQ_probeRespTemplateLen = ProtoField.uint32("wcn36xx.UPDATE_PROBE_RSP_TEMPLATE_REQ_probeRespTemplateLen", "probeRespTemplateLen")
f.UPDATE_PROBE_RSP_TEMPLATE_REQ_ucProxyProbeReqValidIEBmap = ProtoField.bytes("wcn36xx.UPDATE_PROBE_RSP_TEMPLATE_REQ_ucProxyProbeReqValidIEBmap", "ucProxyProbeReqValidIEBmap")
f.UPDATE_PROBE_RSP_TEMPLATE_REQ_bssId = ProtoField.ether("wcn36xx.UPDATE_PROBE_RSP_TEMPLATE_REQ_bssId", "bssId")

f.UPDATE_BEACON_REQ_bssIdx = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_bssIdx", "bssIdx")
f.UPDATE_BEACON_REQ_fShortPreamble = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_fShortPreamble", "fShortPreamble")
f.UPDATE_BEACON_REQ_fShortSlotTime = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_fShortSlotTime", "fShortSlotTime")
f.UPDATE_BEACON_REQ_beaconInterval = ProtoField.uint16("wcn36xx.UPDATE_BEACON_REQ_beaconInterval", "beaconInterval")
f.UPDATE_BEACON_REQ_llaCoexist = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_llaCoexist", "llaCoexist")
f.UPDATE_BEACON_REQ_llbCoexist = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_llbCoexist", "llbCoexist")
f.UPDATE_BEACON_REQ_llgCoexist = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_llgCoexist", "llgCoexist")
f.UPDATE_BEACON_REQ_ht20MhzCoexist = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_ht20MhzCoexist", "ht20MhzCoexist")
f.UPDATE_BEACON_REQ_llnNonGFCoexist = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_llnNonGFCoexist", "llnNonGFCoexist")
f.UPDATE_BEACON_REQ_fLsigTXOPProtectionFullSupport = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_fLsigTXOPProtectionFullSupport", "fLsigTXOPProtectionFullSupport")
f.UPDATE_BEACON_REQ_fRIFSMode = ProtoField.uint8("wcn36xx.UPDATE_BEACON_REQ_fRIFSMode", "fRIFSMode")
f.UPDATE_BEACON_REQ_paramChangeBitmap = ProtoField.uint16("wcn36xx.UPDATE_BEACON_REQ_paramChangeBitmap", "paramChangeBitmap")

f.SET_STAKEY_REQ_staIdx = ProtoField.uint16("wcn36xx.SET_STAKEY_REQ_staIdx", "staIdx")
f.SET_STAKEY_REQ_encType = ProtoField.uint32("wcn36xx.SET_STAKEY_REQ_encType", "encType", base.DEC, ani_ed_type_strings)
f.SET_STAKEY_REQ_wepType = ProtoField.uint32("wcn36xx.SET_STAKEY_REQ_wepType", "wepType", base.DEC, ani_wep_type_strings)
f.SET_STAKEY_REQ_defWEPIdx = ProtoField.uint8("wcn36xx.SET_STAKEY_REQ_defWEPIdx", "defWEPIdx")
f.SET_STAKEY_REQ_key = ProtoField.bytes("wcn36xx.SET_STAKEY_REQ_key", "key")
f.SET_STAKEY_REQ_singleTidRc = ProtoField.uint8("wcn36xx.SET_STAKEY_REQ_singleTidRc", "singleTidRc")

f.FINISH_SCAN_REQ_scanMode = ProtoField.uint32("wcn36xx.FINISH_SCAN_REQ_scanMode", "scanMode", base.HEX, sys_mode_strings)
f.FINISH_SCAN_REQ_currentOperChannel = ProtoField.uint8("wcn36xx.FINISH_SCAN_REQ_currentOperChannel", "currentOperChannel")
f.FINISH_SCAN_REQ_cbState = ProtoField.uint32("wcn36xx.FINISH_SCAN_REQ_cbState", "cbState", base.DEC, bond_state_strings)
f.FINISH_SCAN_REQ_bssid = ProtoField.ether("wcn36xx.FINISH_SCAN_REQ_bssid", "bssid")
f.FINISH_SCAN_REQ_notifyBss = ProtoField.uint8("wcn36xx.FINISH_SCAN_REQ_notifyBss", "notifyBss")
f.FINISH_SCAN_REQ_frameType = ProtoField.uint8("wcn36xx.FINISH_SCAN_REQ_frameType", "frameType")
f.FINISH_SCAN_REQ_frameLength = ProtoField.uint8("wcn36xx.FINISH_SCAN_REQ_frameLength", "frameLength")
f.FINISH_SCAN_REQ_macMgmtHdr = ProtoField.bytes("wcn36xx.FINISH_SCAN_REQ_macMgmtHdr", "macMgmtHdr")
f.FINISH_SCAN_REQ_scanEntry = ProtoField.bytes("wcn36xx.FINISH_SCAN_REQ_scanEntry", "scanEntry")

f.CONFIG_BSS_RSP_bssIdx = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_bssIdx", "bssIdx")
f.CONFIG_BSS_RSP_dpuDescIndx = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_dpuDescIndx", "dpuDescIndx")
f.CONFIG_BSS_RSP_ucastDpuSignature = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_ucastDpuSignature", "ucastDpuSignature")
f.CONFIG_BSS_RSP_bcastDpuDescIndx = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_bcastDpuDescIndx", "bcastDpuDescIndx")
f.CONFIG_BSS_RSP_bcastDpuSignature = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_bcastDpuSignature", "bcastDpuSignature")
f.CONFIG_BSS_RSP_mgmtDpuDescIndx = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_mgmtDpuDescIndx", "mgmtDpuDescIndx")
f.CONFIG_BSS_RSP_mgmtDpuSignature = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_mgmtDpuSignature", "mgmtDpuSignature")
f.CONFIG_BSS_RSP_bssStaIdx = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_bssStaIdx", "bssStaIdx")
f.CONFIG_BSS_RSP_bssSelfStaIdx = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_bssSelfStaIdx", "bssSelfStaIdx")
f.CONFIG_BSS_RSP_bssBcastStaIdx = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_bssBcastStaIdx", "bssBcastStaIdx")
f.CONFIG_BSS_RSP_staMac = ProtoField.ether("wcn36xx.CONFIG_BSS_RSP_staMac", "staMac")
f.CONFIG_BSS_RSP_txMgmtPower = ProtoField.uint8("wcn36xx.CONFIG_BSS_RSP_txMgmtPower", "txMgmtPower")

f.SET_BSSKEY_REQ_bssIdx = ProtoField.uint8("wcn36xx.SET_BSSKEY_REQ_bssIdx", "bssIdx")
f.SET_BSSKEY_REQ_encType = ProtoField.uint32("wcn36xx.SET_BSSKEY_REQ_encType", "encType", base.DEC, ani_ed_type_strings)
f.SET_BSSKEY_REQ_numKeys = ProtoField.uint8("wcn36xx.SET_BSSKEY_REQ_numKeys", "numKeys")
f.SET_BSSKEY_REQ_key = ProtoField.bytes("wcn36xx.SET_BSSKEY_REQ_key", "key")
f.SET_BSSKEY_REQ_singleTidRc = ProtoField.uint8("wcn36xx.SET_BSSKEY_REQ_singleTidRc", "singleTidRc")

f.GET_STATS_RSP_staId = ProtoField.uint32("wcn36xx.GET_STATS_RSP_staId", "staId")
f.GET_STATS_RSP_statsMask = ProtoField.uint32("wcn36xx.GET_STATS_RSP_statsMask", "statsMask")
f.GET_STATS_RSP_msgType = ProtoField.uint16("wcn36xx.GET_STATS_RSP_msgType", "msgType")
f.GET_STATS_RSP_msgLen = ProtoField.uint16("wcn36xx.GET_STATS_RSP_msgLen", "msgLen")

f.GET_STATS_RSP_summary_cnt0 = ProtoField.uint32("wcn36xx.GET_STATS_RSP_cnt0", "cnt0")
f.GET_STATS_RSP_summary_cnt1 = ProtoField.uint32("wcn36xx.GET_STATS_RSP_cnt1", "cnt1")
f.GET_STATS_RSP_summary_cnt2 = ProtoField.uint32("wcn36xx.GET_STATS_RSP_cnt2", "cnt2")
f.GET_STATS_RSP_summary_cnt3 = ProtoField.uint32("wcn36xx.GET_STATS_RSP_cnt3", "cnt3")
f.GET_STATS_RSP_summary_retry_cnt = ProtoField.bytes("wcn36xx.GET_STATS_RSP_summary_retry_cnt", "retry_cnt")
f.GET_STATS_RSP_summary_multiple_retry_cnt = ProtoField.bytes("wcn36xx.GET_STATS_RSP_summary_multiple_retry_cnt", "multiple_retry_cnt")
f.GET_STATS_RSP_summary_tx_frm_cnt = ProtoField.bytes("wcn36xx.GET_STATS_RSP_summary_tx_frm_cnt", "tx_frm_cnt")
f.GET_STATS_RSP_summary_rx_frm_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_rx_frm_cnt", "rx_frm_cnt")
f.GET_STATS_RSP_summary_frm_dup_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_frm_dup_cnt", "frm_dup_cnt")
f.GET_STATS_RSP_summary_fail_cnt = ProtoField.bytes("wcn36xx.GET_STATS_RSP_summary_fail_cnt", "fail_cnt")
f.GET_STATS_RSP_summary_rts_fail_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_rts_fail_cnt", "rts_fail_cnt")
f.GET_STATS_RSP_summary_ack_fail_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_ack_fail_cnt", "ack_fail_cnt")
f.GET_STATS_RSP_summary_rts_succ_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_rts_succ_cnt", "rts_succ_cnt")
f.GET_STATS_RSP_summary_rx_discard_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_rx_discard_cnt", "rx_discard_cnt")
f.GET_STATS_RSP_summary_rx_error_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_rx_error_cnt", "rx_error_cnt")
f.GET_STATS_RSP_summary_tx_byte_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_summary_tx_byte_cnt", "tx_byte_cnt")

f.GET_STATS_RSP_classA_rx_frag_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_rx_frag_cnt", "rx_frag_cnt")
f.GET_STATS_RSP_classA_promiscuous_rx_frag_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_promiscuous_rx_frag_cnt", "promiscuous_rx_frag_cnt")
f.GET_STATS_RSP_classA_rx_input_sensitivity = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_rx_input_sensitivity", "rx_input_sensitivity")
f.GET_STATS_RSP_classA_max_pwr = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_max_pwr", "max_pwr")
f.GET_STATS_RSP_classA_sync_fail_cnt = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_sync_fail_cnt", "sync_fail_cnt")
f.GET_STATS_RSP_classA_tx_rate = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_tx_rate", "tx_rate")
f.GET_STATS_RSP_classA_mcs_index = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_mcs_index", "mcs_index")
f.GET_STATS_RSP_classA_tx_rate_flags = ProtoField.uint32("wcn36xx.GET_STATS_RSP_classA_tx_rate_flags", "tx_rate_flags")

f.ADD_STA_SELF_RSP_selfStaIdx = ProtoField.uint8("wcn36xx.ADD_STA_SELF_RSP_selfStaIdx", "selfStaIdx")
f.ADD_STA_SELF_RSP_dpuIdx = ProtoField.uint8("wcn36xx.ADD_STA_SELF_RSP_dpuIdx", "dpuIdx")
f.ADD_STA_SELF_RSP_dpuSignature = ProtoField.uint8("wcn36xx.ADD_STA_SELF_RSP_dpuSignature", "dpuSignature")

f.DEL_STA_SELF_REQ_selfMacAddr = ProtoField.ether("wcn36xx.DEL_STA_SELF_REQ_selfMacAddr", "selfMacAddr")

f.DEL_STA_SELF_RSP_selfMacAddr = ProtoField.ether("wcn36xx.DEL_STA_SELF_RSP_selfMacAddr", "selfMacAddr")

f.COEX_IND_coexIndType = ProtoField.uint32("wcn36xx.COEX_IND_coexIndType", "coexIndType", base.DEC, coex_ind_type_strings)
f.COEX_IND_Bssfordisableaggr = ProtoField.ether("wcn36xx.COEX_IND_Bssfordisableaggra", "Bssfordisableaggr")
f.COEX_IND_Unused = ProtoField.bytes("wcn36xx.COEX_IND_Unused", "Unused")

f.ADD_BA_SESSION_RSP_baDialogToken = ProtoField.uint8("wcn36xx.ADD_BA_SESSION_RSP_baDialogToken", "baDialogToken")
f.ADD_BA_SESSION_RSP_baTID = ProtoField.uint8("wcn36xx.ADD_BA_SESSION_RSP_baTID", "baTID")
f.ADD_BA_SESSION_RSP_baBufferSize = ProtoField.uint8("wcn36xx.ADD_BA_SESSION_RSP_baBufferSize", "baBufferSize")
f.ADD_BA_SESSION_RSP_baSessionID = ProtoField.uint8("wcn36xx.ADD_BA_SESSION_RSP_baSessionID", "baSessionID")
f.ADD_BA_SESSION_RSP_winSize = ProtoField.uint8("wcn36xx.ADD_BA_SESSION_RSP_winSize", "winSize")
f.ADD_BA_SESSION_RSP_STAID = ProtoField.uint8("wcn36xx.ADD_BA_SESSION_RSP_STAID", "STAID")
f.ADD_BA_SESSION_RSP_SSN = ProtoField.uint16("wcn36xx.ADD_BA_SESSION_RSP_SSN", "SSN")

f.TRIGGER_BA_REQ_baSessionID = ProtoField.uint8("wcn36xx.TRIGGER_BA_REQ_baSessionID", "baSessionID")
f.TRIGGER_BA_REQ_baCandidateCnt = ProtoField.uint16("wcn36xx.TRIGGER_BA_REQ_baCandidateCnt", "baCandidateCnt")

f.SET_THERMAL_MITIGATION_REQ_thermalMitMode = ProtoField.uint32("wcn36xx.SET_THERMAL_MITIGATION_REQ_thermalMitMode", "thermalMitMode", base.DEC, thermal_mit_mode_strings)
f.SET_THERMAL_MITIGATION_REQ_thermalMitLevel = ProtoField.uint32("wcn36xx.SET_THERMAL_MITIGATION_REQ_thermalMitLevel", "thermalMitLevel", base.DEC, thermal_mit_level_strings)

f.GET_ROAM_RSSI_REQ_staId = ProtoField.uint32("wcn36xx.GET_ROAM_RSSI_REQ_staId", "staId")

f.GET_ROAM_RSSI_RSP_staId = ProtoField.uint8("wcn36xx.GET_ROAM_RSSI_RSP_staId", "staId")
f.GET_ROAM_RSSI_RSP_rssi = ProtoField.uint8("wcn36xx.GET_ROAM_RSSI_RSP_rssi", "rssi")

f.CONFIG_STA_RSP_staIdx = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_staIdx", "staIdx")
f.CONFIG_STA_RSP_bssIdx = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_bssIdx", "bssIdx")
f.CONFIG_STA_RSP_dpuIndex = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_dpuIndex", "dpuIndex")
f.CONFIG_STA_RSP_bcastDpuIndex = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_bcastDpuIndex", "bcastDpuIndex")
f.CONFIG_STA_RSP_bcastMgmtDpuIdx = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_bcastMgmtDpuIdx", "bcastMgmtDpuIdx")
f.CONFIG_STA_RSP_ucUcastSig = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_ucUcastSig", "ucUcastSig")
f.CONFIG_STA_RSP_ucBcastSig = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_ucBcastSig", "ucBcastSig")
f.CONFIG_STA_RSP_ucMgmtSig = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_ucMgmtSig", "ucMgmtSig")
f.CONFIG_STA_RSP_p2pCapableSta = ProtoField.uint8("wcn36xx.CONFIG_STA_RSP_p2pCapableSta", "p2pCapableSta")

f.UPD_EDCA_PARAMS_REQ_bssIdx = ProtoField.uint16("wcn36xx.UPD_EDCA_PARAMS_REQ_bssIdx", "bssIdx")

f.EDCA_PARAM_RECORD_aci_aifsn = ProtoField.uint8("wcn36xx.EDCA_PARAM_RECORD_aci_aifsn", "aci_aifsn")
f.EDCA_PARAM_RECORD_aci_acm = ProtoField.bool("wcn36xx.EDCA_PARAM_RECORD_aci_acm", "aci_acm")
f.EDCA_PARAM_RECORD_aci_aci = ProtoField.uint8("wcn36xx.EDCA_PARAM_RECORD_aci_aci", "aci_aci")

f.EDCA_PARAM_RECORD_cw_max = ProtoField.uint8("wcn36xx.EDCA_PARAM_RECORD_cw_max", "cw_max")
f.EDCA_PARAM_RECORD_cw_min = ProtoField.uint8("wcn36xx.EDCA_PARAM_RECORD_cw_min", "cw_min")
f.EDCA_PARAM_RECORD_txoplimit = ProtoField.uint8("wcn36xx.EDCA_PARAM_RECORD_txoplimit", "txoplimit")

f.UPDATE_VHT_OP_MODE_REQ_opMode = ProtoField.uint16("wcn36xx.UPDATE_VHT_OP_MODE_REQ_opMode", "opMode")
f.UPDATE_VHT_OP_MODE_REQ_staId = ProtoField.uint16("wcn36xx.UPDATE_VHT_OP_MODE_REQ_staId", "staId")

f.FW_CAP = ProtoField.uint8("wcn36xx.fw_cap", "fw_cap", base.DEC, fw_caps_strings)

f.START_SCAN_RSP_status = ProtoField.uint32("wcn36xx.START_SCAN_RSP_status", "status")
f.START_SCAN_RSP_startTSF = ProtoField.uint64("wcn36xx.START_SCAN_RSP_startTSF", "startTSF")
f.START_SCAN_RSP_txMgmtPower = ProtoField.uint8("wcn36xx.START_SCAN_RSP_txMgmtPower", "txMgmtPower")

f.WLAN_ROAM_SCAN_OFFLOAD_REQ_RoamScanOffloadEnabled = ProtoField.uint32("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_RoamScanOffloadEnabled", "RoamScanOffloadEnabled")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_LookupThreshold = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_LookupThreshold", "LookupThreshold")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_RoamRssiDiff = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_RoamRssiDiff", "RoamRssiDiff")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ChannelCacheType = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ChannelCacheType", "ChannelCacheType")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_Command = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_Command", "Command")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_StartScanReason = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_StartScanReason", "StartScanReason")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanTimerPeriod = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanTimerPeriod", "NeighborScanTimerPeriod")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborRoamScanRefreshPeriod = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborRoamScanRefreshPeriod", "NeighborRoamScanRefreshPeriod")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanChannelMinTime = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanChannelMinTime", "NeighborScanChannelMinTime")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanChannelMaxTime = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_NeighborScanChannelMaxTime", "NeighborScanChannelMaxTime")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_EmptyRefreshScanPeriod = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_EmptyRefreshScanPeriod", "EmptyRefreshScanPeriod")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ValidChannelCount = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ValidChannelCount", "ValidChannelCount")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ValidChannelList = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ValidChannelList", "ValidChannelList")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_IsCCXEnabled = ProtoField.uint32("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_IsCCXEnabled", "IsCCXEnabled")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_us24GProbeSize = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_us24GProbeSize", "us24GProbeSize")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_a24GProbeTemplate = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_a24GProbeTemplate", "a24GProbeTemplate")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_us5GProbeSize = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_us5GProbeSize", "us5GProbeSize")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_a5GProbeTemplate = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_a5GProbeTemplate", "a5GProbeTemplate")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_nProbes = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_nProbes", "nProbes")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_HomeAwayTime = ProtoField.uint16("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_HomeAwayTime", "HomeAwayTime")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_MAWCEnabled = ProtoField.uint32("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_MAWCEnabled", "MAWCEnabled")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ReservedBytes = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ReservedBytes", "ReservedBytes")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnectedNetwork = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnectedNetwork", "ConnectedNetwork")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_MDID = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_MDID", "MDID")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ssId = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ssId", "ssId")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_currAPbssid = ProtoField.ether("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_currAPbssid", "currAPbssid")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_authentication = ProtoField.uint32("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_authentication", "authentication")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_encryption = ProtoField.uint32("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_encryption", "encryption")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_mcencryption = ProtoField.uint32("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_mcencryption", "mcencryption")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ChannelCount = ProtoField.uint8("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ChannelCount", "ChannelCount")
f.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ChannelCache = ProtoField.bytes("wcn36xx.WLAN_ROAM_SCAN_OFFLOAD_REQ_ConnNet_ChannelCache", "ChannelCache")

f.TRIGGER_BA_RSP_Cand_staAddr = ProtoField.ether("wcn36xx.TRIGGER_BA_RSP_Cand_staAddr", "staAddr")
f.TRIGGER_BA_RSP_Cand_baInfo = ProtoField.uint16("wcn36xx.TRIGGER_BA_RSP_Cand_baInfo", "baInfo", base.HEX)

f.GTK_OFFLOAD_REQ_ulFlags = ProtoField.uint32("wcn36xx.GTK_OFFLOAD_REQ_ulFlags", "ulFlags", base.HEX)
f.GTK_OFFLOAD_REQ_aKCK = ProtoField.bytes("wcn36xx.GTK_OFFLOAD_REQ_aKCK", "aKCK")
f.GTK_OFFLOAD_REQ_aKEK = ProtoField.bytes("wcn36xx.GTK_OFFLOAD_REQ_aKEK", "aKEK")
f.GTK_OFFLOAD_REQ_ullKeyReplayCounter = ProtoField.uint64("wcn36xx.GTK_OFFLOAD_REQ_ullKeyReplayCounter", "ullKeyReplayCounter")
f.GTK_OFFLOAD_REQ_bssIdx = ProtoField.uint8("wcn36xx.GTK_OFFLOAD_REQ_bssIdx", "bssIdx")

f.MULTICAST_LIST_RSP_bssIdx = ProtoField.uint8("wcn36xx.8023_MULTICAST_LIST_RSP_bssIdx", "bssIdx")

f.JOIN_RSP_txMgmtPower = ProtoField.uint8("wcn36xx.JOIN_RSP_txMgmtPower", "txMgmtPower")

f.CH_SWITCH_RSP_channelNumber = ProtoField.uint8("wcn36xx.CH_SWITCH_RSP_channelNumber", "channelNumber")
f.CH_SWITCH_RSP_txMgmtPower = ProtoField.uint8("wcn36xx.CH_SWITCH_RSP_txMgmtPower", "txMgmtPower")
f.CH_SWITCH_RSP_bssId = ProtoField.ether("wcn36xx.CH_SWITCH_RSP_bssId", "bssId")

f.KEEP_ALIVE_REQ_packetType = ProtoField.uint8("wcn36xx.KEEP_ALIVE_REQ_packetType", "packetType", base.DEC, keep_alive_packet_type_strings)
f.KEEP_ALIVE_REQ_timePeriod = ProtoField.uint32("wcn36xx.KEEP_ALIVE_REQ_timePeriod", "timePeriod")
f.KEEP_ALIVE_REQ_hostIpv4Addr = ProtoField.ipv4("wcn36xx.KEEP_ALIVE_REQ_hostIpv4Addr", "hostIpv4Addr")
f.KEEP_ALIVE_REQ_destIpv4Addr = ProtoField.ipv4("wcn36xx.KEEP_ALIVE_REQ_destIpv4Addr", "destIpv4Addr")
f.KEEP_ALIVE_REQ_destMacAddr = ProtoField.ether("wcn36xx.KEEP_ALIVE_REQ_destMacAddr", "destMacAddr")
f.KEEP_ALIVE_REQ_bssIdx = ProtoField.uint8("wcn36xx.KEEP_ALIVE_REQ_bssIdx", "bssIdx")

f.OTA_TX_COMPL_IND_status = ProtoField.uint32("wcn36xx.OTA_TX_COMPL_IND_status", "status")

f.DELETE_STA_RSP_staId = ProtoField.uint8("wcn36xx.DELETE_STA_RSP_staId", "staId")

f.ENTER_BMPS_RSP_bssIdx = ProtoField.uint8("wcn36xx.ENTER_BMPS_RSP_bssIdx", "bssIdx")

f.START_RSP_ucMaxStations = ProtoField.uint8("wcn36xx.START_RSP_ucMaxStations", "ucMaxStations")
f.START_RSP_ucMaxBssids = ProtoField.uint8("wcn36xx.START_RSP_ucMaxBssids", "ucMaxBssids")
f.START_RSP_wcnssWlanVersion = ProtoField.uint32("wcn36xx.START_RSP_wcnssWlanVersion", "wcnssWlanVersion", base.HEX)
f.START_RSP_wcnssCrmVersionString = ProtoField.string("wcn36xx.START_RSP_wcnssCrmVersionString", "wcnssCrmVersionString")
f.START_RSP_wcnssWlanVersionString = ProtoField.string("wcn36xx.START_RSP_wcnssWlanVersionString", "wcnssWlanVersionString")

f.SET_P2P_GONOA_REQ_opp_ps = ProtoField.uint8("wcn36xx.SET_P2P_GONOA_REQ_opp_ps", "opp_ps")
f.SET_P2P_GONOA_REQ_ctWindow = ProtoField.uint32("wcn36xx.SET_P2P_GONOA_REQ_ctWindow", "ctWindow")
f.SET_P2P_GONOA_REQ_count = ProtoField.uint8("wcn36xx.SET_P2P_GONOA_REQ_count", "count")
f.SET_P2P_GONOA_REQ_duration = ProtoField.uint32("wcn36xx.SET_P2P_GONOA_REQ_duration", "duration")
f.SET_P2P_GONOA_REQ_interval = ProtoField.uint32("wcn36xx.SET_P2P_GONOA_REQ_interval", "interval")
f.SET_P2P_GONOA_REQ_single_noa_duration = ProtoField.uint32("wcn36xx.SET_P2P_GONOA_REQ_single_noa_duration", "single_noa_duration")
f.SET_P2P_GONOA_REQ_psSelection = ProtoField.uint8("wcn36xx.SET_P2P_GONOA_REQ_psSelection", "psSelection")
