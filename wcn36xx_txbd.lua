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

local wcn36xx = Proto("wcn36xx_txbd", "wcn36xx txbd dissector")
local f = wcn36xx.fields
local bd_rate_strings = {}
local tx_wq_id_strings = {}

function wcn36xx.init()
	-- Hook into ethertype parser
	-- Bogus value 0x3662 used together with textpcap dummy header generation
	local udp_table = DissectorTable.get("ethertype")
	local pattern = 0x3662
	udp_table:add(pattern, wcn36xx)
end

function parse_pdu(buffer, pinfo, tree)
	-- todo implement parser
	local subtree = tree:add(wcn36xx, buffer(0, 16), "pdu")
	local n = 0

	local bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.pdu_dpu_fb, bd1)
	subtree:add(f.pdu_adu_fb, bd1)
	subtree:add(f.pdu_pdu_id, bd1)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.pdu_tail_pid_idx, bd1)
	subtree:add(f.pdu_head_pid_idx, bd1)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.pdu_pdu_count, bd1)
	subtree:add(f.pdu_mpu_data_off, bd1)
	subtree:add(f.pdu_mpu_header_off, bd1)
	subtree:add(f.pdu_mpu_header_len, bd1)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.pdu_reserved4, bd1)
	subtree:add(f.pdu_tid, bd1)
	subtree:add(f.pdu_reserved3, bd1)
	subtree:add(f.pdu_mpdu_len, bd1)
	return n
end

function bitval(nr1, count)
	-- bitfields apparently are MSB0
	-- todo tidy this function
	local nr = 31 - nr1 + count - 1
	local tmp = bit.rshift(0xffffffff, 32 - count)
	return bit.lshift(tmp, nr + 1 - count)
end

function wcn36xx.dissector(inbuffer, pinfo, tree)
	local n = 0
	local buffer = inbuffer
	pinfo.cols.protocol = "wcn36xx_txbd"
	pinfo.cols.info = ""

	-- Ethernet frames are 64 (60) bytes minimum. Remove trailing dummy data
	buffer = buffer(0, 40)
	local subtree = tree:add(wcn36xx, buffer(), "wcn36xx txbd protocol data")
	tree:add(wcn36xx, inbuffer(40), "Ethernet frame dummy data")

	local bd1 = buffer(n, 4); n =  n + 4
	subtree:add(f.txbd_bdt, bd1)
	subtree:add(f.txbd_ft, bd1)
	subtree:add(f.txbd_dpu_ne, bd1)
	subtree:add(f.txbd_fw_tx_comp, bd1)
	subtree:add(f.txbd_tx_comp, bd1)
	subtree:add(f.txbd_reserved1, bd1)
	subtree:add(f.txbd_ub, bd1)
	subtree:add(f.txbd_rmf, bd1)
	subtree:add(f.txbd_reserved0, bd1)
	subtree:add(f.txbd_dpu_sign, bd1)
	subtree:add(f.txbd_dpu_rf, bd1)

	n = n + parse_pdu(buffer(n):tvb(), pinfo, subtree)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.txbd_reserved5, bd1)
	subtree:add(f.txbd_queue_id, bd1)
	subtree:add(f.txbd_bd_rate, bd1)
	subtree:add(f.txbd_ack_policy, bd1)
	subtree:add(f.txbd_sta_index, bd1)
	subtree:add(f.txbd_dpu_desc_idx, bd1)

	subtree:add(f.txbd_bd_sign, buffer(n, 4)); n = n + 4
	subtree:add(f.txbd_reserved6, buffer(n, 4)); n = n + 4
	subtree:add(f.txbd_dxe_start_time, buffer(n, 4)); n = n + 4
	subtree:add(f.txbd_dxe_end_time, buffer(n, 4)); n = n + 4

--	bd1 = buffer(n, 4); n = n + 4
--	subtree:add(f.txbd_tcp_udp_start_off, bd1)
--	subtree:add(f.txbd_header_cks, bd1)
--	subtree:add(f.txbd_reserved7, bd1)
end

-- Lookup strings
bd_rate_strings[0] = "data"
bd_rate_strings[2] = "mgmt"
bd_rate_strings[3] = "ctrl"

tx_wq_id_strings[10] = "broadcast"
tx_wq_id_strings[9] = "unicast"

-- Protocol fields
local curr = 31
f.txbd_bdt = ProtoField.uint32("wcn36xx.txbd.bdt", "bdt", base.HEX, nil, bitval(curr, 2)); curr = curr - 2
f.txbd_ft = ProtoField.uint32("wcn36xx.txbd.ft", "ft", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.txbd_dpu_ne = ProtoField.uint32("wcn36xx.txbd.dpu_ne", "dpu_ne", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.txbd_fw_tx_comp = ProtoField.uint32("wcn36xx.txbd.fw_tx_comp", "fw_tx_comp", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.txbd_tx_comp = ProtoField.uint32("wcn36xx.txbd.tx_comp", "tx_comp", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.txbd_reserved1 = ProtoField.uint32("wcn36xx.txbd.reserved1", "reserved1", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.txbd_ub = ProtoField.uint32("wcn36xx.txbd.ub", "ub", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.txbd_rmf = ProtoField.uint32("wcn36xx.txbd.rmf", "rmf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.txbd_reserved0 = ProtoField.uint32("wcn36xx.txbd.reserved0", "reserved0", base.HEX, nil, bitval(curr, 12)); curr = curr - 12
f.txbd_dpu_sign = ProtoField.uint32("wcn36xx.txbd.dpu_sign", "dpu_sign", base.HEX, nil, bitval(curr, 3)); curr = curr - 3
f.txbd_dpu_rf = ProtoField.uint32("wcn36xx.txbd.dpu_rf", "dpu_rf", base.HEX, nil, bitval(curr, 8)); curr = curr - 8

curr = 31
f.txbd_reserved5 = ProtoField.uint32("wcn36xx.txbd.reserved5", "reserved5", base.HEX, nil, bitval(curr, 7)); curr = curr - 7
f.txbd_queue_id = ProtoField.uint32("wcn36xx.txbd.queue_id", "queue_id", base.HEX, tx_wq_id_strings, bitval(curr, 5)); curr = curr - 5
f.txbd_bd_rate = ProtoField.uint32("wcn36xx.txbd.bd_rate", "bd_rate", base.HEX, bd_rate_strings, bitval(curr, 2)); curr = curr - 2
f.txbd_ack_policy = ProtoField.uint32("wcn36xx.txbd.ack_policy", "ack_policy", base.HEX, nil, bitval(curr, 2)); curr = curr - 2
f.txbd_sta_index = ProtoField.uint32("wcn36xx.txbd.sta_index", "sta_index", base.HEX, nil, bitval(curr, 8)); curr = curr - 8
f.txbd_dpu_desc_idx = ProtoField.uint32("wcn36xx.txbd.dpu_desc_idx", "dpu_desc_idx", base.HEX, nil, bitval(curr, 8)); curr = curr - 8

f.txbd_bd_sign = ProtoField.uint32("wcn36xx.txbd.bd_sign", "bd_sign", base.HEX)
f.txbd_reserved6 = ProtoField.uint32("wcn36xx.txbd.reserved6", "reserved6", base.HEX)
f.txbd_dxe_start_time = ProtoField.uint32("wcn36xx.txbd.dxe_start_time", "dxe_start_time", base.HEX)
f.txbd_dxe_end_time = ProtoField.uint32("wcn36xx.txbd.bd_dxe_end_time", "dxe_end_time", base.HEX)

curr = 31
f.pdu_dpu_fb = ProtoField.uint32("wcn36xx.pdu.dpu_fb", "dpu_fb", base.HEX, nil, bitval(curr, 8)); curr = curr - 8
f.pdu_adu_fb = ProtoField.uint32("wcn36xx.pdu.adu_fb", "adu_fb", base.HEX, nil, bitval(curr, 8)); curr = curr - 8
f.pdu_pdu_id = ProtoField.uint32("wcn36xx.pdu.pdu_fb", "pdu_fb", base.HEX, nil, bitval(curr, 16)); curr = curr - 16

curr = 31
f.pdu_tail_pid_idx = ProtoField.uint32("wcn36xx.pdu.tail_pid_idx", "tail_pid_idx", base.HEX, nil, bitval(curr, 16)); curr = curr - 16
f.pdu_head_pid_idx = ProtoField.uint32("wcn36xx.pdu.head_pid_idx", "head_pid_idx", base.HEX, nil, bitval(curr, 16)); curr = curr - 16

curr = 31
f.pdu_pdu_count = ProtoField.uint32("wcn36xx.pdu.pdu_count", "pdu_count", base.DEC, nil, bitval(curr, 7)); curr = curr - 7
f.pdu_mpu_data_off = ProtoField.uint32("wcn36xx.pdu.mpu_data_off", "mpu_data_off", base.DEC, nil, bitval(curr, 9)); curr = curr - 9
f.pdu_mpu_header_off = ProtoField.uint32("wcn36xx.pdu.header_off", "header_off", base.DEC, nil, bitval(curr, 8)); curr = curr - 8
f.pdu_mpu_header_len = ProtoField.uint32("wcn36xx.pdu.header_len", "header_len", base.DEC, nil, bitval(curr, 8)); curr = curr - 8

curr = 31
f.pdu_reserved4 = ProtoField.uint32("wcn36xx.pdu.reserved4", "reserved4", base.HEX, nil, bitval(curr, 8)); curr = curr - 8
f.pdu_tid = ProtoField.uint32("wcn36xx.pdu.tid", "tid", base.HEX, nil, bitval(curr, 4)); curr = curr - 4
f.pdu_reserved3 = ProtoField.uint32("wcn36xx.pdu.reserved3", "reserved3", base.HEX, nil, bitval(curr, 4)); curr = curr - 4
f.pdu_mpdu_len = ProtoField.uint32("wcn36xx.pdu.mpdu_len", "mpdu_len", base.DEC, nil, bitval(curr, 16)); curr = curr - 16
