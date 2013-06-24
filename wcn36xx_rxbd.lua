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

local wcn36xx = Proto("wcn36xx_rxbd", "wcn36xx rxbd dissector")
local f = wcn36xx.fields

function wcn36xx.init()
	-- Hook into ethertype parser
	-- Bogus value 0x3661 used together with textpcap dummy header generation
	local udp_table = DissectorTable.get("ethertype")
	local pattern = 0x3661
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
	pinfo.cols.protocol = "wcn36xx_rxbd"
	pinfo.cols.info = ""


	if (buffer:len() <= 46) then
		-- Ethernet frames are 64 (60) bytes minimum. Remove dummy
		-- trailing data if commands are smaller than that.
		buffer = buffer(0, cmd_len)
	end

	local subtree = tree:add(wcn36xx, buffer(), "wcn36xx rxbd protocol data")

	local bd1 = buffer(n, 4); n =  n + 4
	subtree:add(f.rxbd_bdt, bd1)
	subtree:add(f.rxbd_ft, bd1)
	subtree:add(f.rxbd_dpu_ne, bd1)
	subtree:add(f.rxbd_rx_key_id, bd1)
	subtree:add(f.rxbd_ub, bd1)
	subtree:add(f.rxbd_rmf, bd1)
	subtree:add(f.rxbd_uma_bypass, bd1)
	subtree:add(f.rxbd_csr11, bd1)
	subtree:add(f.rxbd_reserved0, bd1)
	subtree:add(f.rxbd_scan_learn, bd1)
	subtree:add(f.rxbd_rx_chan, bd1)
	subtree:add(f.rxbd_rtsf, bd1)
	subtree:add(f.rxbd_bsf, bd1)
	subtree:add(f.rxbd_a2hf, bd1)
	subtree:add(f.rxbd_st_auf, bd1)
	subtree:add(f.rxbd_dpu_sign, bd1)
	subtree:add(f.rxbd_dpu_rf, bd1)

	n = n + parse_pdu(buffer(n):tvb(), pinfo, subtree)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.rxbd_addr3, bd1)
	subtree:add(f.rxbd_addr2, bd1)
	subtree:add(f.rxbd_addr1, bd1)
	subtree:add(f.rxbd_dpu_desc_idx, bd1)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.rxbd_rxp_flags, bd1)
	subtree:add(f.rxbd_rate_id, bd1)

	local phy_stat0 = buffer(n, 4):uint()
	local rssi = -(100 - buffer(n + 3, 1):uint())
	subtree:add(f.rxbd_phy_stat0, buffer(n, 4), phy_stat0, nil, "(rssi = "..rssi..")"); n = n + 4
	local phy_stat1 = buffer(n, 4):uint()
	local snr = buffer(n + 3, 1):uint()
	subtree:add(f.rxbd_phy_stat1, buffer(n, 4), phy_stat1, nil, "(snr = "..snr..")"); n = n + 4

	subtree:add(f.rxbd_rx_times, buffer(n, 4)); n = n + 4

	subtree:add(f.rxbd_pmi_cmd, buffer(n, 24)); n = n + 24

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.rxbd_reserved7, bd1)
	subtree:add(f.rxbd_reorder_slot_id, bd1)
	subtree:add(f.rxbd_reorder_fwd_id, bd1)
	subtree:add(f.rxbd_reserved6, bd1)
	subtree:add(f.rxbd_reorder_code, bd1)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.rxbd_exp_seq_num, bd1)
	subtree:add(f.rxbd_cur_seq_num, bd1)
	subtree:add(f.rxbd_fr_type_subtype, bd1)

	bd1 = buffer(n, 4); n = n + 4
	subtree:add(f.rxbd_msdu_size, bd1)
	subtree:add(f.rxbd_sub_fr_id, bd1)
	subtree:add(f.rxbd_proc_order, bd1)
	subtree:add(f.rxbd_reserved9, bd1)
	subtree:add(f.rxbd_aef, bd1)
	subtree:add(f.rxbd_lsf, bd1)
	subtree:add(f.rxbd_esf, bd1)
	subtree:add(f.rxbd_asf, bd1)
end

-- Protocol fields
local curr = 31
f.rxbd_bdt = ProtoField.uint32("wcn36xx.rxbd.bdt", "bdt", base.HEX, nil, bitval(curr, 2)); curr = curr - 2
f.rxbd_ft = ProtoField.uint32("wcn36xx.rxbd.ft", "ft", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_dpu_ne = ProtoField.uint32("wcn36xx.rxbd.dpu_ne", "dpu_ne", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_rx_key_id = ProtoField.uint32("wcn36xx.rxbd.rx_key_id", "rx_key_id", base.HEX, nil, bitval(curr, 3)); curr = curr - 3
f.rxbd_ub = ProtoField.uint32("wcn36xx.rxbd.ub", "ub", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_rmf = ProtoField.uint32("wcn36xx.rxbd.rmf", "rmf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_uma_bypass = ProtoField.uint32("wcn36xx.rxbd.uma_bypass", "uma_bypass", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_csr11 = ProtoField.uint32("wcn36xx.rxbd.csr11", "csr11", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_reserved0 = ProtoField.uint32("wcn36xx.rxbd.reserved0", "reserved0", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_scan_learn = ProtoField.uint32("wcn36xx.rxbd.scan_learn", "scan_learn", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_rx_chan = ProtoField.uint32("wcn36xx.rxbd.rx_chan", "rx_chan", base.HEX, nil, bitval(curr, 4)); curr = curr - 4
f.rxbd_rtsf = ProtoField.uint32("wcn36xx.rxbd.rtsf", "rtsf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_bsf = ProtoField.uint32("wcn36xx.rxbd.bsf", "bsf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_a2hf = ProtoField.uint32("wcn36xx.rxbd.a2hf", "a2hf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_st_auf = ProtoField.uint32("wcn36xx.rxbd.st_auf", "st_auf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_dpu_sign = ProtoField.uint32("wcn36xx.rxbd.dpu_sign", "dpu_sign", base.HEX, nil, bitval(curr, 3)); curr = curr - 3
f.rxbd_dpu_rf = ProtoField.uint32("wcn36xx.rxbd.dpu_rf", "dpu_rf", base.HEX, nil, bitval(curr, 8)); curr = curr - 8

curr = 31
f.rxbd_addr3 = ProtoField.uint32("wcn36xx.rxbd.addr3", "addr3", base.HEX, nil, bitval(curr, 8)); curr = curr - 8
f.rxbd_addr2 = ProtoField.uint32("wcn36xx.rxbd.addr2", "addr2", base.HEX, nil, bitval(curr, 8)); curr = curr - 8
f.rxbd_addr1 = ProtoField.uint32("wcn36xx.rxbd.addr1", "addr1", base.HEX, nil, bitval(curr, 8)); curr = curr - 8
f.rxbd_dpu_desc_idx = ProtoField.uint32("wcn36xx.rxbd.dpu_desc_idx", "dpu_desc_idx", base.HEX, nil, bitval(curr, 8)); curr = curr - 8

curr = 31
f.rxbd_rxp_flags = ProtoField.uint32("wcn36xx.rxbd.rxp_flags", "rxp_flags", base.HEX, nil, bitval(curr, 23)); curr = curr - 23
f.rxbd_rate_id = ProtoField.uint32("wcn36xx.rxbd.rate_id", "rate_id", base.HEX, nil, bitval(curr, 9)); curr = curr - 9

f.rxbd_phy_stat0 = ProtoField.uint32("wcn36xx.rxbd.phy_stat0", "phy_stat0", base.HEX)
f.rxbd_phy_stat1 = ProtoField.uint32("wcn36xx.rxbd.phy_stat1", "phy_stat1", base.HEX)

f.rxbd_rx_times = ProtoField.uint32("wcn36xx.rxbd.rx_times", "rx_times", base.HEX)

f.rxbd_pmi_cmd = ProtoField.bytes("wcn36xx.rxbd.pmi_cmd", "pmi_cmd", base.HEX)

curr = 31
f.rxbd_reserved7 = ProtoField.uint32("wcn36xx.rxbd.reserved7", "reserved7", base.HEX, nil, bitval(curr, 4)); curr = curr - 4
f.rxbd_reorder_slot_id = ProtoField.uint32("wcn36xx.rxbd.reorder_slot_id", "reorder_slot_id", base.HEX, nil, bitval(curr, 6)); curr = curr - 6
f.rxbd_reorder_fwd_id = ProtoField.uint32("wcn36xx.rxbd.reorder_fwd_id", "reorder_fwd_id", base.HEX, nil, bitval(curr, 6)); curr = curr - 6
f.rxbd_reserved6 = ProtoField.uint32("wcn36xx.rxbd.reserved6", "reserved6", base.HEX, nil, bitval(curr, 12)); curr = curr - 12
f.rxbd_reorder_code = ProtoField.uint32("wcn36xx.rxbd.reorder_code", "reorder_code", base.HEX, nil, bitval(curr, 4)); curr = curr - 4

curr = 31
f.rxbd_exp_seq_num = ProtoField.uint32("wcn36xx.rxbd.exp_seq_num", "exp_seq_num", base.HEX, nil, bitval(curr, 12)); curr = curr - 12
f.rxbd_cur_seq_num = ProtoField.uint32("wcn36xx.rxbd.cur_seq_num", "cur_seq_num", base.HEX, nil, bitval(curr, 12)); curr = curr - 12
f.rxbd_fr_type_subtype = ProtoField.uint32("wcn36xx.rxbd.fr_type_subtype", "fr_type_subtype", base.HEX, nil, bitval(curr, 8)); curr = curr - 8

curr = 31
f.rxbd_exp_seq_num = ProtoField.uint32("wcn36xx.rxbd.exp_seq_num", "exp_seq_num", base.HEX, nil, bitval(curr, 12)); curr = curr - 12
f.rxbd_cur_seq_num = ProtoField.uint32("wcn36xx.rxbd.cur_seq_num", "cur_seq_num", base.HEX, nil, bitval(curr, 12)); curr = curr - 12
f.rxbd_fr_type_subtype = ProtoField.uint32("wcn36xx.rxbd.fr_type_subtype", "fr_type_subtype", base.HEX, nil, bitval(curr, 8)); curr = curr - 8

curr = 31
f.rxbd_msdu_size = ProtoField.uint32("wcn36xx.rxbd.msdu_size", "msdu_size", base.DEC, nil, bitval(curr, 16)); curr = curr - 16
f.rxbd_sub_fr_id = ProtoField.uint32("wcn36xx.rxbd.fr_id", "fr_id", base.HEX, nil, bitval(curr, 4)); curr = curr - 4
f.rxbd_proc_order = ProtoField.uint32("wcn36xx.rxbd.proc_order", "proc_order", base.HEX, nil, bitval(curr, 4)); curr = curr - 4
f.rxbd_reserved9 = ProtoField.uint32("wcn36xx.rxbd.reserved9", "reserved9", base.HEX, nil, bitval(curr, 4)); curr = curr - 4
f.rxbd_aef = ProtoField.uint32("wcn36xx.rxbd.aef", "aef", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_lsf = ProtoField.uint32("wcn36xx.rxbd.lsf", "lsf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_esf = ProtoField.uint32("wcn36xx.rxbd.esf", "esf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
f.rxbd_asf = ProtoField.uint32("wcn36xx.rxbd.asf", "asf", base.HEX, nil, bitval(curr, 1)); curr = curr - 1
