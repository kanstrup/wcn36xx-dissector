wcn36xx-dissector
=================

Wireshark protocol dissector for host to wcn36xx communcation protocols

Install instructions
--------------------
1) Copy *.lua to ~/.wireshark/plugins/ folder

2) Enable hexdumps in smd.c in wcn36xx driver (for wcn36xx_hal.lua)

2) Enable hexdumps in dxe.c in wcn36xx driver (for wcn36xx_txbd.lua)

3) Run the following from a shell: <pre>mkfifo /tmp/wireshark</pre>

Live capture
------------
1) Start wireshark: <pre>wireshark -k -i /tmp/wireshark &</pre>
2) To capture HAL commands run: <pre>adb shell cat /proc/kmsg | grep SMD | text2pcap -q -o hex -e 0x3660 - /tmp/wireshark</pre>
2) To capture skb txbd run: <pre>adb shell cat /proc/kmsg | grep "BD   >>> " | text2pcap -q -o hex -e 0x3662 - /tmp/wireshark</pre>
