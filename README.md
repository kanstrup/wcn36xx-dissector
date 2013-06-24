wcn36xx-dissector
=================

Wireshark protocol dissector for host to wcn36xx communcation protocols

Install instructions
--------------------
1) Copy wcn36xx_hal.lua to ~/.wireshark/plugins/ folder

2) Enable hexdumps in smd.c in wcn36xx driver

3) Run the following from a shell
  <pre>mkfifo /tmp/wireshark
wireshark -k -i /tmp/wireshark &
adb shell cat /proc/kmsg | grep SMD | text2pcap -q -o hex -e 0x3660 - /tmp/wireshark</pre>

