wcn36xx-dissector
=================

Wireshark protocol dissector host to wcn36xx communcation protocols

Install instructions
--------------------
Copy wcn36xx_hal.lua to ~/.wireshark/plugins/ folder
Enable hexdumps in smd.c in wcn36xx driver
Run the following from a shell
  mkfifo /tmp/wireshark
  wireshark -k -i /tmp/wireshark &
  adb shell cat /proc/kmsg | grep SMD | text2pcap -q -o hex -e 0x3660 - /tmp/wireshark

