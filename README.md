wcn36xx-dissector
=================

Wireshark protocol dissector for host to wcn36xx communication protocols

Install instructions
--------------------
1) Copy *.lua to ~/.wireshark/plugins/ folder


Capturing with wcn36xx driver
-----------------------------
1) Enable hexdumps in smd.c in wcn36xx driver (for wcn36xx_hal.lua)

1) Enable hexdumps in txrx.c in wcn36xx driver (for wcn36xx_rxbd.lua)

1) Enable hexdumps in dxe.c in wcn36xx driver (for wcn36xx_txbd.lua)

2) Run the following from a shell: <pre>mkfifo /tmp/wireshark</pre>

Live capture
------------
1) Start wireshark: <pre>wireshark -k -i /tmp/wireshark &</pre>
2) To capture HAL commands run: <pre>adb shell cat /proc/kmsg | grep -E "SMD <<<|HAL >>>" | text2pcap -q -o hex -e 0x3660 - /tmp/wireshark</pre>
2) To capture skb rxbd run: <pre>adb shell cat /proc/kmsg | grep "BD   <<<" | text2pcap -q -o hex -e 0x3661 - /tmp/wireshark</pre>
2) To capture skb txbd run: <pre>adb shell cat /proc/kmsg | grep "BD   >>> " | text2pcap -q -o hex -e 0x3662 - /tmp/wireshark</pre>


Capturing from prima driver
---------------------------
The prima driver patch dumps commands and buffer descriptors with an 802.11 header. This makes it possible to dump everything together in one file,
including actual frame data, complete with timestamps.

1) Patch prima driver with <pre>0001-Trace-communication-between-host-and-wcn.patch</pre>
2) Capture kernel log <pre>adb shell cat /proc/kmsg | tee dump.txt</pre>
3) Convert to pcap: <pre>cat dump.txt | grep primad | perl -pe 's/.{4}(.{12}).{20}(.+)/$1 $2/' | text2pcap -q -t "%s." -l 105 - dump.pcap</pre>


Example dumps
-------------
The examples folder contains some dumps takes from a patched prima driver
