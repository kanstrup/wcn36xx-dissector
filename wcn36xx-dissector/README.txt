-- Protocol dissector for wcn36xx HAL (host to firmware communication)
--
-- Install instructions
-- Copy wcn36xx_hal.lua to ~/.wireshark/plugins/ folder
-- Apply patches to the wifi device driver to hexdump the communication data
-- Run the following from a shell
--   mkfifo /tmp/wireshark
--   wireshark -k -i /tmp/wireshark &
--   adb shell cat /proc/kmsg | grep HALDUMP | text2pcap -q -o hex -e 0x3660 - /tmp/wireshark

