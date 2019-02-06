# wifi-presence
Simple presence detection by passive wifi sniffing. esp8266 and Python.

ESP8266 code in esp/ 
Some code borrowed from https://github.com/kalanda/esp8266-sniffer
Listens on _all_ WiFi traffic. Filters out packets of interest and publishes them on the serial line. I used a serial line to get quick responses on detected packages. The alternative would be to change wifi mode and connect to an AP to dump info once in a while.

Python
The python code runs on the host computer (like an RPi with OpenHAB2). It reads and parses the meta info on the serial wire. If it sees a known mac address, it publishes that to a specified MQTT topic. If it sees an unknown MAC details are shown in the terminal. Ignored MACs are ignored except for printing a dash in the terminal to show activity. Information of unknown and known hosts are saved in a file. ARP lookups are cached.

OpenHAB2
There is a one line example in the openhab dir that shows how a presence item could be set up
