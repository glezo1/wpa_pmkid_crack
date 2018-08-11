# wpa_pmkid_crack
python implementation of the attack discovered by @jsteube , described at https://hashcat.net/forum/thread-7717.html
It just calls wpa_passphrase to generate a conf file
,wpa_supplicant to force the generation of the pmkid hash
,generates the 16800-format hash
,and __should__ call hashcat to crack the hash.

Tested on python 3.5, should be ok with any 3.*
