# wpa_pmkid_crack
python implementation of the attack discovered by @jsteube , described at https://hashcat.net/forum/thread-7717.html
It just calls wpa_passphrase to generate a conf file, wpa_supplicant to force the generation of the pmkid hash.

__Should__ call hashcat to crack the hash.
