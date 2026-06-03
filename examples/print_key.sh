#!/usr/bin/env bash
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
pink='\033[0;35m'
teal='\033[0;36m'
clear_color='\033[0m'
usage() {
	printf "${teal}$0${clear_color}: simple script to output AES encryption key and commandnto repack config.bin for ZXHN F670L1FXS.\n"
	printf "Usage: ${teal}$0${clear_color} "
	printf "${pink}SERIAL ${yellow}\"MAC\"${clear_color}"
	printf "\nPut double quotes around the MAC address, ex: \n${teal}$0 ${pink}ZTEG83726942${yellow}" 
	printf ' "f8:4d:a0:62:b6:23"'
	printf "${clear_color}\nwhich would output:\n"
	printf "KEY: ${green}83726942326b260a${clear_color}\n"
	printf "Command to encode config.bin for ZXHN F670L1FXS: \n${green}./encode.py --little-endian-header --include-header --key 83726942326b260a --iv '"
	printf 'ZTE%%FN$GponNJ025'
        printf "' --signature "
	printf '"ZXHN F670L1FXS" INFILE.xml OUTFILE.bin'
	printf "${clear_color}\n"
	exit 1
}
if [ -z "$1" ]; then
	printf "${pink}Serial number${clear_color}: " 
	read serial
else
	serial="$1"
fi
if ! (grep -E "^ZTEG[0-9]{8}" <<< $serial >/dev/null); then
	printf "${red}Error${clear_color}: Serial number ${pink}$serial${clear_color} is invalid\n"
	usage
fi
if [ -z "$2" ]; then
	printf "${yellow}MAC address${clear_color}: "
	read mac
else
	mac="$2"
fi
if ! (grep -E "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$" <<< $mac >/dev/null); then
	printf "${red}Error${clear_color}: MAC address ${yellow}$mac${clear_color} is invalid\n"
	usage
fi
procserial="$(grep -oE "[0-9]{8}" <<< $serial)"
procmac="$(sed 's/://g' <<< $mac | rev | head -c 8)"
key="$procserial$procmac"
printf "KEY: ${green}$key${clear_color}\n"
printf "Command to encode config.bin for ZXHN F670L1FXS: \n${green}"
printf './encode.py --little-endian-header --include-header --key '
printf "$key --iv '"
printf 'ZTE%%FN$GponNJ025' 
printf "' --signature "
printf '"ZXHN F670L1FXS"' 
printf " ${clear_color}INFILE.xml OUTFILE.bin\n"


