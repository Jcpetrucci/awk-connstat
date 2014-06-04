#!/usr/bin/awk -f
BEGIN {
cols[1]="SRC IP"
cols[2]="SRC PORT"
cols[3]="DST IP"
cols[4]="DST PORT"
cols[5]="IPP"
cols[6]="DIR"

for (i = 1; i <= 6; i++) {
	printf "%17.15s", cols[i];
}
printf "\n";
"tput cols" | getline screenWidth
for (i = 1; i<= screenWidth; i++) printf "-"
printf "\n";

}

$1 ~ /<0000000(0|1)/ { # Find connections - ignore headers
	if (NF > 15) { # Find non-symlink connections
		connectionIndex[NR] = "1"
		$0 = tolower($0)
		$0 = gensub( /[^0-9a-f ]/, "", "g", $0 ); # Strip illegal characters
		# Direction
		$1 ~ /00000000/ ? connections[NR, "dir"] = "IN" : connections[NR, "dir"] = "OUT" # Determine direction
		# Source IP
		connections[NR, "srcip"] = \
			strtonum("0x" substr($2, 1, 2))"."\
			strtonum("0x" substr($2, 3, 2))"."\
			strtonum("0x" substr($2, 5, 2))"."\
			strtonum("0x" substr($2, 7, 2))
		# Source port
		connections[NR, "srcport"] = strtonum("0x" $3)
		# Destination IP
		connections[NR, "dstip"] = \
			strtonum("0x" substr($4, 1, 2))"."\
			strtonum("0x" substr($4, 3, 2))"."\
			strtonum("0x" substr($4, 5, 2))"."\
			strtonum("0x" substr($4, 7, 2))
		# Destination port
		connections[NR, "dstport"] = strtonum("0x" $5)
		# IP Protocol
		connections[NR, "ipp"] = strtonum("0x" $6)
	}
#print connections["6" SUBSEP "dir"];
}

END {
for (cindex in connectionIndex) {
	for (i = 1; i <= 6; i++) {
		printf "%17.15s", connections[cindex SUBSEP gensub( / /, "", "g", tolower(cols[i]))];
	}
	printf "\n";
}

print "END"
}
