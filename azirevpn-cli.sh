#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2016-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
# Copyright (C) 2024 Netbouncer AB. All Rights Reserved.

die() {
	echo "[-] Error: $1" >&2
	exit 1
}

PROGRAM="${0##*/}"
ARGS=( "$@" )
SELF="${BASH_SOURCE[0]}"
[[ $SELF == */* ]] || SELF="./$SELF"
SELF="$(cd "${SELF%/*}" && pwd -P)/${SELF##*/}"
[[ $UID == 0 ]] || exec sudo -p "[?] $PROGRAM must be run as root. Please enter the password for %u to continue: " -- "$BASH" -- "$SELF" "${ARGS[@]}"

[[ ${BASH_VERSINFO[0]} -ge 4 ]] || die "bash ${BASH_VERSINFO[0]} detected, when bash 4+ required"

set -e
type wg >/dev/null || die "Please install wg and then try again."
type wg-quick >/dev/null || die "Please install wg-quick and then try again."
type curl >/dev/null || die "Please install curl and then try again."
type jq >/dev/null || die "Please install jq and then try again."

PASS_TYPE=password
[[ $1 == --token ]] && PASS_TYPE=token

read -p "[?] Please enter your AzireVPN username: " -r USER
read -p "[?] Please enter your AzireVPN $PASS_TYPE: " -rs PASS
echo

declare -A SERVER_ENDPOINTS
declare -A SERVER_LOCATIONS
declare -A SERVER_PUBKEYS
declare -a SERVER_CODES
PRIVATE_KEY=""

check_api_response() {
	local data="$1"
	FIELDS="$(jq -r '.status,.message' <<<"$data")" || die "Unable to parse response."
	IFS=$'\n' read -r -d '' STATUS MESSAGE <<<"$FIELDS" || true
	if [[ $STATUS != success ]]; then
		if [[ -n $MESSAGE ]]; then
			die "$MESSAGE"
		else
			die "An unknown API error has occurred. Please try again later."
		fi
	fi
}

echo "[+] Contacting AzireVPN API for server locations."
RESPONSE="$(curl -LsS https://api.azirevpn.com/v3/locations)" || die "Unable to connect to AzireVPN API."
check_api_response "$RESPONSE"
FIELDS="$(jq -r '.locations[]| .name,.city,.country,.pool,.pubkey' <<<"$RESPONSE")" || die "Unable to parse response."
while read -r CODE && read -r CITY && read -r COUNTRY && read -r POOL && read -r PUBKEY; do
	SERVER_CODES+=( "$CODE" )
	SERVER_LOCATIONS["$CODE"]="$CITY, $COUNTRY"
	SERVER_ENDPOINTS["$CODE"]="$POOL"
	SERVER_PUBKEYS["$CODE"]="$PUBKEY"
	CONFIGURATION_FILE="/etc/wireguard/azirevpn-$CODE.conf"

	shopt -s nocasematch
	if [ -f "$CONFIGURATION_FILE" ] && [ -z "$PRIVATE_KEY" ]; then
		while read -r line; do
			[[ $line =~ ^PrivateKey[[:space:]]*=[[:space:]]*([a-zA-Z0-9+/]{43}=)[[:space:]]*$ ]] && PRIVATE_KEY="${BASH_REMATCH[1]}" && break
		done < "$CONFIGURATION_FILE"
	fi
	shopt -u nocasematch
done <<<"$FIELDS"

if [[ -z $PRIVATE_KEY ]]; then
	echo "[+] Generating new private key."
	PRIVATE_KEY="$(wg genkey)" || die "Unable to generate private key."
else
	echo "[+] Using existing private key."
fi

echo "[+] Contacting AzireVPN API for token creation."
RESPONSE="$(curl -LsS -H "Content-Type: application/json" -d '{"device_name": "azirevpn-cli", "username": "'"$USER"'", "password": "'"$PASS"'"}' https://api.azirevpn.com/v3/tokens)" || die "Unable to connect to AzireVPN API."
check_api_response "$RESPONSE"
FIELDS="$(jq -r '.data.key' <<<"$RESPONSE")" || die "Unable to parse response."
IFS=$'\n' read -r -d '' TOKEN <<<"$FIELDS" || true

echo "[+] Contacting AzireVPN API for key registration."
RESPONSE="$(curl -LsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"key": "'"$(wg pubkey <<<"$PRIVATE_KEY")"'"}' https://api.azirevpn.com/v3/ips)" || die "Unable to connect to AzireVPN API."
check_api_response "$RESPONSE"
FIELDS="$(jq -r '.data.ipv4_address,.data.ipv6_address,.data.dns' <<<"$RESPONSE")" || die "Unable to parse response."
IFS=$'\n' read -r -d '' IPV4_ADDRESS IPV6_ADDRESS DNS <<<"$FIELDS" || true

DNS=$(echo "$DNS" | jq -r '. | join(", ")')
for CODE in "${SERVER_CODES[@]}"; do
	CONFIGURATION_FILE="/etc/wireguard/azirevpn-$CODE.conf"
	echo "[+] Writing WriteGuard configuration file to $CONFIGURATION_FILE."
	umask 077
	mkdir -p /etc/wireguard/
	rm -f "$CONFIGURATION_FILE.tmp"
	cat > "$CONFIGURATION_FILE.tmp" <<-_EOF
		[Interface]
		PrivateKey = $PRIVATE_KEY
		Address = $IPV4_ADDRESS, $IPV6_ADDRESS
		DNS = $DNS

		[Peer]
		PublicKey = ${SERVER_PUBKEYS["$CODE"]}
		Endpoint = ${SERVER_ENDPOINTS["$CODE"]}:51820
		AllowedIPs = 0.0.0.0/0, ::/0
	_EOF
	mv "$CONFIGURATION_FILE.tmp" "$CONFIGURATION_FILE"
done


echo "[+] Success. The following commands may be run for connecting to AzireVPN:"
for CODE in "${SERVER_CODES[@]}"; do
	echo "- ${SERVER_LOCATIONS["$CODE"]}:"
	echo "  \$ wg-quick up azirevpn-$CODE"
done
