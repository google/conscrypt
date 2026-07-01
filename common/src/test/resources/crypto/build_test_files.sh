#!/usr/bin/env bash
#
# Writes out all CSV files for crypto test data based on NIST test vectors.
#
# NIST vectors can be obtained from
# http://csrc.nist.gov/groups/STM/cavp/block-ciphers.html#test-vectors
#
# BoringSSL vectors can be obtained from their source under crypto/cipher_extra/test

if [ -z "$1" ] || [ ! -d "$1" ]; then
  echo "The directory of files to process must be supplied as an argument."
  exit 1
fi

cat "$1"/CBC*.rsp | parse_records.py > aes-cbc.csv
cat "$1"/CFB8*.rsp | parse_records.py > aes-cfb8.csv
cat "$1"/CFB128*.rsp | parse_records.py > aes-cfb128.csv
cat "$1"/ECB*.rsp | parse_records.py > aes-ecb.csv
cat "$1"/OFB*.rsp | parse_records.py > aes-ofb.csv
cat "$1"/TCBC*.rsp | parse_records.py > desede-cbc.csv
cat "$1"/TCFB8*.rsp | parse_records.py > desede-cfb8.csv
cat "$1"/TCFB64*.rsp | parse_records.py > desede-cfb64.csv
cat "$1"/TECB*.rsp | parse_records.py > desede-ecb.csv
cat "$1"/TOFB*.rsp | parse_records.py > desede-ofb.csv
# Select all the GCM tests except the GCM-SIV ones
echo "$1"/gcm*.rsp | tr ' ' '\n' | grep -v gcm_siv | xargs cat | parse_records.py > aes-gcm.csv
# GCM-SIV vectors come from BoringSSL, so they don't need the NIST header
cat "$1"/gcm_siv*.rsp | parse_records.py --noheader > aes-gcm-siv.csv
# ChaCha20 vectors come from RFC drafts, so they don't need the NIST header
cat "$1"/chacha20-cipher*.rsp | parse_records.py --noheader > chacha20.csv
# ChaCha20-Poly1305 vectors come from BoringSSL, so they don't need the NIST header
cat "$1"/chacha20-poly1305.rsp | parse_records.py --noheader > chacha20-poly1305.csv
