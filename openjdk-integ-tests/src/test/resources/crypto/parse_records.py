#!/usr/bin/env python
#
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Outputs CSV data for NIST test cases.

Reads in a selection of test cases in NIST response file format on standard
input and outputs a CSV representation of them to standard output, with the
NIST-recommended statement in a header at the top, prefixed by #
characters.  The data is in one of the following formats:

key,iv,plaintext,ciphertext
key,iv,plaintext,ciphertext,tag,aad"""

import argparse
import binascii
import sys


def dequote(value):
    if value[0] == '"' and value[-1] == '"':
        value = binascii.hexlify(value[1:-1])
    return value


def format_records(record):
    # There are a number of different input formats, depending on whether the
    # particular operation includes an IV, single or multiple cipher operations,
    # etc.  Just check for each possibility.
    if 'key' in record and 'iv' in record and 'plaintext' in record and 'ciphertext' in record:
        # A normal operation with an IV
        return ["{key},{iv},{plaintext},{ciphertext}".format(**record)]
    elif 'key' in record and 'nonce' in record and 'plaintext' in record and 'ciphertext' in record:
        # A normal operation with nonce instead of IV
        return ["{key},{nonce},{plaintext},{ciphertext}".format(**record)]
    elif 'key' in record and 'plaintext' in record and 'ciphertext' in record:
        # A normal operation without IV
        return ["{key},,{plaintext},{ciphertext}".format(**record)]
    elif 'keys' in record and 'iv' in record and 'plaintext' in record and 'ciphertext' in record:
        # A single triple-DES operation where all keys are the same
        return ["{keys}{keys}{keys},{iv},{plaintext},{ciphertext}".format(**record)]
    elif 'keys' in record and 'plaintext' in record and 'ciphertext' in record:
        # A single triple-DES operation where all keys are the same without IV
        return ["{keys}{keys}{keys},,{plaintext},{ciphertext}".format(**record)]
    elif ('key1' in record and 'key2' in record and 'key3' in record and 'iv' in record
          and 'plaintext' in record and 'ciphertext' in record):
        # A single triple-DES operation with different keys for each step
        return ["{key1}{key2}{key3},{iv},{plaintext},{ciphertext}".format(**record)]
    elif ('key' in record and 'iv' in record and 'pt' in record and 'aad' in record
          and 'ct' in record and 'tag' in record):
        # An AEAD operation
        return ["{key},{iv},{pt},{ct},{tag},{aad}".format(**record)]
    elif ('key' in record and 'nonce' in record and 'in' in record and 'ad' in record
          and 'ct' in record and 'tag' in record):
        # A BoringSSL AEAD operation
        return ["{key},{nonce},{in},{ct},{tag},{ad}".format(**record)]
    return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--noheader", action='store_true')
    args = parser.parse_args()
    if not args.noheader:
        print """# This data was developed by employees of the National Institute
# of Standards and Technology (NIST), an agency of the Federal
# Government. Pursuant to title 17 United States Code Section 105, works
# of NIST employees are not subject to copyright protection in the United
# States and are considered to be in the public domain.
#
# The data is provided by NIST as a public service and is expressly
# provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
# OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
# AND DATA ACCURACY. NIST does not warrant or make any representations
# regarding the use of the data or the results thereof, including but
# not limited to the correctness, accuracy, reliability or usefulness
# of the data. NIST SHALL NOT BE LIABLE AND YOU HEREBY RELEASE NIST FROM
# LIABILITY FOR ANY INDIRECT, CONSEQUENTIAL, SPECIAL, OR INCIDENTAL DAMAGES
# (INCLUDING DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION,
# LOSS OF BUSINESS INFORMATION, AND THE LIKE), WHETHER ARISING IN TORT,
# CONTRACT, OR OTHERWISE, ARISING FROM OR RELATING TO THE DATA (OR THE USE
# OF OR INABILITY TO USE THIS DATA), EVEN IF NIST HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGES.
#
# To the extent that NIST may hold copyright in countries other than the
# United States, you are hereby granted the non-exclusive irrevocable
# and unconditional right to print, publish, prepare derivative works and
# distribute the NIST data, in any medium, or authorize others to do so
# on your behalf, on a royalty-free basis throughout the world.
#
# You may improve, modify, and create derivative works of the data or any
# portion of the data, and you may copy and distribute such modifications
# or works. Modified works should carry a notice stating that you changed
# the data and should note the date and nature of any such change. Please
# explicitly acknowledge the National Institute of Standards and Technology
# as the source of the data: Data citation recommendations are provided
# below.
#
# Permission to use this data is contingent upon your acceptance of
# the terms of this agreement and upon your providing appropriate
# acknowledgments of NIST's creation of the data.
#"""
    record = {}
    output_lines = []
    for line in sys.stdin.readlines():
        line = line.strip()
        if line == '':
            output_lines.extend(format_records(record))
            record = {}
        if ' =' in line:
            record[line[:line.index('=') - 1].lower()] = line[line.index('=') + 2:]
        if ': ' in line:
            record[line[:line.index(':')].lower()] = dequote(line[line.index(':') + 2:])
        if line == 'FAIL':
            record['fail'] = True
    output_lines.extend(format_records(record))
    if len(output_lines) > 0:
        if output_lines[0].count(',') == 3:
            print """# Data is in the format:
# key,iv,plaintext,ciphertext"""
        elif output_lines[0].count(',') == 5:
            print """# Data is in the format:
# key,iv,plaintext,ciphertext,tag,aad"""
        for output_line in output_lines:
            print output_line



if __name__ == '__main__':
    main()
