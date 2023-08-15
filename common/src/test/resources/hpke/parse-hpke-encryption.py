# !/usr/bin/env python3

import json

from pathlib import Path

# Can only process base mode 0
# https://www.rfc-editor.org/rfc/rfc9180.html#name-hybrid-public-key-encryptio
MODE_BASE = 0x00

# Can only process KEM DHKEM(X25519, HKDF-SHA256) = 0x0020
# https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism
KEM_DHKEM_X25519_SHA256 = 0x0020

# Can only process KDF HKDF-SHA256
# https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd
KDF_HKDF_SHA256 = 0x0001

# Can process all AEADs except EXPORT-only as this will be generating
# a file to test encryption/decryption only, not secret exports
# https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi
AEAD_EXPORT_ONLY = 0xffff


def parse_and_format(file_in_path: str, file_out_path: str) -> None:
    """
    Parse and formats test-vectors.txt into Conscrypt's format.
    A copy of the JSON file mentioned in RFC 9180 must be placed right next to
    this script. A file will be created named "hpke-encryption.csv"

        Parameters:
            file_in_path: Absolute path to test-vectors.txt.
            file_out_path: Absolute path to output file.
    """

    with open(file_in_path) as input:
        payload = json.load(input)

    records = ["# Several lines conform cryptographic operations ordered in sequence.",
               "#   If records belong to a sequence, the following values won't change: ",
               "#   kem_id, kdf_id, aead_id, info, skRm, skEm, pkRm, and pkEm.",
               "#   The first record in the sequence contains all the data, while the ",
               "#   next records in the sequence has the data omitted to make the file readable.",
               "#   Please use the data from the first record of the sequence when performing ",
               "#   the cryptographic operations. ",
               "# ",
               "# Data is in the format:",
               "# kem_id,kdf_id,aead_id,info,skRm,skEm,pkRm,pkEm,aad,ct,pt"]

    for key in payload:
        # Skip these to test only capabilities exposed by BoringSSL
        if (key["mode"] != MODE_BASE or
                key["kem_id"] != KEM_DHKEM_X25519_SHA256 or
                key["kdf_id"] != KDF_HKDF_SHA256 or
                key["aead_id"] == AEAD_EXPORT_ONLY):
            continue

        firstEncryptionKeyIteration = True
        for encryptionKey in key["encryptions"]:
            if (firstEncryptionKeyIteration):
                firstEncryptionKeyIteration = False
                records.append("{},{},{},{},{},{},{},{},{},{},{}"
                                   .format(str(key["kem_id"]),
                                           str(key["kdf_id"]),
                                           str(key["aead_id"]),
                                           str(key["info"]),
                                           str(key["skRm"]),
                                           str(key["skEm"]),
                                           str(key["pkRm"]),
                                           str(key["pkEm"]),
                                           str(encryptionKey["aad"]),
                                           str(encryptionKey["ct"]),
                                           str(encryptionKey["pt"])))
            else:
                records.append(",,,,,,,,{},{},{}"
                                   .format(str(encryptionKey["aad"]),
                                           str(encryptionKey["ct"]),
                                           str(encryptionKey["pt"])))

        with open(file_out_path, "w") as output:
            output.write("\n".join(records))


def main():
    path = Path(__file__).parent.absolute()
    parse_and_format(path / "test-vectors.txt", path / "hpke-encryption.csv")


if __name__ == "__main__":
    main()
