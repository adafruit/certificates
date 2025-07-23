#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Dan Halbert for Adafruit Industries LLC
#
# SPDX-License-Identifier: MIT

#Script to read multiple PEM certificates from a file, extract organization and common names,
# and write a sorted PEM file with comments.
# Written mostly Claude Code given specs by Dan Halbert.

import click
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import List, Tuple, Optional
import os
import base64


def extract_certificates_from_pem(pem_content: str) -> List[str]:
    """Extract individual PEM certificates from a multi-certificate PEM file."""
    cert_pattern = r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)'
    certificates = re.findall(cert_pattern, pem_content, re.DOTALL)
    return certificates


def get_certificate_names(cert_pem: str) -> Tuple[str, str]:
    """Extract organization name and common name from a PEM certificate."""
    try:
        cert_bytes = cert_pem.encode('utf-8')
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        # Extract subject attributes
        subject = cert.subject

        # Get organization name
        org_name = ""
        org_attrs = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if org_attrs:
            org_name = org_attrs[0].value

        # Get common name
        common_name = ""
        cn_attrs = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            common_name = cn_attrs[0].value

        return org_name, common_name

    except Exception as e:
        print(f"Error parsing certificate: {e}")
        return "", ""


def canonicalize_certificate_lines(cert_pem: str, line_length: int) -> str:
    """Canonicalize the line length of base64 data in a PEM certificate."""
    lines = cert_pem.strip().split('\n')
    begin_line = lines[0]
    end_line = lines[-1]

    # Extract just the base64 data (everything between BEGIN and END lines)
    b64_data = ''.join(lines[1:-1])

    # Rewrap to specified line length
    wrapped_lines = []
    for i in range(0, len(b64_data), line_length):
        wrapped_lines.append(b64_data[i:i+line_length])

    # Reconstruct the certificate
    result = [begin_line] + wrapped_lines + [end_line]
    return '\n'.join(result)


def sort_and_format_certificates(input_file: str, output_file: str, line_length: Optional[int] = None):
    """Read PEM file, sort certificates by org/CN, and write formatted output."""

    # Read input file
    try:
        with open(input_file, 'r') as f:
            pem_content = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    # Extract certificates
    certificates = extract_certificates_from_pem(pem_content)
    if not certificates:
        print("No certificates found in input file.")
        return

    print(f"Found {len(certificates)} certificates")

    # Extract names and create sorting tuples
    cert_data = []
    for cert_pem in certificates:
        org_name, common_name = get_certificate_names(cert_pem)
        cert_data.append((org_name, common_name, cert_pem))

    # Sort by (organization_name, common_name)
    cert_data.sort(key=lambda x: (x[0].lower(), x[1].lower()))

    # Write sorted output
    try:
        with open(output_file, 'w') as f:
            for org_name, common_name, cert_pem in cert_data:
                # Write comment with org and CN
                f.write(f"# O={org_name}, CN={common_name}\n")

                # Canonicalize line length if specified
                if line_length is not None:
                    cert_pem = canonicalize_certificate_lines(cert_pem, line_length)

                f.write(cert_pem)
                f.write("\n\n")

        print(f"Sorted certificates written to '{output_file}'")

    except Exception as e:
        print(f"Error writing output file: {e}")


@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', 'output_file',
              help='Output PEM file with sorted certificates. Defaults to input.sorted.pem')
@click.option('--line-length', '-l', type=int,
              help='Canonicalize base64 line length in certificates (e.g., 64, 76)')
def main(input_file, output_file, line_length):
    """Sort PEM certificates by organization and common name.

    INPUT_FILE: Input PEM file containing multiple certificates.

    Output defaults to input.sorted.pem (e.g., input.pem -> input.sorted.pem)
    """
    if output_file is None:
        # Generate default output filename
        name, ext = os.path.splitext(input_file)
        output_file = f"{name}.sorted{ext}"

    sort_and_format_certificates(input_file, output_file, line_length)


if __name__ == "__main__":
    main()
