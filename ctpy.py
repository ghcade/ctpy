from datetime import datetime
from pathlib import Path
from typing import List
import sys
import urllib.parse
import urllib.request
import requests
import json

from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
    ServerScanResult,
    ServerScanResultAsJson,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt


class bcolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    RESET = '\033[0m'  # RESET COLOR


def get_security(search_cipher):
    with open('csinfo.json', 'r') as f:
        hjson = json.loads(f.read())
    x = 0
    while hjson['ciphersuites'][x].get(search_cipher) == None:
        x = x + 1
    search_security = hjson['ciphersuites'][x].get(
        search_cipher).get('security')
    try:
        if search_security == 'recommended':
            return bcolors.OK + "  " + search_security + bcolors.RESET + "| "
        elif search_security == 'secure':
            return bcolors.OK + "  " + search_security + bcolors.RESET + "    | "
        elif search_security == 'weak':
            return bcolors.WARNING + "  " + search_security + bcolors.RESET + "      | "
        elif search_security == 'insecure':
            return bcolors.FAIL + "  " + search_security + bcolors.RESET + "  | "
    except requests.exceptions.RequestException as e:
        print(e)


def _print_failed_scan_command_attempt(scan_command_attempt: ScanCommandAttempt) -> None:
    print(
        f"\nError when running ssl_2_0_cipher_suites: {scan_command_attempt.error_reason}:\n"
        f"{scan_command_attempt.error_trace}"
    )


def main(taget) -> None:
    print("Starting the Scans...")
    date_scans_started = datetime.utcnow()

    # First create the scan requests for each server that we want to scan
    try:
        all_scan_requests = [
            ServerScanRequest(
                server_location=ServerNetworkLocation(hostname=taget)),
        ]
    except ServerHostnameCouldNotBeResolved:
        # Handle bad input ie. invalid hostnames
        print("Error resolving the supplied hostnames")
        return

    # Then queue all the scans
    scanner = Scanner()
    scanner.queue_scans(all_scan_requests)

    # And retrieve and process the results for each server
    all_server_scan_results = []
    for server_scan_result in scanner.get_results():
        all_server_scan_results.append(server_scan_result)
        print("\nCHECKING CONNECTIVITY TO SERVER(S)")
        print("----------------------------------")
        print(
            f"SCAN RESULTS FOR {server_scan_result.server_location.hostname}:{server_scan_result.server_location.port}")
        print("----------------------------------")
        # Were we able to connect to the server and run the scan?
        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            # No we weren't
            print(
                f"\nError: Could not connect to {server_scan_result.server_location.hostname}:"
                f" {server_scan_result.connectivity_error_trace}"
            )
            continue

        # Since we were able to run the scan, scan_result is populated
        assert server_scan_result.scan_result

        # Process the result of the SSL 2.0 scan command
        ssl2_attempt = server_scan_result.scan_result.ssl_2_0_cipher_suites
        if ssl2_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            # An error happened when this scan command was run
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif ssl2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            # This scan command was run successfully
            ssl2_result = ssl2_attempt.result
            assert ssl2_result
            if ssl2_result.is_tls_version_supported == True:
                print("SSL 2.0 Cipher Suites:")
                print(
                    f"The server accepted the following {len(ssl2_result.accepted_cipher_suites)} cipher suites:")
                print("  Security  |  Cipher Suite")
                print("---------------------------------------------------")
                for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                    print(
                        f"{get_security(accepted_cipher_suite.cipher_suite.name)} {accepted_cipher_suite.cipher_suite.name}")
                print("---------------------------------------------------")
        # Process the result of the SSL 2.0 scan command
        ssl3_attempt = server_scan_result.scan_result.ssl_3_0_cipher_suites
        if ssl3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            # An error happened when this scan command was run
            _print_failed_scan_command_attempt(ssl3_attempt)
        elif ssl3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            # This scan command was run successfully
            ssl3_result = ssl3_attempt.result
            assert ssl3_result
            if ssl3_result.is_tls_version_supported == True:
                print("SSL 3.0 Cipher Suites:")
                print(
                    f"The server accepted the following {len(ssl3_result.accepted_cipher_suites)} cipher suites:")
                print("  Security  |  Cipher Suite")
                print("---------------------------------------------------")
                for accepted_cipher_suite in ssl3_result.accepted_cipher_suites:
                    print(
                        f"{get_security(accepted_cipher_suite.cipher_suite.name)} {accepted_cipher_suite.cipher_suite.name}")
                print("---------------------------------------------------")
        # Process the result of the TLS 1.0 scan command
        tls1_0_attempt = server_scan_result.scan_result.tls_1_0_cipher_suites
        if tls1_0_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif tls1_0_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_0_result = tls1_0_attempt.result
            assert tls1_0_result
            if tls1_0_result.is_tls_version_supported == True:
                print("TLS 1.0 Cipher Suites:")
                print(
                    f"The server accepted the following {len(tls1_0_result.accepted_cipher_suites)} cipher suites:")
                print("  Security  |  Cipher Suite")
                print("---------------------------------------------------")
                for accepted_cipher_suite in tls1_0_result.accepted_cipher_suites:
                    print(
                        f"{get_security(accepted_cipher_suite.cipher_suite.name)} {accepted_cipher_suite.cipher_suite.name}")
                print("---------------------------------------------------")
        # Process the result of the TLS 1.1 scan command
        tls1_1_attempt = server_scan_result.scan_result.tls_1_1_cipher_suites
        if tls1_1_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif tls1_1_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_1_result = tls1_1_attempt.result
            assert tls1_1_result
            if tls1_1_result.is_tls_version_supported == True:
                print("TLS 1.1 Cipher Suites:")
                print(
                    f"The server accepted the following {len(tls1_1_result.accepted_cipher_suites)} cipher suites:")
                print("  Security  |  Cipher Suite")
                print("---------------------------------------------------")
                for accepted_cipher_suite in tls1_1_result.accepted_cipher_suites:
                    print(
                        f"{get_security(accepted_cipher_suite.cipher_suite.name)} {accepted_cipher_suite.cipher_suite.name}")
                print("---------------------------------------------------")
        # Process the result of the TLS 1.2 scan command
        tls1_2_attempt = server_scan_result.scan_result.tls_1_2_cipher_suites
        if tls1_2_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif tls1_2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_2_result = tls1_2_attempt.result
            assert tls1_2_result
            if tls1_2_result.is_tls_version_supported == True:
                print("TLS 1.2 Cipher Suites:")
                print(
                    f"The server accepted the following {len(tls1_2_result.accepted_cipher_suites)} cipher suites:")
                print("  Security  |  Cipher Suite")
                print("---------------------------------------------------")
                for accepted_cipher_suite in tls1_2_result.accepted_cipher_suites:
                    print(
                        f"{get_security(accepted_cipher_suite.cipher_suite.name)} {accepted_cipher_suite.cipher_suite.name}")
                print("---------------------------------------------------")
        # Process the result of the TLS 1.3 scan command
        tls1_3_attempt = server_scan_result.scan_result.tls_1_3_cipher_suites
        if tls1_3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif tls1_3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_3_result = tls1_3_attempt.result
            assert tls1_3_result
            if tls1_3_result.is_tls_version_supported == True:
                print("TLS 1.3 Cipher Suites:")
                print(
                    f"The server accepted the following {len(tls1_3_result.accepted_cipher_suites)} cipher suites:")
                print("  Security  |  Cipher Suite")
                print("---------------------------------------------------")
                for accepted_cipher_suite in tls1_3_result.accepted_cipher_suites:
                    print(
                        f"{get_security(accepted_cipher_suite.cipher_suite.name)} {accepted_cipher_suite.cipher_suite.name}")
                print("---------------------------------------------------")
    print("\nDone...")


if __name__ == "__main__":
    taget = sys.argv[1]
    main(taget)
