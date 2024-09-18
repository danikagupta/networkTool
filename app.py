import streamlit as st
import socket
import subprocess
import requests
import time
from datetime import datetime
from typing import List, Tuple, Dict
import concurrent.futures
import threading


def get_dns_info(server: str) -> Tuple[str, Dict[str, str]]:
    """
    Retrieves DNS information for the given server.

    Args:
        server (str): The server name to look up.

    Returns:
        Tuple containing the IP address and a dictionary of DNS information.
    """
    dns_info = {}
    try:
        ip_address = socket.gethostbyname(server)
        dns_info['Canonical Name'] = socket.getfqdn(server)
        dns_info['IP Address'] = ip_address
    except socket.gaierror as e:
        dns_info['Error'] = str(e)
        ip_address = "N/A"
    return ip_address, dns_info


def ping_server(ip: str) -> str:
    """
    Pings the given IP address.

    Args:
        ip (str): The IP address to ping.

    Returns:
        str: The ping result or an error message.
    """
    try:
        # '-c 4' sends 4 packets; '-n' numeric output
        result = subprocess.run(['ping', '-c', '4', '-n', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return result.stderr
    except Exception as e:
        return str(e)


def traceroute_server(ip: str) -> str:
    """
    Performs a traceroute to the given IP address.

    Args:
        ip (str): The IP address to traceroute.

    Returns:
        str: The traceroute result or an error message.
    """
    try:
        result = subprocess.run(['traceroute', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return result.stderr
    except Exception as e:
        return str(e)


def perform_https_request(url: str) -> Dict[str, any]:
    """
    Makes an HTTPS GET request to the given URL and records each step's time.

    Args:
        url (str): The base URL to request.

    Returns:
        Dict containing response details and timings.
    """
    response_details = {}
    timings = {}
    try:
        start_time = time.time()
        session = requests.Session()
        # Resolve TCP connection
        tcp_start = time.time()
        response = session.get(url, stream=True, timeout=10)
        tcp_end = time.time()
        timings['TCP Connection'] = tcp_end - tcp_start

        # SSL Handshake
        ssl_start = tcp_end
        # requests handles SSL handshake internally; approximating time
        ssl_end = time.time()
        timings['SSL Handshake'] = ssl_end - ssl_start

        # Response Headers
        headers_start = ssl_end
        headers = response.headers
        headers_end = time.time()
        timings['Response Headers'] = headers_end - headers_start

        # Full Response
        body_start = headers_end
        body = response.text[:200]  # First 200 characters
        body_end = time.time()
        timings['Full Response'] = body_end - body_start

        total_time = body_end - start_time

        response_details['Status Code'] = response.status_code
        response_details['Headers'] = dict(response.headers)
        response_details['Body'] = body
        response_details['Timings'] = timings
        response_details['Total Time'] = total_time

    except requests.exceptions.RequestException as e:
        response_details['Error'] = str(e)

    return response_details


def diagnose_issues(dns_info: Tuple[str, Dict[str, str]], ping_result: str, traceroute_result: str, https_result: Dict[str, any]) -> str:
    """
    Diagnoses issues based on the results of DNS, Ping, Traceroute, and HTTPS checks.

    Args:
        dns_info (Tuple[str, Dict[str, str]]): DNS information.
        ping_result (str): Result of the ping test.
        traceroute_result (str): Result of the traceroute test.
        https_result (Dict[str, any]): Result of the HTTPS request.

    Returns:
        str: Diagnosis and suggested fixes.
    """
    diagnosis = ""

    ip, dns_details = dns_info
    if ip == "N/A":
        diagnosis += "🛑 DNS resolution failed. Check the server name and your DNS settings.\n"
    else:
        diagnosis += f"✅ DNS resolution succeeded. IP Address: {ip}\n"

    if "Request timeout" in ping_result or "unreachable" in ping_result.lower():
        diagnosis += "⚠️ Ping test failed. The server might be down or ICMP requests are blocked.\n"
    else:
        diagnosis += "✅ Ping test succeeded. Server is reachable.\n"

    if "over" in traceroute_result.lower() or "unreachable" in traceroute_result.lower():
        diagnosis += "⚠️ Traceroute encountered issues. There might be network routing problems.\n"
    else:
        diagnosis += "✅ Traceroute succeeded. Network routing appears normal.\n"

    if 'Error' in https_result:
        diagnosis += f"🛑 HTTPS request failed: {https_result['Error']}\n"
    else:
        diagnosis += f"✅ HTTPS request succeeded with status code {https_result['Status Code']}.\n"

    # Suggested fixes based on diagnosis
    if "DNS resolution failed" in diagnosis:
        diagnosis += "- Ensure the server name is correct.\n- Check your DNS server settings.\n"
    if "Ping test failed" in diagnosis:
        diagnosis += "- Verify if the server is up and running.\n- Check firewall settings that might block ICMP requests.\n"
    if "Traceroute encountered issues" in diagnosis:
        diagnosis += "- Investigate network routing configurations.\n- Contact your ISP if necessary.\n"
    if "HTTPS request failed" in diagnosis:
        diagnosis += "- Ensure the server has a valid SSL certificate.\n- Check if the server is configured to accept HTTPS requests.\n"

    return diagnosis


def main():
    st.title("🛠️ Networking Diagnostic Tool")

    st.sidebar.header("Server Selection")
    predefined_servers = ["google.com", "github.com", "stackoverflow.com"]
    server_choice = st.sidebar.selectbox("Select a server from the list:", ["--Select--"] + predefined_servers)
    custom_server = st.sidebar.text_input("Or enter your own server name:", "")

    # Placeholders for sidebar diagnostics
    sidebar_diagnosis = st.sidebar.empty()
    dns_placeholder = st.sidebar.empty()
    ping_placeholder = st.sidebar.empty()
    traceroute_placeholder = st.sidebar.empty()
    https_placeholder = st.sidebar.empty()
    final_diagnosis_placeholder = st.sidebar.empty()

    if st.sidebar.button("Run Diagnostics"):
        if server_choice != "--Select--":
            server = server_choice
        elif custom_server:
            server = custom_server
        else:
            st.error("Please select a predefined server or enter a custom server name.")
            return

        st.header(f"Diagnostics for: {server}")

        # Initialize placeholders in sidebar
        dns_placeholder.text("🔍 Performing DNS Lookup...")
        ping_placeholder.text("📡 Pinging the server...")
        traceroute_placeholder.text("🗺️ Running Traceroute...")
        https_placeholder.text("🔒 Making HTTPS GET request...")
        final_diagnosis_placeholder.text("🩺 Awaiting diagnosis...")

        # Shared variables to store results
        results = {}
        lock = threading.Lock()

        # Function to update sidebar as each test completes
        def update_sidebar():
            diagnosis = diagnose_issues(
                results.get("dns_info", ("N/A", {})),
                results.get("ping_result", ""),
                results.get("traceroute_result", ""),
                results.get("https_result", {})
            )
            final_diagnosis_placeholder.text("🩺 Diagnosis:")
            # Display the diagnosis in the sidebar
            final_diagnosis_placeholder.markdown(diagnosis)

        # Start parallel diagnostics
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_dns = executor.submit(get_dns_info, server)
            future_ping = None
            future_traceroute = None
            future_https = None

            # Collect DNS result first to get IP for ping and traceroute
            dns_result = future_dns.result()
            with lock:
                results["dns_info"] = dns_result
            ip, dns_info = dns_result

            # Update DNS information in sidebar
            if ip != "N/A":
                with dns_placeholder.expander(f"IP Address: {ip}"):
                    for k, v in dns_info.items():
                        if k != "IP Address":
                            dns_placeholder.text(f"{k}: {v}")
            else:
                dns_placeholder.error("DNS resolution failed.")

            # Submit other diagnostics if DNS was successful
            if ip != "N/A":
                future_ping = executor.submit(ping_server, ip)
                future_traceroute = executor.submit(traceroute_server, ip)
                future_https = executor.submit(perform_https_request, f"https://{server}")
            else:
                ping_placeholder.error("Skipping Ping due to DNS failure.")
                traceroute_placeholder.error("Skipping Traceroute due to DNS failure.")
                https_placeholder.error("Skipping HTTPS request due to DNS failure.")
                # Update diagnosis since other tests are skipped
                diagnosis = diagnose_issues((ip, dns_info), "", "", {})
                final_diagnosis_placeholder.markdown(diagnosis)
                return

            # As futures complete, update the sidebar
            for future in concurrent.futures.as_completed([future_ping, future_traceroute, future_https]):
                if future == future_ping:
                    ping_result = future.result()
                    results["ping_result"] = ping_result
                    if "Request timeout" in ping_result or "unreachable" in ping_result.lower():
                        ping_placeholder.error("⚠️ Ping test failed.")
                    else:
                        ping_placeholder.success("✅ Ping test succeeded.")
                elif future == future_traceroute:
                    traceroute_result = future.result()
                    results["traceroute_result"] = traceroute_result
                    if "over" in traceroute_result.lower() or "unreachable" in traceroute_result.lower():
                        traceroute_placeholder.error("⚠️ Traceroute encountered issues.")
                    else:
                        traceroute_placeholder.success("✅ Traceroute succeeded.")
                elif future == future_https:
                    https_result = future.result()
                    results["https_result"] = https_result
                    if 'Error' in https_result:
                        https_placeholder.error(f"🛑 HTTPS request failed: {https_result['Error']}")
                    else:
                        https_placeholder.success("✅ HTTPS request succeeded.")
                        https_placeholder.markdown(f"**Status Code:** {https_result['Status Code']}")
                        https_placeholder.markdown("**Response Headers:**")
                        https_placeholder.json(https_result['Headers'])
                        https_placeholder.markdown(f"**Body (first 200 characters):** {https_result['Body']}")
                        https_placeholder.markdown("**Timings:**")
                        for step, duration in https_result['Timings'].items():
                            https_placeholder.markdown(f"{step}: {duration:.2f} seconds")
                        https_placeholder.markdown(f"**Total Time:** {https_result['Total Time']:.2f} seconds")

            # Final Diagnosis
            diagnosis = diagnose_issues(
                results.get("dns_info", ("N/A", {})),
                results.get("ping_result", ""),
                results.get("traceroute_result", ""),
                results.get("https_result", {})
            )
            final_diagnosis_placeholder.markdown("🩺 **Diagnosis:**")
            final_diagnosis_placeholder.text(diagnosis)

if __name__ == "__main__":
    main()

