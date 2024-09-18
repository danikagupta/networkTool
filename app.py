import streamlit as st
import socket
import subprocess
import requests
import time
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any
from urllib.parse import urlparse

# Diagnostic Functions

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
        # Modify the ping command based on the operating system
        import platform
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(['ping', param, '4', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        if result.returncode == 0:
            return result.stdout
        else:
            return result.stderr
    except subprocess.TimeoutExpired:
        return "Ping command timed out."
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
        import platform
        command = ['tracert', ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        if result.returncode == 0:
            return result.stdout
        else:
            return result.stderr
    except subprocess.TimeoutExpired:
        return "Traceroute command timed out."
    except Exception as e:
        return str(e)

def perform_https_request(url: str) -> Dict[str, Any]:
    """
    Performs an HTTPS GET request to the specified URL and records timings.

    Args:
        url (str): The URL to send the GET request to.

    Returns:
        Dict containing the HTTPS response details and timings.
    """
    result = {}
    try:
        start_time = time.time()
        response = requests.get(url, timeout=120)
        end_time = time.time()
        result['Status Code'] = response.status_code
        result['Headers'] = dict(response.headers)
        result['Body'] = response.text[:200]  # First 200 characters
        result['Timings'] = {
            'DNS Lookup': response.elapsed.total_seconds(),
            'Total Time': end_time - start_time
        }
        result['Bytes Downloaded'] = len(response.content)
    except requests.RequestException as e:
        result['Error'] = str(e)
    return result

def diagnose_issues(dns_info: Tuple[str, Dict[str, str]], ping_result: str, traceroute_result: str, https_result: Dict[str, Any]) -> str:
    """
    Diagnoses issues based on the results of DNS, Ping, Traceroute, and HTTPS checks.

    Args:
        dns_info (Tuple[str, Dict[str, str]]): DNS information.
        ping_result (str): Result of the ping test.
        traceroute_result (str): Result of the traceroute test.
        https_result (Dict[str, Any]): Result of the HTTPS request.

    Returns:
        str: Diagnosis and suggested fixes.
    """
    diagnosis = ""

    ip, dns_details = dns_info
    if ip == "N/A":
        diagnosis += "🛑 DNS resolution failed. Check the server name and your DNS settings.\n"
    else:
        diagnosis += f"✅ DNS resolution succeeded. IP Address: {ip}\n"

    if ping_result:
        if "Request timeout" in ping_result or "unreachable" in ping_result.lower():
            diagnosis += "⚠️ Ping test failed. The server might be down or ICMP requests are blocked.\n"
        else:
            diagnosis += "✅ Ping test succeeded. Server is reachable.\n"

    if traceroute_result:
        if "over" in traceroute_result.lower() or "unreachable" in traceroute_result.lower():
            diagnosis += "⚠️ Traceroute encountered issues. There might be network routing problems.\n"
        else:
            diagnosis += "✅ Traceroute succeeded. Network routing appears normal.\n"

    if 'Error' in https_result:
        diagnosis += f"🛑 HTTPS request failed: {https_result['Error']}\n"
    elif 'Status Code' in https_result:
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

# Streamlit Application

def main():
    st.set_page_config(page_title="🛠️ Networking Diagnostic Tool", layout="wide")
    st.title("🛠️ Networking Diagnostic Tool")

    # Initialize session state
    if 'diagnostics_running' not in st.session_state:
        st.session_state.diagnostics_running = False
    if 'start_time' not in st.session_state:
        st.session_state.start_time = None
    if 'elapsed_time' not in st.session_state:
        st.session_state.elapsed_time = "00:00:00"
    if 'timeout_reached' not in st.session_state:
        st.session_state.timeout_reached = False

    # Layout: Single column
    st.header("🔧 Server Selection & Diagnostics")
    st.markdown("---")

    # Server Selection and Diagnostic Options
    server_choice = st.selectbox("Select a server from the list:", ["--Select--", "google.com", "github.com", "stackoverflow.com"], key="server_choice")
    custom_input = st.text_input("Or enter a URL (e.g., https://example.com):", key="custom_input")

    st.markdown("---")
    st.header("🧰 Select Diagnostics to Run")
    run_dns = st.checkbox("🔍 DNS Mapping", value=True, key="run_dns")  # DNS is essential
    run_ping = st.checkbox("📡 Ping Test", value=False, key="run_ping")
    run_traceroute = st.checkbox("🗺️ Traceroute", value=False, key="run_traceroute")
    run_https = st.checkbox("🔒 HTTPS GET Request", value=True, key="run_https")  # HTTPS is essential

    st.markdown("---")
    run_button = st.button("🚀 Run Diagnostics", disabled=st.session_state.diagnostics_running)

    # Display Server Name
    server_display = st.empty()
    if run_button and not st.session_state.diagnostics_running:
        # Determine server and URL
        if server_choice != "--Select--":
            server = server_choice
            url = f"https://{server}"
        elif custom_input.strip():
            parsed_url = urlparse(custom_input.strip())
            if parsed_url.scheme and parsed_url.netloc:
                server = parsed_url.netloc
                url = custom_input.strip()
            else:
                server = custom_input.strip()
                url = custom_input.strip()
        else:
            st.error("❌ Please select a predefined server or enter a valid URL.")
            st.stop()

        # Validate that at least one diagnostic is selected
        if not any([run_dns, run_ping, run_traceroute, run_https]):
            st.error("❌ Please select at least one diagnostic test to run.")
            st.stop()

        # Initialize diagnostics state
        st.session_state.diagnostics_running = True
        st.session_state.start_time = datetime.now()
        st.session_state.elapsed_time = "00:00:00"
        st.session_state.timeout_reached = False

        # Display Server Name
        server_display.markdown(f"## 🖥️ Selected Server: **{server}**")
        st.markdown("---")

        # Placeholders for Diagnostic Results
        timer_placeholder = st.empty()
        dns_placeholder = st.empty()
        ping_placeholder = st.empty()
        traceroute_placeholder = st.empty()
        https_placeholder = st.empty()
        diagnosis_placeholder = st.empty()

        # Timer Function
        def run_timer():
            while st.session_state.diagnostics_running and not st.session_state.timeout_reached:
                current_time = datetime.now()
                elapsed = current_time - st.session_state.start_time
                if elapsed >= timedelta(minutes=3):
                    st.session_state.timeout_reached = True
                    st.session_state.diagnostics_running = False
                    st.error("⏰ Diagnostics timed out after 3 minutes.")
                    st.stop()
                else:
                    st.session_state.elapsed_time = str(elapsed).split(".")[0]  # Remove microseconds
                timer_placeholder.markdown(f"### ⏱️ Elapsed Time: {st.session_state.elapsed_time}")
                time.sleep(1)

        # Start Timer
        import threading
        timer_thread = threading.Thread(target=run_timer, daemon=True)
        timer_thread.start()

        # Run Diagnostics Synchronously
        try:
            results = {}

            # DNS Mapping
            if run_dns:
                dns_placeholder.markdown("**🔍 DNS Mapping:** Running...")
                dns_result = get_dns_info(server)
                results["dns_info"] = dns_result
                ip, dns_info = dns_result

                if ip != "N/A":
                    dns_placeholder.markdown("**🔍 DNS Mapping:** ✅ Succeeded")
                else:
                    st.error("🛑 DNS resolution failed. Skipping dependent diagnostics.")
            else:
                ip = "N/A"

            # Ping Test
            if run_ping and ip != "N/A":
                ping_placeholder.markdown("**📡 Ping Test:** Running...")
                ping_result = ping_server(ip)
                results["ping_result"] = ping_result

                if "Request timeout" in ping_result or "unreachable" in ping_result.lower():
                    ping_placeholder.markdown("**📡 Ping Test:** ⚠️ Failed")
                    st.warning("⚠️ Ping test failed. The server might be down or ICMP requests are blocked.")
                else:
                    ping_placeholder.markdown("**📡 Ping Test:** ✅ Succeeded")
                    st.success("✅ Ping test succeeded. Server is reachable.")
            elif run_ping:
                # Silently ignore skipped Ping Test
                pass

            # Traceroute
            if run_traceroute and ip != "N/A":
                traceroute_placeholder.markdown("**🗺️ Traceroute:** Running...")
                traceroute_result = traceroute_server(ip)
                results["traceroute_result"] = traceroute_result

                if "request timed out" in traceroute_result.lower() or "unreachable" in traceroute_result.lower():
                    traceroute_placeholder.markdown("**🗺️ Traceroute:** ⚠️ Failed")
                    st.warning("⚠️ Traceroute encountered issues. There might be network routing problems.")
                else:
                    traceroute_placeholder.markdown("**🗺️ Traceroute:** ✅ Succeeded")
                    st.success("✅ Traceroute succeeded. Network routing appears normal.")
            elif run_traceroute:
                # Silently ignore skipped Traceroute
                pass

            # HTTPS GET Request
            if run_https:
                https_placeholder.markdown("**🔒 HTTPS GET Request:** Running...")
                https_result = perform_https_request(url)
                results["https_result"] = https_result

                if 'Error' in https_result:
                    https_placeholder.markdown("**🔒 HTTPS GET Request:** 🛑 Failed")
                    st.error(f"🛑 HTTPS request failed: {https_result['Error']}")
                else:
                    https_placeholder.markdown("**🔒 HTTPS GET Request:** ✅ Succeeded")
                    # Using expander to show detailed HTTPS info
                    with https_placeholder.expander("📝 View Details"):
                        st.markdown(f"**Status Code:** {https_result['Status Code']}")
                        st.markdown(f"**Bytes Downloaded:** {https_result['Bytes Downloaded']} bytes")
                        st.markdown(f"**Timings:**")
                        for step, duration in https_result['Timings'].items():
                            st.markdown(f"- **{step}:** {duration:.2f} seconds")
            # Final Diagnosis
            diagnosis = diagnose_issues(
                results.get("dns_info", ("N/A", {})),
                results.get("ping_result", "") if run_ping else "",
                results.get("traceroute_result", "") if run_traceroute else "",
                results.get("https_result", {}) if run_https else {}
            )
            diagnosis_placeholder.markdown("## 🩺 Diagnosis:")
            st.text(diagnosis)

        except Exception as e:
            st.error(f"An unexpected error occurred: {str(e)}")

        finally:
            # Stop diagnostics
            st.session_state.diagnostics_running = False
            # Ensure timer stops
            timer_thread.join()

            # Display Total Time
            elapsed_total_time = datetime.now() - st.session_state.start_time
            if elapsed_total_time > timedelta(minutes=3):
                elapsed_total_time = timedelta(minutes=3)
            st.session_state.elapsed_time = str(elapsed_total_time).split(".")[0]
            timer_placeholder.markdown(f"### ⏱️ Total Time: {st.session_state.elapsed_time}")

    # Run the app
if __name__ == "__main__":
    main()

