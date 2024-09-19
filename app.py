import streamlit as st
import socket
import requests
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
import dns.resolver

def get_dns_info(domain):
    dns_info = {}
    try:
        ip = socket.gethostbyname(domain)
        dns_info['IP'] = ip
        
        for record_type in ['A', 'CNAME', 'MX', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_info[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
    except socket.gaierror:
        dns_info['Error'] = "Unable to resolve domain"
    return dns_info

def perform_https_request(url):
    result = {}
    session = requests.Session()
    try:
        start_time = time.time()
        response = session.get(url, timeout=60, allow_redirects=False)
        end_time = time.time()
        
        result['TCP Connection'] = "Established"
        result['SSL Handshake'] = "Successful"
        result['Response Headers Received'] = f"{response.elapsed.total_seconds():.2f} seconds"
        result['Full Response Received'] = f"{end_time - start_time:.2f} seconds"
        result['Status Code'] = response.status_code
        result['Headers'] = dict(response.headers)
        result['Body'] = response.text[:200]
        result['Total Time'] = f"{end_time - start_time:.2f} seconds"
        result['Bytes Downloaded'] = len(response.content)
    except requests.exceptions.RequestException as e:
        result['Error'] = str(e)
    return result

st.set_page_config(layout="wide")

st.sidebar.title("Network Diagnostic Tool")

predefined_urls = [
    "https://corp.aiclub.world/research-institute",
    "https://navigator.pyxeda.ai/ai-services",
    "https://learn.aiclub.world/profile"
]

url_choice = st.sidebar.radio("Select a URL:", ["Custom"] + predefined_urls)

if url_choice == "Custom":
    url = st.sidebar.text_input("Enter custom URL:")
else:
    url = url_choice

if url:
    st.title(f"Diagnostics for: {url}")
    
    start_time = datetime.now()
    
    domain = urlparse(url).netloc
    
    dns_info = get_dns_info(domain)
    
    if 'IP' in dns_info:
        with st.expander(f"DNS Information - IP: {dns_info['IP']}"):
            for key, value in dns_info.items():
                if key != 'IP':
                    st.write(f"{key}: {value}")
    else:
        st.error("DNS resolution failed")
    
    https_result = perform_https_request(url)
    
    if 'Error' not in https_result:
        with st.expander(f"HTTPS GET - Time: {https_result['Total Time']}, Bytes: {https_result['Bytes Downloaded']}"):
            st.write("TCP Connection:", https_result['TCP Connection'])
            st.write("SSL Handshake:", https_result['SSL Handshake'])
            st.write("Response Headers Received:", https_result['Response Headers Received'])
            st.write("Full Response Received:", https_result['Full Response Received'])
            st.write("Status Code:", https_result['Status Code'])
            st.write("Response Headers:")
            st.json(https_result['Headers'])
            st.write("Response Body (first 200 characters):")
            st.text(https_result['Body'])
    else:
        st.error(f"HTTPS request failed: {https_result['Error']}")


