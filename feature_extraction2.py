from urllib.parse import urlparse, parse_qs
import re
import socket
import whois
import requests
from bs4 import BeautifulSoup
import time
import ssl
from datetime import datetime
from googleapiclient.discovery import build
from dateutil import parser
from OpenSSL import SSL
import certifi
import tldextract


def extractfeatures2(url):
    # Parse URL
    parsed_url = urlparse(url)

    # Extract url features
    qty_dot_url = url.count(".")
    qty_hyphen_url = url.count("-")
    qty_underline_url = url.count("_")
    qty_slash_url = url.count("/")
    qty_questionmark_url = url.count("?")
    qty_equal_url = url.count("=")
    qty_at_url = url.count("@")
    qty_and_url = url.count("&")
    qty_exclamation_url = url.count("!")
    qty_space_url = url.count(" ")
    qty_tilde_url = url.count("~")
    qty_comma_url = url.count(",")
    qty_plus_url = url.count("+")
    qty_asterisk_url = url.count("*")
    qty_hashtag_url = url.count("#")
    qty_dollar_url = url.count("$")
    qty_percent_url = url.count("%")
    qty_tld_url = get_tld_from_url(url)
    length_url = len(url)

    # Extract domain features
    domain = parsed_url.netloc
    qty_dot_domain = domain.count(".")
    qty_hyphen_domain = domain.count("-")
    qty_underline_domain = domain.count("_")
    qty_slash_domain = domain.count("/")
    qty_questionmark_domain = domain.count("?")
    qty_equal_domain = domain.count("=")
    qty_at_domain = domain.count("@")
    qty_and_domain = domain.count("&")
    qty_exclamation_domain = domain.count("!")
    qty_space_domain = domain.count(" ")
    qty_tilde_domain = domain.count("~")
    qty_comma_domain = domain.count(",")
    qty_plus_domain = domain.count("+")
    qty_asterisk_domain = domain.count("*")
    qty_hashtag_domain = domain.count("#")
    qty_dollar_domain = domain.count("$")
    qty_percent_domain = domain.count("%")
    qty_vowels_domain = sum(1 for char in domain if char.lower() in "aeiou")
    domain_length = len(domain)
    domain_in_ip = domain_is_ip(domain)
    server_client_domain = server_client_relation(url)

    # Extract directory features
    path = parsed_url.path
    qty_dot_directory = path.count(".")
    qty_hyphen_directory = path.count("-")
    qty_underline_directory = path.count("_")
    qty_slash_directory = path.count("/")
    qty_questionmark_directory = path.count("?")
    qty_equal_directory = path.count("=")
    qty_at_directory = path.count("@")
    qty_and_directory = path.count("&")
    qty_exclamation_directory = path.count("!")
    qty_space_directory = path.count(" ")
    qty_tilde_directory = path.count("~")
    qty_comma_directory = path.count(",")
    qty_plus_directory = path.count("+")
    qty_asterisk_directory = path.count("*")
    qty_hashtag_directory = path.count("#")
    qty_dollar_directory = path.count("$")
    qty_percent_directory = path.count("%")
    directory_length = len(path)

    # Extract file features
    filename = path.split("/")[-1]
    qty_dot_file = filename.count(".")
    qty_hyphen_file = filename.count("-")
    qty_underline_file = filename.count("_")
    qty_slash_file = filename.count("/")
    qty_questionmark_file = filename.count("?")
    qty_equal_file = filename.count("=")
    qty_at_file = filename.count("@")
    qty_and_file = filename.count("&")
    qty_exclamation_file = filename.count("!")
    qty_space_file = filename.count(" ")
    qty_tilde_file = filename.count("~")
    qty_comma_file = filename.count(",")
    qty_plus_file = filename.count("+")
    qty_asterisk_file = filename.count("*")
    qty_hashtag_file = filename.count("#")
    qty_dollar_file = filename.count("$")
    qty_percent_file = filename.count("%")
    file_length = len(filename)

    # Extract parameters features
    params = parsed_url.query
    qty_dot_params = params.count(".")
    qty_hyphen_params = params.count("-")
    qty_underline_params = params.count("_")
    qty_slash_params = params.count("/")
    qty_questionmark_params = params.count("?")
    qty_equal_params = params.count("=")
    qty_at_params = params.count("@")
    qty_and_params = params.count("&")
    qty_exclamation_params = params.count("!")
    qty_space_params = params.count(" ")
    qty_tilde_params = params.count("~")
    qty_comma_params = params.count(",")
    qty_plus_params = params.count("+")
    qty_asterisk_params = params.count("*")
    qty_hashtag_params = params.count("#")
    qty_dollar_params = params.count("$")
    qty_percent_params = params.count("%")
    params_length = len(params)
    tld_present_params = int(parsed_url.netloc.endswith(params))
    qty_params = get_qty_params(url)

    # Extract other features
    email_in_url = is_email_in_url(url)
    time_response = get_time_response(url)
    domain_spf = has_spf_record(domain)
    asn_ip = get_asn_for_ip(socket.gethostbyname(domain))
    time_domain_activation, time_domain_expiration = get_domain_activation_expiration(
        domain
    )
    qty_ip_resolved, qty_nameservers, qty_mx_servers = get_domain_resolution_info(
        domain
    )
    ttl_hostname = get_ttl_for_hostname(url)
    tls_ssl_certificate = has_valid_ssl_certificate(domain)
    qty_redirects = get_redirect_count(url)
    url_google_index, domain_google_index = get_google_index_info(url, parsed_url)
    url_shortened = is_url_shortened(url)

    return {
        "qty_dot_url": qty_dot_url,
        "qty_hyphen_url": qty_hyphen_url,
        "qty_underline_url": qty_underline_url,
        "qty_slash_url": qty_slash_url,
        "qty_questionmark_url": qty_questionmark_url,
        "qty_equal_url": qty_equal_url,
        "qty_at_url": qty_at_url,
        "qty_and_url": qty_and_url,
        "qty_exclamation_url": qty_exclamation_url,
        "qty_space_url": qty_space_url,
        "qty_tilde_url": qty_tilde_url,
        "qty_comma_url": qty_comma_url,
        "qty_plus_url": qty_plus_url,
        "qty_asterisk_url": qty_asterisk_url,
        "qty_hashtag_url": qty_hashtag_url,
        "qty_dollar_url": qty_dollar_url,
        "qty_percent_url": qty_percent_url,
        "qty_tld_url": qty_tld_url,
        "length_url": length_url,
        "qty_dot_domain": qty_dot_domain,
        "qty_hyphen_domain": qty_hyphen_domain,
        "qty_underline_domain": qty_underline_domain,
        "qty_slash_domain": qty_slash_domain,
        "qty_questionmark_domain": qty_questionmark_domain,
        "qty_equal_domain": qty_equal_domain,
        "qty_at_domain": qty_at_domain,
        "qty_and_domain": qty_and_domain,
        "qty_exclamation_domain": qty_exclamation_domain,
        "qty_space_domain": qty_space_domain,
        "qty_tilde_domain": qty_tilde_domain,
        "qty_comma_domain": qty_comma_domain,
        "qty_plus_domain": qty_plus_domain,
        "qty_asterisk_domain": qty_asterisk_domain,
        "qty_hashtag_domain": qty_hashtag_domain,
        "qty_dollar_domain": qty_dollar_domain,
        "qty_percent_domain": qty_percent_domain,
        "qty_vowels_domain": qty_vowels_domain,
        "domain_length": domain_length,
        "domain_in_ip": domain_in_ip,
        "server_client_domain": server_client_domain,
        "qty_dot_directory": qty_dot_directory,
        "qty_hyphen_directory": qty_hyphen_directory,
        "qty_underline_directory": qty_underline_directory,
        "qty_slash_directory": qty_slash_directory,
        "qty_questionmark_directory": qty_questionmark_directory,
        "qty_equal_directory": qty_equal_directory,
        "qty_at_directory": qty_at_directory,
        "qty_and_directory": qty_and_directory,
        "qty_exclamation_directory": qty_exclamation_directory,
        "qty_space_directory": qty_space_directory,
        "qty_tilde_directory": qty_tilde_directory,
        "qty_comma_directory": qty_comma_directory,
        "qty_plus_directory": qty_plus_directory,
        "qty_asterisk_directory": qty_asterisk_directory,
        "qty_hashtag_directory": qty_hashtag_directory,
        "qty_dollar_directory": qty_dollar_directory,
        "qty_percent_directory": qty_percent_directory,
        "directory_length": directory_length,
        "qty_dot_file": qty_dot_file,
        "qty_hyphen_file": qty_hyphen_file,
        "qty_underline_file": qty_underline_file,
        "qty_slash_file": qty_slash_file,
        "qty_questionmark_file": qty_questionmark_file,
        "qty_equal_file": qty_equal_file,
        "qty_at_file": qty_at_file,
        "qty_and_file": qty_and_file,
        "qty_exclamation_file": qty_exclamation_file,
        "qty_space_file": qty_space_file,
        "qty_tilde_file": qty_tilde_file,
        "qty_comma_file": qty_comma_file,
        "qty_plus_file": qty_plus_file,
        "qty_asterisk_file": qty_asterisk_file,
        "qty_hashtag_file": qty_hashtag_file,
        "qty_dollar_file": qty_dollar_file,
        "qty_percent_file": qty_percent_file,
        "file_length": file_length,
        "qty_dot_params": qty_dot_params,
        "qty_hyphen_params": qty_hyphen_params,
        "qty_underline_params": qty_underline_params,
        "qty_slash_params": qty_slash_params,
        "qty_questionmark_params": qty_questionmark_params,
        "qty_equal_params": qty_equal_params,
        "qty_at_params": qty_at_params,
        "qty_and_params": qty_and_params,
        "qty_exclamation_params": qty_exclamation_params,
        "qty_space_params": qty_space_params,
        "qty_tilde_params": qty_tilde_params,
        "qty_comma_params": qty_comma_params,
        "qty_plus_params": qty_plus_params,
        "qty_asterisk_params": qty_asterisk_params,
        "qty_hashtag_params": qty_hashtag_params,
        "qty_dollar_params": qty_dollar_params,
        "qty_percent_params": qty_percent_params,
        "params_length": params_length,
        "tld_present_params": tld_present_params,
        "qty_params": qty_params,
        "email_in_url": email_in_url,
        "time_response": time_response,
        "domain_spf": domain_spf,
        "asn_ip": asn_ip,
        "time_domain_activation": time_domain_activation,
        "time_domain_expiration": time_domain_expiration,
        "qty_ip_resolved": qty_ip_resolved,
        "qty_nameservers": qty_nameservers,
        "qty_mx_servers": qty_mx_servers,
        "ttl_hostname": ttl_hostname,
        "tls_ssl_certificate": tls_ssl_certificate,
        "qty_redirects": qty_redirects,
        "url_google_index": url_google_index,
        "domain_google_index": domain_google_index,
        "url_shortened": url_shortened,
    }


def get_qty_params(url):
    # Parse the URL
    parsed_url = urlparse(url)

    # Extract the query string
    query_string = parsed_url.query

    # Parse the query string into a dictionary of parameters
    parsed_params = parse_qs(query_string)

    # Count the number of parameters
    qty_params = len(parsed_params)

    return qty_params


def get_tld_from_url(url):
    # Use tldextract to extract the TLD
    extracted_info = tldextract.extract(url)
    tld = extracted_info.suffix

    # Count the number of dots in the TLD
    dot_count_in_tld = tld.count(".")

    # If there is more than one dot, multiple TLDs are present
    return dot_count_in_tld + 1


def domain_is_ip(domain):
    try:
        m = socket.inet_aton(domain)
        print("M =", m)
        return 1
    except socket.error:
        return 0


def server_client_relation(url):
    try:
        response = requests.get(url, timeout=5)
        server_header = response.headers.get("server")
        client_header = response.headers.get("client")
        if server_header and client_header:
            return int(server_header.lower() == client_header.lower())
    except requests.RequestException:
        pass
    return -1


def is_email_in_url(url):
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    value = bool(re.search(email_pattern, url))
    return 1 if value else 0


def get_time_response(url):
    try:
        start_time = time.time()
        requests.get(url, timeout=5)
        end_time = time.time()
        return end_time - start_time
    except requests.RequestException:
        pass
    return -1


def has_spf_record(domain):
    try:
        spf_records = whois.whois(domain).get("spf", [])
        return int(bool(spf_records))
    except whois.parser.PywhoisError:
        pass
    return -1


def get_asn_for_ip(ip):
    try:
        asn_info = requests.get(f"https://ipinfo.io/{ip}/json").json()
        asn = asn_info.get("asn")
        return 0 if asn == None else 1
    except requests.RequestException:
        pass
    return -1


def get_domain_activation_expiration(domain):
    try:
        domain_info = whois.whois(domain)
        activation_date = domain_info.get("creation_date")
        expiration_date = domain_info.get("expiration_date")

        if activation_date and expiration_date:
            activation_date = (
                activation_date[0]
                if isinstance(activation_date, list)
                else activation_date
            )
            expiration_date = (
                expiration_date[0]
                if isinstance(expiration_date, list)
                else expiration_date
            )

            # Convert activation and expiration dates to datetime objects
            activation_datetime = (
                datetime.strptime(activation_date, "%Y-%m-%d %H:%M:%S")
                if isinstance(activation_date, str)
                else activation_date
            )
            expiration_datetime = (
                datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S")
                if isinstance(expiration_date, str)
                else expiration_date
            )

            # Calculate the count of days from activation to current date
            days_since_activation = (datetime.now() - activation_datetime).days

            # Calculate the count of days from current date to expiration
            days_until_expiration = (expiration_datetime - datetime.now()).days

            return days_since_activation, days_until_expiration

    except whois.parser.PywhoisError:
        pass

    return -1, -1


def get_domain_resolution_info(domain):
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        qty_ip_resolved = len(ip_addresses)
        nameservers = whois.whois(domain).get("name_servers", [])
        qty_nameservers = len(nameservers)
        mx_servers = whois.whois(domain).get("mail_servers", [])
        qty_mx_servers = len(mx_servers)
        return qty_ip_resolved, qty_nameservers, qty_mx_servers
    except (socket.error, whois.parser.PywhoisError):
        pass
    return -1, -1, -1


def get_ttl_for_hostname(url):
    try:
        hostname = urlparse(url).netloc
        ttl_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return ttl_info[0][1]
    except socket.error:
        pass
    return -1


def has_valid_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        context.load_verify_locations(certifi.where())

        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Extract the expiration date from the certificate
        expiration_date = cert.get("notAfter")

        # Convert expiration date to a datetime object
        expiration_datetime = datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z")

        # Use UTC time for comparison
        current_datetime = datetime.utcnow()

        return 1 if expiration_datetime > current_datetime else 0
    except Exception as e:
        print(f"Error: {e}")
        pass
    return -1


def get_redirect_count(url):
    try:
        response = requests.get(url, allow_redirects=True)
        return len(response.history)
    except requests.RequestException:
        pass
    return -1


def get_google_index_info(url, parsed_url):
    try:
        service = build(
            "customsearch", "v1", developerKey="AIzaSyCwYzgryMb_tqwcJU2Z3Hj-IsfL-I9n5kU"
        )
        response = service.cse().list(q=url, cx="14eb963e0fb754b75").execute()

        items = response.get("items", [])
        url_google_index = any(item["link"] == url for item in items)
        domain_google_index = any(parsed_url.netloc in item["link"] for item in items)

        return int(url_google_index), int(domain_google_index)
    except Exception as e:
        print(f"Error: {e}")
    return -1, -1


def is_url_shortened(url):
    return (
        1 if len(url) < 54 else 0
    )  # You can adjust the threshold based on your criteria
