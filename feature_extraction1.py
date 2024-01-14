import re
from urllib.parse import urlparse
import urllib
from bs4 import BeautifulSoup
import dns.resolver
import whois
from datetime import datetime
import requests


def check_dns_records(domain):
    try:
        # Resolve any DNS records for the given domain
        result = dns.resolver.resolve(domain)

        # If there are any records, print a message
        if result:
            print(f"DNS records found for {domain}.")
            return 1
        else:
            print(f"No DNS records found for {domain}.")
            return 0
    except dns.resolver.NXDOMAIN:
        print(f"{domain} does not exist.")
        return 0
    except dns.resolver.NoAnswer:
        print(f"No DNS records found for {domain}.")
        return 0
    except dns.resolver.NoNameservers:
        print(f"No nameservers found for {domain}.")
        return 0
    except Exception as e:
        print(f"Error checking DNS records: {e}")
        return 0


shortening_services = (
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"
    r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
    r"tr\.im|link\.zip\.net"
)


def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0


def webtraffic(url):
    try:
        # Filling the whitespaces in the URL if any
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(
            urllib.request.urlopen(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + url
            ).read(),
            "xml",
        ).find("REACH")["RANK"]
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
    else:
        return 0


def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if isinstance(creation_date, str) or isinstance(expiration_date, str):
        try:
            creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None) or (creation_date is None):
        return 1
    elif (type(expiration_date) is list) or (type(creation_date) is list):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if (ageofdomain / 30) < 6:
            age = 1
        else:
            age = 0
    return age


def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if expiration_date is None:
        return 1
    elif type(expiration_date) is list:
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if (end / 30) < 6:
            end = 0
        else:
            end = 1
    return end


def Iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1


def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0


def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1


def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1


def extract_features(url):
    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    print(parsed_url.query)
    print(parsed_url.fragment)
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        response = None

    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    # Extract features using regular expressions
    have_ip = int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url)))
    have_at = int("@" in domain)
    url_length = len(url)
    url_depth = url.count("/")
    redirection = 1
    https_domain = int(parsed_url.scheme == "https")
    tiny_url = tinyURL(url)
    prefix_suffix = int(bool(re.search(r"-|_", domain)))
    dns_record = check_dns_records(domain)
    web_traffic = 1
    domain_age = domainAge(domain_name)
    domain_end = domainEnd(domain_name)
    iframe = Iframe(response)
    mouse_over = mouseOver(response)
    right_click = rightClick(response)
    web_forwards = forwarding(response)

    # Return a dictionary of extracted features
    features = {
        "Have_IP": have_ip,
        "Have_At": have_at,
        "URL_Length": url_length,
        "URL_Depth": url_depth,
        "Redirection": redirection,
        "https_Domain": https_domain,
        "TinyURL": tiny_url,
        "Prefix/Suffix": prefix_suffix,
        "DNS_Record": dns_record,
        "Web_Traffic": web_traffic,
        "Domain_Age": domain_age,
        "Domain_End": domain_end,
        "iFrame": iframe,
        "Mouse_Over": mouse_over,
        "Right_Click": right_click,
        "Web_Forwards": web_forwards,
    }

    return features
