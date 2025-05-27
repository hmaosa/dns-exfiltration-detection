import math
from collections import defaultdict
import tldextract  # Make sure this package is installed

def shannon_entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = -sum(p * math.log2(p) for p in prob)
    return entropy

def map_dns_subdomains(domain_series):
    subdomain_map = defaultdict(set)
    for fqdn in domain_series.dropna().unique():
        extracted = tldextract.extract(fqdn)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        if extracted.subdomain:
            subdomain_map[root_domain].add(extracted.subdomain)
    return subdomain_map