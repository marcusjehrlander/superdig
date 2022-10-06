#!/usr/bin/python3

# Modules
import socket
import dns.resolver, dns.reversename
import sys
import json
import ipwhois
from ipwhois import IPWhois
import re


def main():
    # Searching with built in DNS-server
    resolver = dns.resolver.Resolver()
    searchobject = input('Input domain or IP-address: ')
    print('-----')
    try: 
        arecord = dns.resolver.query(searchobject, 'A')
        for rdata in arecord:
            cleanarecord = str(rdata)
    except dns.resolver.NXDOMAIN:
        print('IP-address entered, only checking WHOIS information and PTR record.')
        whoislookup = IPWhois(searchobject)
        whoislookupresults = whoislookup.lookup_rdap(depth=1)
        for results in whoislookupresults:
            asn = whoislookupresults['asn']
            asnnetwork = whoislookupresults['asn_cidr']
            asncountry = whoislookupresults['asn_country_code']
            asndescription = whoislookupresults['asn_description']
            asnregistrar = whoislookupresults['asn_registry']
        ptrrecord = dns.reversename.from_address(searchobject)
        print("ASN is:", asn)
        print("ASN network is:", asnnetwork)
        print("ASN description is:", asndescription)
        print("ASN country is:", asncountry)
        print("ASN registrar is:", asnregistrar)
        print("PTR record is:", ptrrecord)
        sys.exit()
    cnamerecord = dns.resolver.query(searchobject, 'CNAME', raise_on_no_answer=False)
    if cnamerecord.rrset is None:
        cleancnamerecord = str('None')
    else:
        for rdata in cnamerecord:
            cleancnamerecord = str(rdata)
    try: 
        nsrecord = dns.resolver.query(searchobject, 'NS')
        for rdata in nsrecord:
            cleansnsrecord = str(rdata)
    except dns.resolver.NoAnswer:
         print('None found')
    try:
        mxsrecord = dns.resolver.query(searchobject, 'MX')
        for rdata in mxsrecord: 
            cleanmxrecord = str(rdata)
    except dns.resolver.NoAnswer:
        cleanmxrecord = str('None')
    try:   
        whoislookup = IPWhois(cleanarecord)
        whoislookupresults = whoislookup.lookup_rdap(depth=1)
        for results in whoislookupresults:
            asn = whoislookupresults['asn']
            asnnetwork = whoislookupresults['asn_cidr']
            asncountry = whoislookupresults['asn_country_code']
            asndescription = whoislookupresults['asn_description']
            asnregistrar = whoislookupresults['asn_registry']
    except ipwhois.exceptions.IPDefinedError:
            asn = ('Private IP, no information availible.')
            asnnetwork = ('Private IP, no information availible.')
            asncountry = ('Private IP, no information availible.')
            asndescription = ('Private IP, no information availible.')
            asnregistrar = ('Private IP, no information availible.')
    ptrrecord = dns.reversename.from_address(cleanarecord)


    #Print stuff
    print('Information found using system DNS settings:')
    print("A record:", cleanarecord)
    print("CNAME record:", cleancnamerecord)
    #print("NS record:", cleansnsrecord)
    print("MX record:", cleanmxrecord)   
    print("ASN is:", asn)
    print("ASN network is:", asnnetwork)
    print("ASN description is:", asndescription)
    print("ASN country is:", asncountry)
    print("ASN registrar is:", asnregistrar)
    print("PTR record is:", ptrrecord)

    internaldomain = re.compile('.domain.com')
    if internaldomain.search(searchobject):
        print('Internal domain, ending script.')
        sys.exit()

    # Change to Google DNS
    print('-----')
    print('Verifying with Google DNS servers.')
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = ['8.8.8.8']

    try: 
        arecord = dns.resolver.query(searchobject, 'A')
        for rdata in arecord:
            cleanarecord2 = str(rdata)
    except dns.resolver.NXDOMAIN:
        print('IP-address entered, only checking WHOIS information.')
        whoislookup = IPWhois(searchobject)
        whoislookupresults2 = whoislookup.lookup_rdap(depth=1)
        for results in whoislookupresults2:
            asn2 = whoislookupresults2['asn']
            asnnetwork2 = whoislookupresults2['asn_cidr']
            asncountry2 = whoislookupresults2['asn_country_code']
            asndescription2 = whoislookupresults2['asn_description']
            asnregistrar2 = whoislookupresults2['asn_registry']
        print("ASN is:", asn2)
        print("ASN network is:", asnnetwork2)
        print("ASN description is:", asndescription2)
        print("ASN country is:", asncountry2)
        print("ASN registrar is:", asnregistrar2)
        sys.exit()
    cnamerecord = dns.resolver.query(searchobject, 'CNAME', raise_on_no_answer=False)
    if cnamerecord.rrset is None:
        cleancnamerecord2 = str('None')
    else:
        for rdata in cnamerecord:
            cleancnamerecord2 = str(rdata)
    try: 
        nsrecord = dns.resolver.query(searchobject, 'NS')
        for rdata in nsrecord:
            cleansnsrecord2 = str(rdata)
    except dns.resolver.NoAnswer:
        print('None found.')
    mxsrecord = dns.resolver.query(searchobject, 'MX')
    for rdata in mxsrecord: 
        cleanmxrecord2 = str(rdata)  
    ptrrecord = dns.reversename.from_address(cleanarecord2)
    whoislookup = IPWhois(cleanarecord2)
    whoislookupresults2 = whoislookup.lookup_rdap(depth=1)
    for results in whoislookupresults2:
        asn2 = whoislookupresults2['asn']
        asnnetwork2 = whoislookupresults2['asn_cidr']
        asncountry2 = whoislookupresults2['asn_country_code']
        asndescription2 = whoislookupresults2['asn_description']
        asnregistrar2 = whoislookupresults2['asn_registry']

    if cleanarecord == cleanarecord2 and cleancnamerecord == cleancnamerecord2 and cleansnsrecord == cleansnsrecord2 and cleanmxrecord == cleanmxrecord2:
        print('!!! Everything matches !!!')
        sys.exit()

    print("A record:", cleanarecord2)
    print("CNAME record:", cleancnamerecord2)
    print("NS record:", cleansnsrecord2)
    print("MX record:", cleanmxrecord2)   
    print("ASN is:", asn2)
    print("ASN network is:", asnnetwork2)
    print("ASN description is:", asndescription2)
    print("ASN country is:", asncountry2)
    print("ASN registrar is:", asnregistrar2)
    print("PTR record is:", ptrrecord)

    sys.exit()

if __name__ == '__main__':
    main()
