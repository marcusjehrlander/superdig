#!/usr/bin/python3

# Modules
import socket
import dns.resolver, dns.reversename
import sys
import json
import ipwhois
from ipwhois import IPWhois
import re
import os

def check_ping(pingtarget):
    hostname = pingtarget
    response = os.system("ping -c 1 -w 1 " + hostname)
    if response == 0:
        pingtargetstatus = "IP-address is reachable"
    else:
        pingtargetstatus = "IP address is not reachable"
    

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
        try:
            whoislookup = IPWhois(searchobject)
            whoislookupresults = whoislookup.lookup_rdap(depth=1)
            for results in whoislookupresults:
                asn = whoislookupresults['asn']
                asnnetwork = whoislookupresults['asn_cidr']
                asncountry = whoislookupresults['asn_country_code']
                asndescription = whoislookupresults['asn_description']
                asnregistrar = whoislookupresults['asn_registry']
                try:
                    checkptrrecord = dns.reversename.from_address(searchobject)
                    cleanptrrecord = resolver.query(checkptrrecord,"PTR")[0]
                except dns.resolver.NXDOMAIN:
                     cleanptrrecord = ("None found")
            print('IP-address entered or invalid host entered, only checking WHOIS information and PTR record.')
            print("ASN is:", asn)
            print("ASN network is:", asnnetwork)
            print("ASN description is:", asndescription)
            print("ASN country is:", asncountry)
            print("ASN registrar is:", asnregistrar)
            print("PTR record is:", cleanptrrecord)
            sys.exit()
        except ValueError:
            print('Nothing found.')
            sys.exit()
        except ipwhois.exceptions.IPDefinedError:
            asn = ('Private IP, no information availible.')
            asnnetwork = ('Private IP, no information availible.')
            asncountry = ('Private IP, no information availible.')
            asndescription = ('Private IP, no information availible.')
            asnregistrar = ('Private IP, no information availible.') 
    try:
        cnamerecord = dns.resolver.query(searchobject, 'CNAME', raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        print('Searched for private or non exisisting IP-address, checking PTR-record.')
        try:
            checkptrrecord = dns.reversename.from_address(searchobject)
            cleanptrrecord = resolver.query(checkptrrecord,"PTR")[0]
        except dns.resolver.NXDOMAIN:
            cleanptrrecord = ("None found")
        print("PTR record is:", cleanptrrecord)
        sys.exit()
    if cnamerecord.rrset is None:
        cleancnamerecord = str('None found')
    else:
        for rdata in cnamerecord:
            cleancnamerecord = str(rdata)
    try: 
        nsrecord = dns.resolver.query(searchobject, 'NS')
        for rdata in nsrecord:
            cleansnsrecord = str(rdata)
    except dns.resolver.NoAnswer:
         cleansnsrecord = str('None found')
    try:
        mxsrecord = dns.resolver.query(searchobject, 'MX')
        for rdata in mxsrecord: 
            cleanmxrecord = str(rdata)
    except dns.resolver.NoAnswer:
        cleanmxrecord = str('None found')
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
    checkptrrecord = dns.reversename.from_address(cleanarecord)
    try:
        cleanptrrecord = resolver.query(checkptrrecord,"PTR")[0]
    except dns.resolver.NXDOMAIN:
        cleanptrrecord = ("None found")

    #Print stuff
    print('Information found using system DNS settings:')
    print("A record:", cleanarecord)
    print("CNAME record:", cleancnamerecord)
    print("NS record:", cleansnsrecord)
    print("MX record:", cleanmxrecord)   
    print("ASN is:", asn)
    print("ASN network is:", asnnetwork)
    print("ASN description is:", asndescription)
    print("ASN country is:", asncountry)
    print("ASN registrar is:", asnregistrar)
    print("PTR record is:", cleanptrrecord)

    # Send ICMP to A-record
    print('-----')
    check_ping(cleanarecord)

    # Don't check external DNS for internal domains
    internaldomain = re.compile('.domain.com')
    if internaldomain.search(searchobject):
        print("-----")
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
        cleancnamerecord2 = str('None found')
    else:
        for rdata in cnamerecord:
            cleancnamerecord2 = str(rdata)
    try: 
        nsrecord = dns.resolver.query(searchobject, 'NS')
        for rdata in nsrecord:
            cleansnsrecord2 = str(rdata)
    except dns.resolver.NoAnswer:
        cleansnsrecord2 = str('None found')
    try:
        mxsrecord = dns.resolver.query(searchobject, 'MX')
        for rdata in mxsrecord: 
            cleanmxrecord2 = str(rdata)  
    except dns.resolver.NoAnswer:
        cleanmxrecord2 = str('None found')
    checkptrrecord2 = dns.reversename.from_address(cleanarecord2)
    try:
        cleanptrrecord2 = resolver.query(checkptrrecord2,"PTR")[0]
    except dns.resolver.NXDOMAIN:
        cleanptrrecord2 = ("None found")
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
    print("PTR record is:", cleanptrrecord2)
    sys.exit()

if __name__ == '__main__':
    main()
