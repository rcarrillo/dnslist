#!/usr/bin/env python3

"""
Check if set of IPs is listed on a set of DNS-based blacklists (or whitelists)

This program is intended to be used in batch queries rather than a single IP
or a single DNS-based list. Nevertheless, it can be used to make individual
queries.

See RFC5782 for details on DNSxL implementation
"""

import logging
import subprocess

def dig(name, query_type='A'):
    """
    Execute the dig command
    """
    while True:
        try:
            import subprocess
            r = subprocess.check_output(['/usr/bin/dig', '-t', query_type, name, '+short'])
            return r.decode('utf-8').strip()
        except subprocess.CalledProcessError:
            # Keep running dig until success
            print('Dig failed', name)
            pass

def is_listed(ip, dnslist, query_txt=True):
    """
    Check if an IP is listed on a DNSxL, if it's listed optionally query the
    reason
    """

    # DNSBL zone have a A record containing usually the value 127.0.0.2, but
    # maybe another, alse they should have a TXT record describing the reason
    # of the listing

    # There are three common methods of representing a DNSxL with multiple
    # sublists: subdomains, multiple A records, and bit-encoded entries.
    # DNSxLs with sublists SHOULD use both subdomains and one of the other
    # methods.

    name = '%s.%s' % ('.'.join(reversed(str(ip).split('.'))), dnslist)

    a_record = dig(name)
    if a_record:
        return (a_record, dig(name, 'TXT') if query_txt else '')
    else:
        return False


def check_lists(lists):
    """
    Return a list of valid DNS lists from the configuration file
    """

    # IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing
    # purposes.  IPv4-based DNSxLs MUST NOT contain an entry for 127.0.0.1.

    return [l for l in lists if is_listed('127.0.0.2', l, query_txt=False)]

import ipaddress
import threading
import queue

def worker(q, space, dnslist):
    """
    Check if every IP from the queue is on the DNSxL, if so, log it
    """

    # Finish if there are no more IPs
    while not q.empty():
        ip = q.get()
        r = is_listed(ip, dnslist)
        if r != False:
            # Message was already passed as the format of the logging configuration
            logging.warning('', extra={
                                       'space': space,
                                       'list': dnslist,
                                       'ip': ip,
                                       'a': r[0].replace('\n', ','),
                                       'txt': r[1].replace('\n', ' - ').replace('"', ''),
                                      })
            print('LISTED', dnslist, ip, r[0], r[1].replace('\n', ' - ').replace('"', ''))
        else:
            print('OK', dnslist, ip)


if __name__ == '__main__':
    import argparse

    # Check if format argument uses invalid keywords
    def fmt(s):
        import string
        FMT_KEYS = ('ip', 'list', 'space', 'a', 'txt')
        for t in string.Formatter().parse(s):
            if t[1] is not None and t[1] not in FMT_KEYS:
                raise argparse.ArgumentTypeError(
                    '"%s" is an invalid format keyword. Must be %s' % (t[1], ', '.join(FMT_KEYS))
                )

        return s

    parser = argparse.ArgumentParser()
    parser.add_argument('ip_file', help='File containing a list of IPv4 networks')
    parser.add_argument('space', help='Name used in the log file')
    parser.add_argument('-c', '--config-file', metavar='CONFIGFILE', default='dnslist.conf',
                        help='Specify a configuration file. Default: dnslist.conf')
    parser.add_argument('-k', '--not-check-list', action='store_true',
                        help='Check if the configured DNSxLs are active')
    parser.add_argument('-o', '--log-file', metavar='LOGFILE', default='dnslist.log',
                        help='Specify a configuration file. Default: dnslist.log')
    parser.add_argument('-f', '--format', metavar='FORMAT', type=fmt, default='{ip} is listed on {list}: a={a} txt="{txt}"',
                        help='Specify the output format for listed IPs. The\
                               available variables are {ip}: the listed IP, {list}:\
                               The list the IP is listed on, {a}: The answer for the\
                               DNS A query from the list. {txt}: The answer for the\
                               DNS TXT query from the list.')
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log_file,
        format=args.format,
        style='{',
        level=logging.WARNING,
    )

    lists = open(args.config_file).read().split()

    if not args.not_check_list:
        print('Checking DNSxLs...')
        lists = check_lists(lists)
        for l in lists:
            print('[+]', l)

    threads = []

    for l in lists:
        q = queue.Queue()

        for network in open(args.ip_file):
            for ip in ipaddress.ip_network(network.strip()):
                q.put(ip)

        # One thread for each DNSxL, there will not be parallel queries for
        # the same DNSxL
        t = threading.Thread(target=worker, args=(q, args.space, l))
        t.start()
        threads.append(t)

    # Wait for all requests for this IP to be finished, otherwise
    # the service will flag it like a DoS attack and it won't respond
    for t in threads:
        t.join()
