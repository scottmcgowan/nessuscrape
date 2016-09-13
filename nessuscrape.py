"""
Scrape a Nessus HTML scan report file for host information
Alpha release - probably safe to use, but not necessarily useful.
Author: Scott McGowan
"""

from bs4 import BeautifulSoup
from os import listdir
import os.path
from time import strftime
import csv


def make_soup(fname):
    """
    Choose how to parse the file for host results, and then call 
    make_vuln_soup() or make_exec_soup() appropriately.
    """
    with open(fname) as fp:

        # TODO: Move this validation to identify_file()... or maybe not?
        first_line = fp.readline().strip()
        if 'Nessus Scan Report' not in first_line:
            print('Not a well-formed Nessus exported HTML file... Aborting\n')
            return None

        switch = {0:make_exec_soup, 1:make_vuln_soup}
        args = identify_file(fp)
        return switch[args[0]](args)
    return


def make_vuln_soup(arg):
    """
    If the file is a Vulnerability Scan, scrape the results section for each
    host.  Create BeautifulSoup objects out of hosts and store them in a list. 
    Nessus can create huge HTML files which choke bs4, so this function creates
    small snippets of soup rather than one large one.
    """
    fp = arg[1]                            # File pointer
    entry_point = 'Host Information</h2>'  # The beginning of a host, exclusive
    exit_point = '</table>'                # The end of a host, inclusive
    append_flag = False                    # Append strings between entry/exit
    results = []                           # List of BeautifulSoup objects

    temp = []
    for line in fp:
        if append_flag:
            temp.append(line)
            if exit_point in line:
                # print('Found host exit point!')
                results.append(''.join(temp).strip())
                append_flag = False
                temp = []

        if entry_point in line:
            # print('Found host entry point!')
            append_flag = True

    return host_results([BeautifulSoup(host, 'lxml') for host in results])


def make_exec_soup(arg):
    """
    If the file is an Executive Summary, scrape the table of contents for hosts
    """
    soup = arg[2]  # The table of contents pass from identify_file()

    # Find all link text from the toc, skip first element (the title)
    return [[host.get_text()] for host in soup.find_all('a')[1:]]


def identify_file(fp):
    """
    Takes a file pointer to a Nessus scan and determines the type of file, 
    Vulnerability Scan or Executive Summary, based on the file's table of 
    contents (toc)
    Returns: tuple(file type, file pointer, optional: toc)
    """
    toc = []
    append_flag = False

    for line in fp:
        if '<h1 xmlns=""' in line:
            break
        if append_flag:
            toc.append(line)
        if 'Table Of Contents' in line:
            append_flag = True
    soup = BeautifulSoup(''.join(toc), 'lxml')
    if soup.find('a').get_text() == 'Hosts Summary (Executive)':
        print('Executive Summary detected\n')
        return (0, fp, soup)
    elif soup.find('a').get_text() == 'Vulnerabilities By Host':
        print('Vulnerability Scan detected\n')
        return (1, fp)
    else:
        print('Unidentified scan, may be malformed\n')
        return (1, fp)  # TODO


def host_results(hosts):
    """
    Create a formatted list of lists from the host information in order to prep
    it for writing as csv.  If a certain value is missing for a host, fill it
    in with 'N/A'
    """
    results = []
    selections = ['DNS Name:', 'IP:']
    list_of_dicts = data_from_soup(hosts)

    # If any of the dictionaries contain an 'OS:' key, add it to selections
    for host_dict in list_of_dicts:
        if 'OS:' in host_dict.keys():
            selections.append('OS:')
            break  # Exit loop as soon as it's found, no need to keep going
    
    for host_dict in list_of_dicts:
        host = []
        for key in selections:
            host.append(host_dict.get(key, 'N/A'))
        results.append(host)
    return results


def data_from_soup(soup_list):
    """
    Extract data from the soup objects into a list of dicts
    """
    hosts = []
    for soup in soup_list:
        host = {}
        spans = soup.find_all('span')
        for i in range(len(spans))[::2]:
            host[spans[i].get_text()] = spans[i+1].get_text()
        hosts.append(host)
    # for host in hosts:
    #     print(host)
    return hosts


def write_csv(hosts, fname=None):
    """
    Write a list of lists to .csv file
    """
    if not fname:
        fname = 'Nessus_IP_Inventory_{}.csv'.format(strftime('%Y-%m-%d_%H.%M.%S'))
    fname = os.path.join('results', fname)
    os.makedirs(os.path.dirname(fname), exist_ok=True)
    with open(fname, 'w', newline='') as csvfile:
        host_file = csv.writer(csvfile)
        for host in hosts:
            host_file.writerow(host)
    return


def main():
    print('Running...\n')

    # get .html files from working dir
    files = [f for f in listdir() if os.path.isfile(f) and f.endswith('.html')]

    if not files:
        print('No HTML files found in working dir, exiting.\n')
        return

    fname = files[0]

    if len(files) > 1:
        print('Multiple HTML files found in working dir:\n')

        # CLI selection loop
        while True:
            for i, f in enumerate(files):
                print('  {} - {}'.format(i + 1, f))  # convert to 1-based index

            try:
                selection = int(input('\nEnter number of file to parse (0 to exit): '))
                print()
                if selection == 0:                   # exit condition
                    return
                elif 1 <= selection <= len(files):   # valid range
                    fname = files[selection - 1]     # convert to 1-based index
                    break
                else:                                # invalid range
                    print('Out of bounds entry, try again.\n')
                    continue
            except ValueError:                       # int cast failed
                print('\nNon-numeric entry, try again.\n')
                continue

    hosts = make_soup(fname)

    # Abort condition, hosts is falsey
    if not hosts:
        print('No hosts found! Exiting...\n')
        return

    print('Parsing file "{}" found {} hosts...\n'.format(fname, len(hosts)))

    write_csv(hosts)

    # just for testing
    # for i, host in enumerate(hosts):
    #     print(i, host)

    return

if __name__ == '__main__':
    main()
    print('Done!\n')
