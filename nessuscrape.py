"""
Scrape a Nessus HTML scan report file for host information

Alpha release, don't bother.

Author: Scott McGowan
"""

from bs4 import BeautifulSoup
from os import listdir
from os.path import isfile
from time import strftime
import csv


def make_soup(fname):
    """
    Parse the file for host results.  Create BeautifulSoup objects out of hosts
    and store them in a list. Nessus can create huge HTML files which choke bs4,
    so this function creates small snippets of soup rather than one large one.
    """
    entry_point = 'Host Information</h2>'  # The beginning of a host, exclusive
    exit_point = '</table>'                # The end of a host, inclusive
    append_flag = False                    # Append strings between entry/exit
    host_results = []                      # List of BeautifulSoup objects

    with open(fname) as fp:
        first_line = fp.readline().strip()
        if 'Nessus Scan Report' not in first_line:
            print('\nNot a well-formed Nessus exported HTML file... Aborting')
            return host_results
        temp = []
        for line in fp:
            if append_flag:
                temp.append(line)
                if exit_point in line:
                    # print('Found host exit point!')
                    host_results.append(''.join(temp).strip())
                    append_flag = False
                    temp = []

            if entry_point in line:
                # print('Found host entry point!')
                append_flag = True

    return [BeautifulSoup(host, 'lxml') for host in host_results]


def data_from_soup(soup_list):
    """
    Extract data from the soup objects into a list of lists
    """
    hosts = []
    for soup in soup_list:
        host = []
        for text in soup.find_all('span'):
            host.append(text.get_text())
        hosts.append(host)
    return hosts


def write_csv(hosts, fname=None):
    if not fname:
        fname = 'Nessus_IP_Inventory_{}.csv'.format(strftime('%Y-%M-%d_%H.%M.%S'))
    with open(fname, 'w', newline='') as csvfile:
        host_file = csv.writer(csvfile)
        for host in hosts:
            host_file.writerow(host)
    return


def main():
    print('Running...\n')

    # get .html files from working dir
    files = [f for f in listdir() if isfile(f) and f.endswith(".html")]

    if files:
        fname = files[0]

        if len(files) > 1:
            print("Multiple HTML files found in working dir:\n")

            while True:
                for i, f in enumerate(files):
                    print(i + 1, f)                   # convert to 1-based index

                try:
                    selection = int(input("\nEnter number of file to parse: "))
                    if 1 <= selection <= len(files):  # valid range
                        fname = files[selection - 1]  # convert to 1-based index
                        break
                    else:                             # invalid range
                        print("\nOut of bounds entry, try again.\n")
                        continue
                except ValueError:                    # int cast failed
                    print("\nNonnumeric entry, try again.\n")
                    continue

        hosts = make_soup(fname)

        print('\nParsing file "{}" found {} hosts...\n'.format(fname, len(hosts)))

        host_results = data_from_soup(hosts)

        # TODO: Selecting data needs to be parameterized and much more robust
        for host in host_results:
            host[:] = host[3::2]  # Selecting what data to keep

        write_csv(host_results)

        # just for testing
        # for i, host in enumerate(host_results):
        #     print(i, host)

    else:
        print("No HTML files found in working dir, exiting.\n")

    print('Done!\n')
    return

if __name__ == '__main__':
    main()
