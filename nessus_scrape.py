"""
Scrape an HTML Nessus results file for host information

pre-alpha
"""

from bs4 import BeautifulSoup

# TODO: Don't hard code, only temporary for testing
htmldoc = "results_file_goes_here.html"

# List to store BeautifulSoup objects
host_results = []


def parse(fname):
    """
    Parse the file for host results.  Create BeautifulSoup objects out of hosts 
    and store them in a list. Nessus can create huge HTML files which choke bs4, 
    so this function creates small snippets of soup rather than one large one.
    """
    entry_point = 'Host Information</h2>'  # Marks to beginning of a result
    exit_point = '</table>'                # Marks the end of a result
    append_flag = False                    # Append strings between entry/exit

    with open(fname) as fp:
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
    return


def create_soup(text):
    return [BeautifulSoup(host, 'lxml') for host in host_results]


def hosts_from_soup(soup_list):
    hosts = []
    for soup in soup_list:
        host = []
        for text in soup.find_all('span'):
            host.append(text.get_text())
        hosts.append(host)
    return hosts


def main():
    print('Running...')
    parse(htmldoc)
    print('Found {} hosts!  Working...'.format(len(host_results)))

    for host in hosts_from_soup(create_soup(host_results)):
        print(host)

    print('Done!\n')
    return

if __name__ == '__main__':
    main()
