# Before running the code, do sudo killall tor to make sure no tor port is turned on
# Below code refers to https://stem.torproject.org/tutorials/to_russia_with_love.html
import io,os
import pycurl

import stem.process

from stem.util import term

SOCKS_PORT = 7000


def query(url):
  """
  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
  """

  output = io.BytesIO()

  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.WRITEFUNCTION, output.write)

  try:
    query.perform()
    return output.getvalue()
  except pycurl.error as exc:
    return "Unable to reach %s (%s)" % (url, exc)
  except Exception as e:
      print(e)




# Define output message for Tor
def print_bootstrap_lines(line):
  if "Bootstrapped " in line:
    print(term.format(line, term.Color.BLUE))


# Start an instance of Tor configured to only exit through Russia. This prints
# Tor's bootstrap information as it starts. Note that this likely will not
# work if you have another Tor instance running.
print(term.format("Starting Tor:\n", term.Attr.BOLD))
try: 
    tor_process = stem.process.launch_tor_with_config(
    config = {
        'SocksPort': str(SOCKS_PORT),
        'ExitNodes': '{ru}',
    },
    init_msg_handler = print_bootstrap_lines,
    )
except Exception as e:
      print(e)   

print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
print(term.format(query("http://ini741website.anishs.net:14741/flag?id=haozhan2"), term.Color.BLUE))

tor_process.kill()  # stops tor