# Below code refers to https://stem.torproject.org/tutorials/to_russia_with_love.html
import io
import pycurl
from stem.control import Controller
import stem.process
from stem import CircStatus
import datetime
from stem.util import term

SOCKS_PORT = 9050


def query(url):
  """
  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
  """
  # Setup query session with proxy settings and 20s timeout
  output = io.BytesIO()
  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.CONNECTTIMEOUT, 30)
  query.setopt(pycurl.WRITEFUNCTION, output.write)

  try:
    query.perform()
    return output.getvalue()
  except pycurl.error as exc:
    return "Unable to reach %s (%s)" % (url, exc)

# Define output message for Tor
def print_bootstrap_lines(line):
  if "Bootstrapped " in line:
    print(term.format(line, term.Color.BLUE))


#Run tor instance with respect to an exit node specified by input country
# The function first launch tor with certain configurations
# Then, it will query target website, if the tor cannot be complete or we cannot reach target website 
# due to the exit node, an exception will be raised and the function will return
# if we can query successfully, then record the exit node and request time
def tor(country):
    print(term.format("Starting Tor:\n", term.Attr.BOLD))
    try:      
        tor_process = stem.process.launch_tor_with_config(
        config = {
            'SocksPort': str(SOCKS_PORT),
            'ExitNodes': '{' + country + '}',
            'ControlPort': '9051',
        },
        init_msg_handler = print_bootstrap_lines,
        timeout = 10,
        take_ownership = True #Terminate all tor process after the completion of this py program
        )
     
        print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
        print(term.format(query("http://ini741website.anishs.net:14741/flag?id=haozhan2"), term.Color.BLUE))
        # Using a website to know the ip of exit node
        fetch_content = query("https://ipecho.net/").decode("utf-8")
        # Filter out the IP address of the exit node from a html page
        exit_node = (fetch_content.split("<h1>Your IP is ")[-1]).split("</h1")[0]
 
        time = datetime.datetime.now()
        
        info = []
        info.append(country)
        info.append(exit_node)
        info.append(str(time))
        bypass_country_list.append(info)
    except Exception as e:
        print("Failed",e)
        return
    

    tor_process.kill()  # stops tor

if __name__ == "__main__":
    #country_list = ['RU', 'CC', 'CH', 'CL','SX', 'SC', 'SY', 'TC', 'TD', 'TG', 'TH', 'CA','FR']
    country_list = ['RU', 'CH', 'SC', 'CA','FR','SX', 'SY']
    bypass_country_list = []
  
    # Select country from country_list as exit nodes and then run tor  
    for country in country_list:
        tor(country)
    
    # Print out the successful bypass country list and their IP, time
    for entry in bypass_country_list:
        print(entry)
    