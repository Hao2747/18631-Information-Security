# Below code refers to https://stem.torproject.org/tutorials/to_russia_with_love.html
import io
import pycurl
from stem.control import Controller
import stem.process
from stem import CircStatus
import datetime
from stem.util import term
import pycountry

SOCKS_PORT = 9050


def query(url):
  """
  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
  """
  # Setup query session with 
  output = io.BytesIO()
  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.CONNECTTIMEOUT, 20)
  query.setopt(pycurl.WRITEFUNCTION, output.write)

  try:
    query.perform()
    return output.getvalue()
  except pycurl.error as exc:
    return "Unable to reach %s (%s)" % (url, exc)


# Start an instance of Tor configured to only exit through Russia. This prints
# Tor's bootstrap information as it starts. Note that this likely will not
# work if you have another Tor instance running.

def print_bootstrap_lines(line):
  if "Bootstrapped " in line:
    print(term.format(line, term.Color.BLUE))



def tor(country):
    print(term.format("Starting Tor:\n", term.Attr.BOLD))
    try:
        
        tor_process = stem.process.launch_tor_with_config(
        config = {
            'SocksPort': str(SOCKS_PORT),
            'ExitNodes': '{' + country + '}',
            'ControlPort': '9051',
            #'ExitNodes': '{RU},"fr", "de", "ca", "nl" ',
        },
        init_msg_handler = print_bootstrap_lines,
        timeout = 10,
        take_ownership = True
        )
     
        print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
        print(term.format(query("http://ini741website.anishs.net:14741/flag?id=haozhan2"), term.Color.BLUE))
        exit_nodes = []
        with Controller.from_port() as controller:
            controller.authenticate()
            #print(sorted(controller.get_circuits()))
            # Refer to code at https://stem.torproject.org/tutorials/examples/exit_used.html 
            # and https://stem.torproject.org/tutorials/examples/list_circuits.html on Jan 22, 2021
            # circ refers to circuit
            for circ in sorted(controller.get_circuits()):
                if circ.status != CircStatus.BUILT:
                    continue

                

                # For each circuit, loop through each relay
             
                
                relay = controller.get_network_status(circ.path[-1][0]) #relay_tuple[0] takes fingerprint
                #print(relay)

                if (relay.address not in exit_nodes):
                    exit_nodes.append(relay.address)
            time = datetime.datetime.now()
            
            info = []
            info.append(country)
            info.append(exit_nodes)
            info.append(str(time))
            bypass_country_list.append(info)
    except Exception as e:
        print("Failed",e)
        return
    

    tor_process.kill()  # stops tor

if __name__ == "__main__":
    country_list = ['RU', 'CC', 'CH', 'CL','SX', 'SC', 'SY', 'TC', 'TD', 'TG', 'TH', 'CA','FR']
    bypass_country_list = []
    # for country in pycountry.countries:
    #     country_list.append(country.alpha_2)
    # print(country_list)
    
    
    for country in country_list:
        tor(country)
    for entry in bypass_country_list:
        print(entry)
    