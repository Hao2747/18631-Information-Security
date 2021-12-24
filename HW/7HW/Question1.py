
from stem import CircStatus
from stem.control import Controller

with Controller.from_port() as controller:
  controller.authenticate()
  #print(sorted(controller.get_circuits()))
  # Refer to code at https://stem.torproject.org/tutorials/examples/exit_used.html 
  # and https://stem.torproject.org/tutorials/examples/list_circuits.html on Jan 22, 2021
  # circ refers to circuit
  for circ in sorted(controller.get_circuits()):
    if circ.status != CircStatus.BUILT:
     continue

    #print("", circ.path)
    print("Circuit %s (%s)" % (circ.id, circ.purpose))

    # For each circuit, loop through each relay
    for i,relay_tuple in enumerate(circ.path):
      
      relay = controller.get_network_status(relay_tuple[0]) #relay_tuple[0] takes fingerprint
      #print(relay)
      if (i== 0):
            print("Entry Node:", end='')
      elif (i==1):
            print("Middle Node:", end='')
      elif (i==2):
          print("Exit Node:", end='')
      print("  address: %s" % relay.address, end='')
      print("  country: %s" % controller.get_info("ip-to-country/%s" % relay.address, 'unknown'), end='')
      print("  bandwidth: %s" % relay.bandwidth)
      