import serial
import re
from datetime import datetime
import subprocess
import pprint
import requests
import json
import paho.mqtt.client as mqtt
from sty import fg, bg, ef, rs
import os
from manuf import manuf
import socket
import threading
import time

arp_cache = dict()
hosts = dict()
kill = False

show = [

]

macmanuf = manuf.MacParser()

def prettyprint_QoS(host):

  if len(host['signal']) > 120:
    s0 = host['signal'][-120:]  
  else: 
    s0 = host['signal']

  for s in s0[::-1]:
    qos = int(list(s.values())[0])
    if qos > -70:
      print('█', end='')
    elif qos > -80:
      print('▄', end='')
    elif qos > -90:
      print('_', end='')
    elif qos > -100:
      print(' ', end='')
    

  print()

def prettyprint_distance(host):

  if len(host['distance']) > 120:
    s0 = host['distance'][-120:]  
  else: 
    s0 = host['distance']

  for s in s0[::-1]:
    qos = int(list(s.values())[0])
    if qos < 15:
      print('█', end='')
    elif qos < 50:
      print('▄', end='')
    elif qos < 100:
      print('_', end='')
    else:
      print(' ', end='')
    

  print()

def prettyprint_host(event, host):
  global hosts
  colors = host['mac'].split(':')
  r = max(int(colors[3], 16), 128)
  g = max(int(colors[4], 16), 128)
  b = max(int(colors[5], 16), 128)
  print(fg(r,g,b))
  print("[{:s}] [{:s}] {:s}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), host['mac'], event))
  print("\tHost: {:s} ({:s})".format(host['hostname'], host['ip']))

  
  print("\tSSIDs: {:s}".format(" ".join(host['ssid']))) 

  print("\tBSSID: ")
  for p in host['bssid']:
    print("\t\t" + p + " [ ", end='')
    if p in known:
      print(known[p] + " ", end='')
    if p in ignore:
      print(ignore[p] + " ", end='')
    if p in hosts:
      print(hosts[p]['hostname'] + " ", end='')
    print("]")

  print("\tPeers: ")
  for p in host['peers']:
    print("\t\t" + p + " [ ", end='')
    if p in known:
      print(known[p] + " ", end='')
    if p in ignore:
      print(ignore[p] + " ", end='')
    if p in hosts:
      print(hosts[p]['hostname'] + " ", end='')
    print("]")



  print("\tSignal:   [{: 4d}] ".format(list(host['signal'][-1].values())[0]), end ='')
  prettyprint_QoS(host)
  print("\tDistance: [{: 3d}m] ".format(list(host['distance'][-1].values())[0]), end ='')
  prettyprint_distance(host)
  
  print("\tClient type: {:s}".format(host['client_type'])) 
  print("\tChannel: {:d}".format(host['channel'])) 
  print("\tFrom DS: {:d}  To DS: {:d}".format(host['from_ds'], host['to_ds'])) 
  print("\tFrame type: {:d}/{:d}".format(host['frame_type'], host['frame_subtype'])) 
  print("\tPackets seen: {:d}".format(host['packets'])) 
  print("\tLast seen: {:s}".format(host['last_seen'].replace(microsecond=0).isoformat(' ')))   
  print("\tCompany: {:s}, {:s}".format(host['vendor'], host['vendor_comment'])) 
  print()
  print(fg.rs)


def save_hosts():
  global hosts, kill
  while True:
    try:
      #print("Saving")
      if os.path.isfile("../user-data/hosts.json"):
        os.rename("../user-data/hosts.json", "../user-data/hosts.json.backup")
      with open('../user-data/hosts.json', 'w') as outfile:
        json.dump(hosts, outfile, indent=4, sort_keys=True, default=str)        
      time.sleep(300)
    except:
      kill = True

def update_arp_cache():
  global arp_cache, kill
  pattern = re.compile("(.+?)\\s([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\\s([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}).*")
  while True:
    try:
      arp = subprocess.getoutput(["arp -a | tr -d '()' | awk '{print $1, $2, $4}'"])
      arp = arp.strip()
      
      for arpline in arp.splitlines():
        match = pattern.match(arpline)
        
        
        if match:
          mac = match.group(3).strip().upper()
          arp_cache[mac] = dict()
          arp_cache[mac]['hostname'] = match.group(1).strip()
          arp_cache[mac]['ip'] = match.group(2).strip()

      with open('../user-data/arp_cache.json', 'w') as outfile:
        json.dump(arp_cache, outfile, indent=4, sort_keys=True, default=str)    

      #print("Updated arp cache")

      time.sleep(61)
    except:
      kill=True

def load_hosts():
  global hosts
  try:
    print("Loading hosts...")
    filename = "../user-data/hosts.json"
    if not os.path.isfile(filename):
      filename = "../user-data/hosts.json.backup"

    try:      
      with open(filename, 'r') as f:
        hosts = json.load(f)
    except Exception as e:
      print(e)


    done = False
    deleted = 0
    while not done:
      done = True
      for m in hosts:
        if m in ignore:
          print("Deleting ignored host: {:s}".format(m))
          del hosts[m]
          done = False
          deleted = deleted + 1
          break
      

    if deleted > 0:
      with open('../user-data/hosts.json', 'w') as outfile:
        json.dump(hosts, outfile, indent=4, sort_keys=True, default=str)
    for m in hosts:
      hosts[m]['last_seen'] = datetime.now() # TODO convert
      prettyprint_host("LOADED", hosts[m])

    print("Loaded {:d} records. Deleted {:d} records".format(len(hosts), deleted))
  except Exception as e:
    print("Failed loading hosts")

def load_arp_cache():
  global arp_cache
  try:
    with open('../user-data/arp_cache.json', 'r') as f:
      arp_cache = json.load(f)
  except:
    arp_cache = {}

def load_ignore():
  global ignore
  try:
    with open('../user-data/ignore.json', 'r') as f:
      ignore = json.load(f)
  except:
    ignore = []

def load_known():
  global known
  try:
    with open('../user-data/known.json', 'r') as f:
      known = json.load(f)
  except:
    known = {}


def arp(host):
  global arp_cache
  if host['mac'] in arp_cache:
    host['hostname'] = arp_cache[host['mac']]['hostname']
    host['ip'] = arp_cache[host['mac']]['ip']
  else:
    host['hostname'] = "Unknown"
    host['ip'] = "Unknown"
  return host

def macvendor(host):

  host['vendor'] = macmanuf.get_manuf_long(host['mac'])
  host['vendor_comment'] = macmanuf.get_comment(host['mac'])
  if host['vendor_comment'] is None:
    host['vendor_comment'] = ""
  if host['vendor'] is None:
    host['vendor'] = "Unknown"

  return host


if __name__ == "__main__":

  client = mqtt.Client("wifilistener")
  client.username_pw_set("openhab", "password")
  client.connect("openhab")
  client.loop_start()

  arp_thread = threading.Thread(target=update_arp_cache)
  

  pattern = re.compile("([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}),([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})?,([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})?,([\\sa-zA-Z0-9_-]*)?,(\\d+),(-?\\d+),(\\d+),([01]),([01]),(\\d),(\\d).*")

 #baudrate = 115200
  baudrate = 230400
 #baudrate = 1500000
  #baudrate = 930000
  ser = serial.Serial('/dev/serial/by-id/usb-1a86_USB2.0-Serial-if00-port0', baudrate)  # open serial port

  load_hosts()
  load_arp_cache()
  load_ignore()
  load_known()

  save_thread = threading.Thread(target=save_hosts)
  arp_thread.start()
  save_thread.start()


  while not kill:
  
    line = ser.readline() 
   
    try:
      line = line.decode('utf-8')
      line = line.strip()
      #print(line)
      match = pattern.match(line)
    except UnicodeDecodeError as e:
      continue
    except Exception as e:
      continue

    
  
    if match:
      mac = match.group(1)

      if "DA:A1:19:" in mac:
        print("H", end='', flush=True)
        continue

      dest_mac = match.group(2)
      bssid = match.group(3)
      ssid = match.group(4)
      channel = int(match.group(5))
      signal = int(match.group(6))
      distance = int(match.group(7))
      fromDS = int(match.group(8))
      toDS = int(match.group(9))      
      frame_type = int(match.group(10))
      frame_subtype = int(match.group(11))


      
      if dest_mac is None:
        dest_mac = ""

      if bssid is None:
        bssid = ""
      
      if ssid is None:
        ssid = ""


      client_type = ""
      peer_type = ""
      if ((fromDS == 0) and (toDS==0)):
        if (frame_type == 4):
          client_type = "Station"
          peer_type = "Station"
        else:
          client_type = "Station"
          peer_type = "AP"
      elif ((fromDS == 1) and (toDS==0)):
          client_type = "Station"
          peer_type = "AP"
      

      if bssid in hosts:
        hosts[bssid]['client_type'] = peer_type #if hosts[bssid]['client_type'] == "" else hosts[bssid]['client_type']

      if dest_mac in hosts:
        hosts[dest_mac]['client_type'] = peer_type #if hosts[dest_mac]['client_type'] == "" else hosts[dest_mac]['client_type']

      #print("peer_type: {:s}, client_type: {:s}".format(peer_type, client_type))
      if (not mac in ignore) and (len(show) == 0 or mac in show):
        
        

        if not mac in hosts: #new mac
        
          hosts[mac] = {
            'mac': mac,
            'peers': [dest_mac],
            'ssid': [ssid] if ssid != "" else [],
            'bssid': [bssid] if bssid != "" else [],
            'channel': channel, 
            'frame_type': frame_type,
            'frame_subtype': frame_subtype,
            'from_ds': fromDS,
            'to_ds': toDS,
            'signal': [{datetime.now().timestamp(): signal}],
            'distance': [{datetime.now().timestamp(): distance}],            
            'last_seen': datetime.now(),
            'packets': 1,
            'client_type': client_type
          }
          hosts[mac] = macvendor(hosts[mac])
          
          hosts[mac] = arp(hosts[mac])
          
          if mac in known.keys():
            print("K", end='', flush=True)
            client.publish("/home/presence/" + known[mac], "seen")
            hosts[mac]['last_published'] = datetime.now().timestamp()
          else:
            print("U", end='', flush=True)
            prettyprint_host("JOINED", hosts[mac])
              
        else: #existing mac
          hosts[mac]['last_seen'] = datetime.now()
          hosts[mac]['packets'] = hosts[mac]['packets'] + 1
          hosts[mac]['signal'] = hosts[mac]['signal'] + [{datetime.now().timestamp(): signal}]
          hosts[mac]['distance'] = hosts[mac]['distance'] + [{datetime.now().timestamp(): distance}]
          hosts[mac]['channel'] = channel
          hosts[mac]['dest_mac'] = dest_mac
          hosts[mac]['client_type'] = client_type if hosts[mac]['client_type'] == "" else hosts[mac]['client_type']


          if ssid not in hosts[mac]['ssid'] and ssid != "":
            hosts[mac]['ssid'] = hosts[mac]['ssid'] + [ssid]

          if bssid not in hosts[mac]['bssid'] and bssid != "":
            hosts[mac]['bssid'] = hosts[mac]['bssid'] + [bssid]
          
          if dest_mac not in hosts[mac]['peers'] and dest_mac != "":
            hosts[mac]['peers'] = hosts[mac]['peers'] + [dest_mac]

          if not 'hostname' in hosts[mac] or hosts[mac]['hostname'] == "" or hosts[mac]['hostname'] == "Unknown" or hosts[mac]['hostname'] == "Skipped":
            hosts[mac] = arp(hosts[mac])

          if mac in known.keys():
            print("K", end='', flush=True)
            if hosts[mac]['last_published'] + 60 < datetime.now().timestamp():
              hosts[mac]['last_published'] = datetime.now().timestamp()
              client.publish("/home/presence/" + known[mac], "seen")
          else:
            print()
            prettyprint_host("SEEN", hosts[mac])
      else:
        print("-", end='', flush=True)
    else:
      print("?", end='', flush=True)

  ser.close()             # close port
    
