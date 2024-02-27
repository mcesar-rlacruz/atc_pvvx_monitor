#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import numbers
import os
import sys
from   logging.handlers import RotatingFileHandler
import logging as lg
import json
import yaml
import re
import asyncio
import signal
import platform
import functools
import aiohttp
import aiomqtt
import bleak
from   Cryptodome.Cipher import AES   # pycryptodome/pycryptodomex
import struct
import ssl

async def main():
  # some constants
  # timeouts
  AIOHTTP_TIMEOUT = 10  # s
  AIOMQTT_TIMEOUT = 10  # s
  # matches the BLE Environmental Sensing service UUID
  SERVICE_UUID_RE = re.compile('(?i)^[0-9a-f]{4}181a')
  # matches one or more slashes
  SLASHES_RE = re.compile('/+')
  # default client configuration
  CLIENT_CONF = {'hostname': '127.0.0.1', 'port': None, 'user': '', 'password': '', 'encrypt': True, 'insecure': False, 'idx': None, 'topic': '', 'payloads': None}
  # default payload configuration
  PAYLOAD_CONF = {'subtopic': '', 'data': ''}
  # skeleton of Domoticz http(s) POST request data
  DOMOTICZ_HTTP_DATA = {'type': 'command', 'param': 'udevice', 'idx': None, 'nvalue': 0, 'svalue': None, 'battery': None, 'rssi': None}

  # MQTT publish to connected broker  ++++++++++++++++++++++++++++++++++++++++++
  async def publish_to_broker(broker, mac, hostname, topic, payload):
    full_topic = topic
    if payload['subtopic'] != '':
      full_topic += '/' + payload['subtopic']
    #: endif
    full_topic = re.sub(SLASHES_RE, '/', full_topic)  # just in case...
    data = payload['data']
    lg.debug(f'({mac} => {hostname}) MQTT publishment with payload "{data}" to topic "{full_topic}".')
    try:
      await broker.publish(topic = full_topic, payload = data, timeout = AIOMQTT_TIMEOUT)
    except (aiomqtt.MqttError, aiomqtt.MqttCodeError) as e:
      lg.error(f'({mac} => {hostname}) MQTT error. {e}.')
      return
    else:
      lg.debug(f'({mac} => {hostname}) Successful MQTT publishment of payload "{data}" to topic "{full_topic}".')
    #: endtry
  #: enddef --------------------------------------------------------------------
 
  # publisher ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  async def publish(mac, client, temperature, humidity, battery, rssi):
    # get configuration for client
    conf = CLIENT_CONF.copy()
    for key in client:
      # overwrite defaults only if specified fields are non-empty
      if key in conf and client[key] is not None and client[key] != '':
        conf[key] = client[key]
      else:
        lg.warning(f'({mac}) Unused/ignored field "{key}" in client configuration "{client}".')
      #: endif
    #: endfor
    hostname = conf['hostname']
    port = conf['port']
    user = conf['user']
    password = conf['password']
    encrypt = conf['encrypt']
    insecure = conf['insecure']
    idx = conf['idx']
    topic = conf['topic']
    rssi_11 = (rssi + 96) // 6
    rssi_11 = 0 if rssi_11 < 0 else rssi_11
    rssi_11 = 11 if rssi_11 > 11 else rssi_11
    # process payload templates
    payloads = None
    if conf['payloads'] is not None:
      payloads = []
      try:
        for raw_payload in conf['payloads']:
          payload = PAYLOAD_CONF.copy()
          # process template fields (subtopic/data)
          try:
            for key in raw_payload:
              if key in payload and raw_payload[key] is not None and raw_payload[key] != '':
                payload[key] = raw_payload[key]
              else:
                # reached if a field inside a payload is unknown
                lg.warning(f'({mac} => {hostname}) Unused/ignored field "{key}" in payload "{raw_payload}" for client "{hostname}" of device {mac}.')
              #: endif
            #: endfor
          except TypeError as e:
            # reached (e.g.) if a payload is non-iterable
            lg.error(f'({mac} => {hostname}) Invalid payload "{raw_payload}" for client "{hostname}" of device {mac}. {e}.')
          else:
            try:
              # instantiate payload template
              payload['data'] = payload['data']%{'temperature': temperature, 'humidity': humidity, 'battery': battery, 'rssi': rssi, 'rssi_11': rssi_11}
            except TypeError as e:
              lg.error(f'({mac} => {hostname}) Cannot insert data into payload "{payload["data"]}" for client "{hostname}" of device {mac}. {e}.')
            else:
              payloads.append(payload)
            #: endtry
          #: endtry
        #: endfor
      except TypeError as e:
        # reached (e.g.) if payloads is non-iterable
        lg.error(f'({mac} => {hostname}) Invalid "payloads" field "{conf["payloads"]}" for client "{hostname}" of device {mac}. {e}.')
        return
      #: endtry
    #: endif
    # dispatch to Domoticz or MQTT broker
    if idx is not None and payloads is None:
      # publish to domoticz ....................................................
      lg.debug(f'({mac} => {hostname}) Publishing measurements for device {mac} to Domoticz client {hostname}.')
      if port is None:
        port = 8080 if encrypt else 80
      #: endif
      # build URL
      proto = 'https' if encrypt else 'http'
      url = f'{proto}://{hostname}:{port}/json.htm'
      # build auth
      auth = None if user == '' else aiohttp.BasicAuth(user, password)
      tls = not insecure
      # build data
      data = DOMOTICZ_HTTP_DATA.copy()
      data['idx'] = idx
      data['svalue'] = f'{temperature};{humidity};-1'
      data['battery'] = battery
      data['rssi'] = rssi_11
      # publish
      lg.debug(f'({mac} => {hostname}) Launching {"encrypted" if encrypt else "unencrypted"}, {"authenticated" if auth is not None else "non-authenticated"} Domoticz API call via {"insecure" if insecure else "secure"} {proto} POST request to "{url}" with data "{data}".')
      try:
        async with http_session.post(url, data = data, auth = auth, ssl = tls) as response:
          if response.ok:
            try:
              response_json = await response.text()
              response_dict = json.loads(response_json)
              if response_dict['status'] == 'OK':
                lg.debug(f'({mac} => {hostname}) Successful Domoticz API call.')
              else:
                lg.error(f'({mac} => {hostname}) Domoticz returned error. Response is:\n{response_json}')
                return
              #: endif
            except (aiohttp.ContentTypeError, json.JSONDecodeError, TypeError) as e:
              lg.error(f'({mac} => {hostname}) Error decoding response in POST request to "{url}" with data "{data}". {e}.')
              return
            #: endtry
          else:
            lg.error(f'({mac} => {hostname}) Failed {proto} POST request. Code {response.status}, reason: "{response.reason}".')
            return
          #: endif
        #: endwith
      except TimeoutError:
        lg.error(f'({mac} => {hostname}) Connection timeout in {proto} POST request to "{url}" with data "{data}".')
        return
      except aiohttp.InvalidURL as e:
        lg.error(f'({mac} => {hostname}) Invalid URL when connecting to {url}. {e}.')
        return
      except aiohttp.ClientConnectorError as e:
        lg.error(f'({mac} => {hostname}) Connection error in {proto} POST request to "{url}" with data "{data}". {e}.')
        return
      except aiohttp.ServerDisconnectedError as e:
        lg.error(f'({mac} => {hostname}) Server disconnected in {proto} POST request to "{url}" with data "{data}" (invalid certificate?). {e}.')
        return
      #: endtry
    elif idx is None and payloads is not None:
      # publish to MQTT ........................................................
      if len(payloads) == 0:
        lg.error(f'({mac} => {hostname}) No valid payloads in configuration "{conf["payloads"]}" for MQTT broker {hostname} of device {mac}.')
        return
      #: endif
      lg.debug(f'({mac} => {hostname}) Publishing measurements for device {mac} to MQTT broker {hostname}.')
      if port is None:
        port = 8883 if encrypt else 1883
      #: endif
      # publish
      try:
        ssl_context = None
        if encrypt:
          ssl_context = ssl.create_default_context(purpose = ssl.Purpose.SERVER_AUTH)
        else:
          insecure = None
        #: endif
        lg.debug(f'({mac} => {hostname}) Connecting ({"with" if encrypt else "without"} encryption, {"insecure, " if encrypt and insecure else ""}{"with" if user != "" else "without"} authentication) to MQTT broker "{hostname}:{port}".')
        async with aiomqtt.Client(
          hostname = hostname,
          username = user,
          password = password,
          port = port,
          tls_context = ssl_context,
          tls_insecure = insecure,
          timeout = AIOMQTT_TIMEOUT
        ) as broker:
          async with asyncio.TaskGroup() as tg:
            for payload in payloads:
              tg.create_task(publish_to_broker(broker, mac, hostname, topic, payload))
            #: endfor
          #: endwith
        #: endwith
      except (aiomqtt.MqttError, aiomqtt.MqttCodeError) as e:
        lg.error(f'({mac} => {hostname}) MQTT error. {e}.')
        return
      else:
        lg.debug(f'({mac} => {hostname}) Done with MQTT broker.')
      #: endtry
    elif idx is not None and payloads is not None:
      lg.error(f'Bad publish configuration for device {mac}, both "idx" (Domoticz) and "payloads" (MQTT) fields specified for client ({hostname}).')
      return
    else:
      lg.error(f'Bad publish configuration for device {mac}, neither "idx" (Domoticz) nor "payloads" (MQTT) fields specified for client ({hostname}).')
      return
    #: endif
  #: endef ---------------------------------------------------------------------

  # processor for each received BLE advertisement ++++++++++++++++++++++++++++++
  async def detection_callback(device, advertisement_data):
    mac = device.address.replace(':', '').upper()
    lg.debug(f'Detected BLE device {mac}.')
    if mac in macs:   # want to monitor this sensor?
      rssi = advertisement_data.rssi
      lg.debug(f'  Monitored. RSSI = {rssi} dBm.')
      for uuid, data in advertisement_data.service_data.items():
        if re.match(SERVICE_UUID_RE, uuid): # service is "Environmental Sensing service"?
          data_len = len(data)
          lg.debug(f'  Data length = {data_len}. Data = "{data}".')
          match data_len: # identify advertisement format from data length
            case 8 | 11:  # encrypted ATC1441 (8) and PVVX (11) advertisement formats
              lg.debug(f'  Encrypted {"atc1441" if data_len == 8 else "pvvx"} format.')
              if 'key' in devices[mac]:  # need a key to decrypt encrypted formats
                key = bytes.fromhex(devices[mac]['key'])
                nonce = bytes.fromhex(mac)[::-1]
                nonce += bytes.fromhex('0b161a18' if len(data) == 8 else '0e161a18')
                nonce += data[0:1]
                cipherpayload = data[1:-4]
                token = data[-4:]
                lg.debug(f'  nonce = {nonce}, token = {token}.')
                lg.debug(f'  cipherpayload = {cipherpayload}.')
                cipher = AES.new(key, AES.MODE_CCM, nonce = nonce, mac_len = 4)
                cipher.update(b"\x11")
                decrypted_data = ''
                try:
                  decrypted_data = cipher.decrypt_and_verify(cipherpayload, token)
                except ValueError as error:
                  lg.error(f'Error decrypting data from device {device.address} (invalid key?).')
                  return
                #: endtry
              else:
                lg.warning(f'Decryption key for device {device.address} not provided.')
                return
              #: endif
              decrypted_data_len = len(decrypted_data)
              lg.debug(f'  decrypted_data length = {decrypted_data_len}, decrypted_data = {decrypted_data}.')
              if decrypted_data_len == 3:     # get T/H/B values for ATC1441 format (3 bytes)
                lg.debug('  Extracting data from atc1441 encrypted format.')
                temp, humidity, battery_lvl = struct.unpack('BBB', decrypted_data)
                temp = temp/2 - 40
                humidity /= 2
                battery_lvl &= 0x7F
              elif decrypted_data_len == 6:   # get T/H/B values for PVVX format (6 bytes)
                lg.debug('  Extracting data from pvvx encrypted format.')
                temp, humidity, battery_lvl, trg = struct.unpack("<hHBB", decrypted_data)
                temp /= 100
                humidity /= 100
              else:
                lg.debug('  Invalid decrypted_data len.')
                return
              #: endif
            case 13:    # atc1441 advertisement format
              lg.debug('  atc1441 format. Extracting data.')
              mac_rx, temp, humidity, battery_lvl, battery_mv, count = struct.unpack('>6shBBHB', data)
              temp /= 10
            case 15:    # pvvx advertisement format
              lg.debug('  pvvx format. Extracting data.')
              mac_rx, temp, humidity, battery_mv, battery_lvl, count, flags = struct.unpack('<6shHHBBB', data)
              temp /= 100
              humidity /= 100
            case _:
              lg.error(f'  Unknown advertisement format for device {device.address}.')
              lg.error(f'    len(data) = {len(data)}; data = "{data}".')
              return
          #: endmatch
          battery_lvl = 100 if battery_lvl > 100 else battery_lvl
          if 'batt_soc' in devices[mac] and devices[mac]['batt_soc']:
            battery = round(100 * pow(battery_lvl / 100, 3))
          else:
            battery = battery_lvl
          #: endif
          if 'name' in devices[mac]:
            lg.log(meas_log_lvl, f'{device.address}[{devices[mac]["name"]}]: T = {temp} ºC, H = {humidity} %, batt = {battery} %, rssi = {rssi} dBm.')
          else:
            lg.log(meas_log_lvl, f'{device.address}: T = {temp} ºC, H = {humidity} %, batt = {battery} %, rssi = {rssi} dBm.')
          #: endif
          # publish
          if 'clients' in devices[mac]:
            async with asyncio.TaskGroup() as tg:
              for client in devices[mac]['clients']:
                tg.create_task(publish(mac, client, temp, humidity, battery, rssi))
              #: endfor
            #: endwith
          else:
            lg.warning(f'Device {mac} has no "clients" section specified, not publishing its measurements.')
          #: endif
        #: endif
      #: endfor
    #: endif
  #: enddef --------------------------------------------------------------------

  # process command line arguments  ++++++++++++++++++++++++++++++++++++++++++++
  arg_parser = argparse.ArgumentParser(description = 'Monitor atc1441/pvvx BLE thermometers.')
  arg_parser.add_argument('-c', '--config-file', action = 'store', 
    default = 'thermometers.yaml',
    help = 'file describing the thermometers to monitor and where to send (Domoticz/MQTT) their measurements. Defaults to "thermometers.yaml".',
    dest = 'config_file_name')
  arg_parser.add_argument('-a', '--adapter', action = 'store',
    default = None,
    help = 'Bluetooth HCI adapter to use (hci0, hci1, ...). Used only in Linux/BlueZ. If not specified, uses system default.',
    dest = 'adapter')
  arg_parser.add_argument('-s', '--scan_time', action = 'store',
    default = 10, type = float,
    help = 'BLE scan time (in s). Defaults to 10. A <= 0 number is treated as "scan with no pauses".',
   dest = 'scan_time')
  arg_parser.add_argument('-p', '--scan-pause', action = 'store',
    default = 50, type = float,
    help = 'pause time between scans (in s). Defaults to 50. Ignored if SCAN_TIME <= 0.',
    dest = 'scan_pause')
  arg_parser.add_argument('-l', '--log-file', action = 'store', 
    default = None,
    help = 'file where to write log messages. If not set, outputs messages to standard error.',
    dest = 'log_file_name')
  arg_parser.add_argument('-m', '--measurements_as_info', action = 'store_true', 
    help = 'log measurements as INFO, instead of as DEBUG.',
    dest = 'log_measurements_as_info')
  arg_parser.add_argument('--log-level', action = 'store', 
    default = 'INFO',
    choices = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    help = 'set log level. Defaults to "INFO".',
    dest = 'log_level')
  arg_parser.add_argument('-t', '--timestamp', action = 'store_true', 
    help = 'include timestamps into log messages.',
    dest = 'log_timestamp')
  arg_parser.add_argument('-d', '--date', action = 'store_true', 
    help = 'include date into timestamps.',
    dest = 'log_date')
  
  args = arg_parser.parse_args()
  config_file_name = args.config_file_name
  adapter = args.adapter
  scan_time = args.scan_time
  scan_pause = args.scan_pause
  log_file_name = args.log_file_name
  log_level = getattr(lg, args.log_level)
  log_measurements_as_info = args.log_measurements_as_info
  log_date = args.log_date
  log_timestamp = args.log_timestamp  # ----------------------------------------

  # configure logging ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  lg.basicConfig(
    # handlers = [RotatingFileHandler(log_file_name, maxBytes = 1000000, backupCount = 5)],
    handlers = [lg.StreamHandler()] if log_file_name is None else [RotatingFileHandler(log_file_name, maxBytes = 1000000, backupCount = 5)],
    encoding = 'utf-8',
    style = '%',
    format = ('%(asctime)s.%(msecs)03d - ' if log_timestamp else '') + '%(levelname)s: %(message)s',
    datefmt = '%Y-%m-%dT%H:%M:%S' if log_date else '%H:%M:%S',
    level = log_level)
  meas_log_lvl = lg.INFO if log_measurements_as_info else lg.DEBUG
  lg.info(f'{__file__} started.')
  lg.info(f'Log level = {args.log_level}')
  # ----------------------------------------------------------------------------

  # check input arguments ++++++++++++++++++++++++++++++++++++++++++++++++++++++
  if not isinstance(scan_time, numbers.Number):
    lg.critical(f'Invalid value {scan_time} for command line argument "scan_time". Exiting.') 
    return
  #: endif
  if not isinstance(scan_pause, numbers.Number) or scan_pause <= 0:
    lg.critical(f'Invalid value {scan_pause} for command line argument "scan_pause". Exiting.') 
    return
  #: endif
  if scan_time <= 0:
    scan_time = sys.float_info.max
    scan_pause = 0.1
  #: endif  --------------------------------------------------------------------

  # Read config file  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  try:
    lg.info(f'Reading "{config_file_name}" YAML configuration file.')
    with open(config_file_name, 'rt') as config_file:
      try:
        devices_from_yaml = yaml.safe_load(config_file)
        devices = {}  # devices to monitor, indexed by MAC address (upper-cased, no colons)
        for mac, device_data in devices_from_yaml.items():
          # remove :-_ from MAC address
          removable_chars = ':-_'
          for char in removable_chars:
            mac = mac.replace(char, '')
          #: endfor
          mac.upper()
          devices[mac] = device_data
        #: endfor
        macs = devices.keys()   # MAC addresses for the devices to monitor
      except yaml.YAMLError as e:
        lg.critical(f'Cannot parse "{config_file_name}" YAML configuration file (bad syntax?). {e}. Exiting.')
        return
      #: endtry
    #endwith
  except FileNotFoundError:
    lg.critical(f'Cannot find "{config_file_name}" configuration file. Exiting.')
    return
  except PermissionError:
    lg.critical(f'Cannot read "{config_file_name}" configuration file. Exiting.')
    return
  except OSError:
    lg.critical(f'OS error when accessing "{config_file_name}" configuration file. Exiting.')
    return
  #: endtry
  lg.info(f'Configuration file "{config_file_name}" successfully parsed.')
  # ----------------------------------------------------------------------------

  # manage program termination  ++++++++++++++++++++++++++++++++++++++++++++++++
  stop_event = asyncio.Event()
  loop = asyncio.get_event_loop()
  def signal_handler(signal_name_or_number, loop_or_frame): # ..................
    global reload
    if platform_system == 'Windows':
      lg.warning(f'Caught signal {signal.Signals(signal_name_or_number).name}, terminating.')
    else:
      lg.warning(f'Caught signal {signal_name_or_number}, terminating.')
      # to reload when running as a daemon
      if signal_name_or_number == 'SIGHUP':
        reload = True
        lg.info('Will reload due to signal HUP.')
      #: endif
    #: endif
    stop_event.set()
  #: enddef ....................................................................

  terminating_signal_names = ['SIGINT', 'SIGTERM', 'SIGABRT']
  if platform_system in ('Linux', 'Darwin'):  # Darwin not tested !!!
    terminating_signal_names += ('SIGHUP', 'SIGQUIT')
  elif platform_system == 'Windows':
    terminating_signal_names += ('SIGBREAK', )
  #: endif
  for signal_name in terminating_signal_names:
    if platform_system == 'Windows':
      signal.signal(getattr(signal, signal_name), signal_handler)
    else:
      loop.add_signal_handler(getattr(signal, signal_name), functools.partial(signal_handler, signal_name, loop))
    #: endif
  # :enfor  --------------------------------------------------------------------

  # start http(s) session manager ++++++++++++++++++++++++++++++++++++++++++++++
  try:
    http_session = aiohttp.ClientSession(timeout = aiohttp.ClientTimeout(total = AIOHTTP_TIMEOUT))
  except Exception as e:
    lg.critical(f'Cannot create aiohttp ClientSession. Terminating.')
    return
  # :endtry --------------------------------------------------------------------
  
  # get parameters for bleak.BleakScanner ++++++++++++++++++++++++++++++++++++++
  match platform_system:
    case 'Windows':
      scanning_mode = 'passive'
      bluez_args = []
      adapter = None
    case 'Linux':
      from bleak.backends.bluezdbus.scanner import BlueZScannerArgs
      from bleak.backends.bluezdbus.advertisement_monitor import OrPattern
      from bleak.assigned_numbers import AdvertisementDataType
      scanning_mode = 'passive'
      bluez_args = BlueZScannerArgs(or_patterns = [OrPattern(0, AdvertisementDataType.SERVICE_DATA_UUID16, b"\x1a\x18")])
    case 'Darwin':  # not tested !!!
      scanning_mode = 'active'
      bluez_args = []
      adapter = None
    case _:
      lg.critical(f'System "{platform_system}" not supported. Exiting.')
      return
  #: endmatch
  lg.info(f'Platform "{platform_system}" detected.')
  lg.debug(f'BLE scanner parameters: scanning_mode = {scanning_mode}, bluez = {repr(bluez_args)}.')
  # ----------------------------------------------------------------------------

  # scan  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  lg.info('Starting BLE scanner.')
  try:
    async with bleak.BleakScanner(detection_callback, scanning_mode = scanning_mode, bluez = bluez_args, adapter = adapter) as scanner:
      lg.info(f'BLE scanner started ({scan_time} s on / {scan_pause} s off).')
      while True:
        try:
          await asyncio.wait_for(stop_event.wait(), scan_time)
        except TimeoutError:
          await scanner.stop()
          lg.debug('BLE scanner stopped.')
        else:
          break
        #: endtry
        try:
          await asyncio.wait_for(stop_event.wait(), scan_pause)
        except TimeoutError:
          lg.debug('BLE scanner restarted.')
          await scanner.start()
        else:
          break
        #: endtry
      #: endwhile
    #: endwith
  except OSError as e:
    lg.critical(f'OS error "{e}" (BLE adapter not ready/enabled?), terminating.')
  except Exception as e:
    lg.critical(f'Unmanaged exception "{e}", terminating.')
  else: # normal termination
    lg.info('BLE scanner stopped.')
  finally:
    lg.info('Exiting.')
  #: endtry -------------------------------------------------------------------- 
  await http_session.close()
#: endef


if __name__ == '__main__':
  global reload
  reload = False
  platform_system = platform.system()
  if platform_system == "Windows":
    # required by aiomqtt
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
  #: endif
  asyncio.run(main())
  # reload daemon (if signal HUP arrived)
  if reload:
    os.execv(sys.executable, [sys.executable] + sys.argv)
  #: endif
#: endif

