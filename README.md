# Monitor for BLE thermometers on the Telink chipset flashed with atc1441 or pvvx firmware

This repo contains a  Python script able to (passively) listen to Bluetooth LE (BLE) thermometers based on the Telink chipset and flashed with either the [atc1441](https://github.com/atc1441/ATC_MiThermometer) or [pvvx](https://github.com/pvvx/ATC_MiThermometer) firmwares. There are a variety of sensors from Xiaomi, Qingping and Tuya compatible with such firmware, see the previous repositories.

The script supports both encrypted and un-encrypted BLE advertisements from the thermometers and reports the measurements to both MQTT (with customizable data formats) and Domoticz (using its native JSON API or via MQTT). Authentication and encryption are supported when sending data to these MQTT/Domoticz clients.

The script is _daemonizable_ to be run as a service under a `systemd` based Linux system. An example `.service` file is provided.

The configuration of the script (sensors to listen to, clients where to publish measurements, encryption, authentication, etc.) are specified in a configuration file in the YAML human-readable data serialization language. Read the comments on it to learn how to write it.

The script is written in Python (v3) using asynchronous IO (`async`/`await`) to manage all BLE/http(s)/MQTT communications. Packages `asyncio`, `bleak`, `aiohttp` and `aiomqtt` are used for that. These asynchronous IO approach gives low CPU and memory usage even when managing many sensors and clients.

Previous work by [jsBergbau](https://github.com/JsBergbau/MiTemperature2) served as an inspiration for this script that, in some parts, is a rewriting from scratch of jsBergbau's code. Such code offers more functionalities than this script, but this script does also work on Windows®, uses `asyncio` (jsBergbau's code is based on `blueply`, `requests` and `paho-mqtt` instead, which is fine, in any case) and, IMHO, it is easier to install and use.

## Requirements

### Hardware

You will need:

* Temperature/humidity sensors compatible and flashed with the [atc1441](https://github.com/atc1441/ATC_MiThermometer) or [pvvx](https://github.com/pvvx/ATC_MiThermometer) firmwares
* A Bluetooth LE capable Windows® (≥ 10) or Linux box (supporting `BlueZ` ≥ 5.43). Sorry, not tested on MacOS. A Raspberry Pi is enough (with its built-in Bluetooth or with an OS-supported BLE dongle)

### Software

You will need:

* Python (≥ 3.8)
* Python packages: `yaml`, `bleak`, `cryptodome`, `aiohttp` and `aiomqtt`.

Depending on the OS and its version, you may need to install them with the usual `pip` (add the `sudo` only in Linux and if you want all packages to be installed system-wide):

```shell
sudo pip install pyyaml bleak pycryptodomex aiohttp aiomqtt
```

or (in Debian Bookworm):

```shell
sudo apt install python3-yaml python3-bleak python3-pycryptodome python3-aiohttp
```

On Bookworm, `aiomqtt` must be installed with:

```shell
sudo apt install python3-pip
sudo pip install aiomqtt --break-system-packages
```

so, maybe, you may prefer to install `aiomqtt` inside a Python virtual environment.

Then, on Linux, file `/usr/lib/systemd/system/bluetooth.service` must be edited:

```shell
sudo nano /usr/lib/systemd/system/bluetooth.service
```

in order to add option `--experimental` to line:

```shell
ExecStart=/usr/libexec/bluetooth/bluetoothd --experimental
```

then:

```shell
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

That's all, copy the supplied `.py` file where you want and then `atc_pvvx_monitor.py` can now be tested from the command line:

```shell
pi@rpiz2w:~ $ ./atc_pvvx_monitor.py -h
usage: atc_pvvx_monitor.py [-h] [-c CONFIG_FILE_NAME] [-a ADAPTER] [-s SCAN_TIME] [-p SCAN_PAUSE] [-l LOG_FILE_NAME] [-m] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-t] [-d]

Monitor atc1441/pvvx BLE thermometers.

options:
  -h, --help            show this help message and exit
  -c CONFIG_FILE_NAME, --config-file CONFIG_FILE_NAME
                        file describing the thermometers to monitor and where to send (Domoticz/MQTT) their measurements. Defaults to "thermometers.yaml".
  -a ADAPTER, --adapter ADAPTER
                        Bluetooth HCI adapter to use (hci0, hci1, ...). Used only in Linux/BlueZ. If not specified, uses system default.
  -s SCAN_TIME, --scan_time SCAN_TIME
                        BLE scan time (in s). Defaults to 10. A <= 0 number is treated as "scan with no pauses".
  -p SCAN_PAUSE, --scan-pause SCAN_PAUSE
                        pause time between scans (in s). Defaults to 50. Ignored if SCAN_TIME <= 0.
  -l LOG_FILE_NAME, --log-file LOG_FILE_NAME
                        file where to write log messages. If not set, outputs messages to standard error.
  -m, --measurements_as_info
                        log measurements as INFO, instead of as DEBUG.
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        set log level. Defaults to "INFO".
  -t, --timestamp       include timestamps into log messages.
  -d, --date            include date into timestamps.
```



## Usage

When invoked from the command line, `atc_pvvx_monitor.py` supports options:

```shell
usage: atc_pvvx_monitor.py [-h] [-c CONFIG_FILE_NAME] [-a ADAPTER] [-s SCAN_TIME] [-p SCAN_PAUSE] [-l LOG_FILE_NAME] [-m] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-t] [-d]

options:
  -h, --help            show this help message and exit
  -c CONFIG_FILE_NAME, --config-file CONFIG_FILE_NAME
                        file describing the thermometers to monitor and where to send (Domoticz/MQTT) their measurements. Defaults to "thermometers.yaml".
  -a ADAPTER, --adapter ADAPTER
                        Bluetooth HCI adapter to use (hci0, hci1, ...). Used only in Linux/BlueZ. If not specified, uses system default.
  -s SCAN_TIME, --scan_time SCAN_TIME
                        BLE scan time (in s). Defaults to 10. A <= 0 number is treated as "scan with no pauses".
  -p SCAN_PAUSE, --scan-pause SCAN_PAUSE
                        pause time between scans (in s). Defaults to 50. Ignored if SCAN_TIME <= 0.
  -l LOG_FILE_NAME, --log-file LOG_FILE_NAME
                        file where to write log messages. If not set, outputs messages to standard error.
  -m, --measurements_as_info
                        log measurements as INFO, instead of as DEBUG.
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        set log level. Defaults to "INFO".
  -t, --timestamp       include timestamps into log messages.
  -d, --date            include date into timestamps.
```

All these options seem self-explanatory. Only `-s` and `-p` may require a comment. When scanning for BLE advertisements, some backends may block the  Bluetooth adapter for other uses. Thus, it may be required to scan for a given time and then release the adapter for some other time. Options `-s` and `-p` set these times (in s) respectively. If option `-s 0` is given, scanning never pauses. If your sensors have and advertisement period of, say, T seconds, a small multiple of T may be enough.

By default, the log does not contain timestamps. This is because, when run as a daemon/service, the log messages are managed by `journald`, that inserts them.

## Configuration

The configuration describing the sensors to listen to and the clients (Domoticz or MQTT) where to report the measurements is contained in a configuration file (whose name may be specified from the command line) in the YAML language. Please, read the provided `thermometers.yaml` example configuration file to see how to write its contents.

## Run as a service

In Linux this script can be run as a daemon. This is achieved creating a service that `systemd` will start at boot. To accomplish this task an example `atc_pvvx_monitor.service` file is provided. Its contents are:

```shell
[Unit]
Description=Monitor ambient temperature via BLE thermometers with ATC/pvvx firmware
Wants=multi-user.target bluetooth.service
After=bluetooth.service

[Service]
ExecStart=/usr/bin/python3 /home/pi/atc_pvvx_monitor.py -s10 -p50 -c /home/pi/thermometers.yaml
ExecReload=/usr/bin/kill -HUP $MAINPID

[Install]
WantedBy=default.target
```

You may want to edit line `ExecStart=/usr/bin/python3 /home/pi/atc_pvvx_monitor.py -s10 -p50 -c /home/pi/thermometers.yaml` to better fit your needs. This file must be placed inside `/usr/lib/systemd/system`, owned by `root:root` with permission `640`, this is:

```shell
sudo cp atc_pvvx_monitor.service /usr/lib/systemd/system
sudo chown root:root /usr/lib/systemd/system/atc_pvvx_monitor.service
sudo chmod 640 /usr/lib/systemd/system/atc_pvvx_monitor.service
```

Then the service can be enabled and started:

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now atc_pvvx_monitor
```

From now on, `atc_pvvx_monitor` will be running in the system, automatically launched at boot. It can be stopped/started/restarted/reloaded (to re-read its YAML configuration file) with `sudo systemctl stop/start/restart/reload atc_pvvx_monitor`. Its status can be viewed with `sudo systemctl status atc_pvvx_monitor`.

When run as a service, its log is managed by the `journald` service, and can be read with `journalctl -u atc_pvvx_monitor`.

