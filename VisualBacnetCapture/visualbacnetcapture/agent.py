"""
Cristian Romo
cristian@aceiotsolutions.com

Capture network packets for BACnet, or on a configurable protocol and port list
Enable upload of packet captures to the Visual BACnet API

"""

__docformat__ = "reStructuredText"

import logging
import sys
import subprocess
import os

import gevent
import grequests
from datetime import datetime
from volttron.platform.agent import utils
from volttron.platform.messaging.health import STATUS_BAD, STATUS_GOOD
from volttron.platform.vip.agent import Agent, Core, RPC

_log = logging.getLogger(__name__)
utils.setup_logging()
__version__ = "1.1.0"


def visualbacnetcapture(config_path, **kwargs):
    """
    Parses the Agent configuration and returns an instance of
    the agent created using that configuration.

    :param config_path: Path to a configuration file.
    :type config_path: str
    :returns: PacketCapture
    :rtype: PacketCapture
    """

    return VisualBacnetCapture(**kwargs)


class VisualBacnetCapture(Agent):
    """
    Document agent constructor here.
    """

    def __init__(self ,**kwargs):
        super(VisualBacnetCapture, self).__init__(**kwargs)
        self.capture_duration = None
        self.capture_interval = None
        self.interface = None
        self.capture_file = None
        self.protocol = None
        self.ports = None
        self.api_key = None
        self.api_url = None
        self.config_store = {}
        self.lock = gevent.lock.BoundedSemaphore()
        # Hook self.configure up to changes to the configuration file "config".
        self.vip.config.subscribe(
            self.configure, actions=["NEW", "UPDATE"], pattern="config"
        )

    def configure(self, config_name, action, contents):
        """
        Called after the Agent has connected to the message bus.
        If a configuration exists at startup this will be called before onstart.

        Is called every time the configuration in the store changes.
        """
        _log.warning(f"configure called with {config_name=}, {action=}, {contents=}")
        if config_name == "config":
            self.capture_duration = contents.get("capture_duration")
            self.capture_interval = contents.get("capture_interval")
            self.interface = contents.get("interface")
            self.capture_file = contents.get("capture_file")
            self.protocol = contents.get("protocol")
            self.ports = contents.get("ports")
            self.api_key = contents.get("api_key")
            self.api_url = contents.get("api_url")
            self.config_store = contents
        result = self.check_config()
        if result is False:
            _log.error("Configuration check failed. Agent will not start.")
            return
        elif result is True:
            self.config_store = contents
            self.core.periodic(self.capture_interval, self.packet_capture, wait=15)
        else:
            _log.error("Configuration check returned unexpected result.")
            self.vip.health.set_status(STATUS_BAD, "Configuration check failed")
            return

    def check_config(self):
        """
        Check to make sure all configuration parameters are set
        """
        try:
            assert self.capture_duration, "capture_duration must be set"
            assert self.capture_interval, "capture_interval must be set"
            assert self.capture_duration > 0, "capture_duration must be greater than 0"
            assert self.capture_interval > 0, "capture_interval must be greater than 0"
            assert self.capture_file, "capture_file must be set"
            assert self.protocol, "protocol must be set"
            assert self.ports, "ports must be set"
            assert self.api_key, "api_key must be set"
            assert self.api_url, "api_url must be set"
        except (AssertionError, TypeError) as error:
            _log.error(f"Configuration error: {error}")
            self.vip.health.set_status(STATUS_BAD, f"Configuration error: {error}")
            return False
        self.vip.health.set_status(STATUS_GOOD, "Configuration is valid")
        _log.info("Configuration is valid")
        return True

    def upload_to_api(self):
        """
        Upload captured packets to Visual BACnet API
        """
        with self.lock:
            _log.debug(f"uploading to API... {self.api_url}")
            with open(self.capture_file, "rb") as file:
                filedata = file.read()
            timestamp = f"{str(datetime.now().isoformat(sep='_', timespec='seconds')).replace(':', '-')}"
            filename = f"{os.uname()[1]}_{timestamp}.pcap"
            try:
                request = grequests.post(
                    self.api_url,
                    files=(
                        ("apiKey", (None, self.api_key)),
                        ("file", (filename, filedata)),
                    ),
                )
                response = grequests.map(
                    [request], exception_handler=self.grequests_exception_handler
                )[0]
                if response is not None:
                    _log.info(f"finished uploading: {response.status_code}")
                else:
                    _log.error("No response from API upload request")
                    self.vip.health.set_status(STATUS_BAD, "API upload failed")
                    return
            except Exception as error:
                _log.debug(f"{error=}")

    def packet_capture(self):
        """
        Capture network packets on configured ports
        """
        if self.lock.locked():
            _log.info("File upload not yet finished. Skipping packet capture")
            return

        if isinstance(self.ports, int):
            ports_list = self.ports
        elif isinstance(self.ports, list):
            # use type() instead of isinstance(), since booleans inherit from int
            # prevents false negatives if list contains bool
            if not all((type(p) is int) for p in self.ports):
                _log.error("ports list contains non-integer")
                return

            if len(self.ports) < 1:
                _log.error("no ports defined to scan on")
                return None
            ports_list = str(self.ports[0])
            for port in self.ports[1:]:
                ports_list += f" or port {port}"
        else:
            _log.error(f"port is not int or list: {type(self.ports)} {self.ports=}")
            return

        command = f"""tcpdump -G {self.capture_duration} -W 1 -w {self.capture_file} proto {self.protocol} and port {ports_list}"""
        if self.interface:
            command += f" -i {self.interface}"

        _log.info(f"capturing packets on ports {ports_list}")
        try:
            subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as error:
            _log.error(f"cannot execute tcpdump command: {error.stderr}")
            self.vip.health.set_status(STATUS_BAD, "tcpdump error")
            return

        self.vip.health.set_status(STATUS_GOOD, "packet capture complete")
        self.upload_to_api()

    def _handle_publish(self, peer, sender, bus, topic, headers, message):
        """
        Callback triggered by the subscription setup using
        the topic from the agent's config file
        """

    def grequests_exception_handler(self, request, exception):
        """
        Handle exceptions from grequests
        """
        _log.error(f"Request failed: {request.url} with exception: {exception}")

    @Core.receiver("onstart")
    def onstart(self, sender, **kwargs):
        """
        This is called once the Agent has successfully connected to the platform.
        This is a good place to setup subscriptions if they are not dynamic or
        do any other startup activities that require a connection to the message bus.
        Called after any configurations methods that are called at startup.

        Usually not needed if using the configuration store.
        """
        if not self.config_store:
            _log.error("No configuration found. Please configure the agent.")
            self.vip.health.set_status(STATUS_BAD, "No configuration found")
            return

    @Core.receiver("onstop")
    def onstop(self, sender, **kwargs):
        """
        This method is called when the Agent is about to shutdown,
        but before it disconnects from the message bus.
        """


def main():
    """Main method called to start the agent."""
    utils.vip_main(visualbacnetcapture, version=__version__)


if __name__ == "__main__":
    # Entry point for script
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
