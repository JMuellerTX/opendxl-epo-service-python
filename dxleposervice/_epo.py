# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2017 McAfee Inc. - All Rights Reserved.
################################################################################

from __future__ import absolute_import
import json
import logging
import re
import threading
import warnings
import requests
from requests.auth import HTTPBasicAuth

# Configure local logger
logger = logging.getLogger(__name__)

_COMMAND_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.]+$")
_TOKEN_QUERY_PATTERN = re.compile(r"(orion\.user\.security\.token=)[^&\s'\"\\]+")
_BASIC_AUTH_URL_PATTERN = re.compile(r"(https?://[^/\s:@]+:)[^/\s@]+(@)")


def _redact_sensitive(message, token=None, password=None):
    """
    Redacts security tokens and passwords from log/error strings.
    """
    if not message:
        return message
    redacted = _TOKEN_QUERY_PATTERN.sub(r"\1--redacted--", str(message))
    redacted = _BASIC_AUTH_URL_PATTERN.sub(r"\1--redacted--\2", redacted)
    if token:
        redacted = redacted.replace(token, "--redacted--")
    if password:
        redacted = redacted.replace(password, "--redacted--")
    return redacted


class _Epo(object):
    """
    An ePO server that is being wrapped and exposed to the DXL fabric
    """

    # The command used to determine the GUID for the ePO server
    DXL_CLIENT_STATUS_REPORT_COMMAND = "DxlClient.getStatusReport"

    # The key within the status report used to determine the ePO server's
    # unique identifier (GUID)
    UNIQUE_ID_KEY = "uniqueId"

    # UTF-8 encoding (used for encoding/decoding payloads)
    UTF_8 = "utf-8"

    def __init__(self, name, host, port, user, password, verify,
                 allowed_commands=None, timeout=None):
        """
        Constructs the ePO server wrapper

        :param name: The name of the ePO server
        :param host: The host for the ePO server
        :param port: The port for the ePO server
        :param user: The user used to login to the ePO server
        :param password: The password used to login to the ePO server
        :param verify: Whether to verify the ePO server's certificate
        :param allowed_commands: Optional iterable of allowed command names
        :param timeout: Optional HTTP request timeout in seconds
        """
        self._name = name
        self._allowed_commands = (
            set(allowed_commands) if allowed_commands is not None else None
        )
        if timeout is None:
            self._client = _EpoRemote(host, port, user, password, verify)
        else:
            self._client = _EpoRemote(
                host, port, user, password, verify, timeout=timeout)

    def lookup_guid(self):
        """
        Attempts to lookup the GUID (unique identifier) for the ePO server by invoking
        the "client status report" remote command

        :return: The GUID if found (otherwise an exception will be thrown)
        """
        try:
            response = self._client.invoke_command(
                self.DXL_CLIENT_STATUS_REPORT_COMMAND,
                {}, output="json")
            response_dict = json.loads(response)

            if self.UNIQUE_ID_KEY not in response_dict:
                raise Exception("Unable to find '{0}' in response.".format(
                    self.UNIQUE_ID_KEY))

            return response_dict[self.UNIQUE_ID_KEY]
        except:
            logger.error(
                "Error attempting to lookup GUID for ePO server: %s",
                self._name)
            raise

    def execute(self, command, output, req_params):
        """
        Invokes a remote command on the ePO server (via HTTP)

        :param command: The command to invoke
        :param output: The output type (json, xml, verbose, terse)
        :param req_params: The parameters for the command
        :return: The result of the command execution
        """
        _EpoRemote.validate_command_name(command)
        if self._allowed_commands is not None and \
                command not in self._allowed_commands:
            raise ValueError(
                "Command '{0}' is not allowed".format(command))
        return self._client.invoke_command(command, req_params, output)


class _EpoRemote(object):
    """
    Handles REST invocation of ePO remote commands
    """

    DEFAULT_TIMEOUT = 30

    def __init__(self, host, port, username, password, verify,
                 timeout=DEFAULT_TIMEOUT):
        """
        Initializes the epoRemote with the information for the target ePO instance

        :param host: the hostname of the ePO to run remote commands on
        :param port: the port of the desired ePO
        :param username: the username to run the remote commands as
        :param password: the password for the ePO user
        :param verify: Whether to verify the ePO server's certificate
        :param timeout: HTTP request timeout in seconds
        """

        logger.debug(
            'Initializing epoRemote for ePO %s on port %s with user %s',
            host, port, username)

        self._baseurl = 'https://{}:{}/remote'.format(host, port)
        self._auth = HTTPBasicAuth(username, password)
        self._session = requests.Session()
        self._verify = verify
        self._timeout = timeout
        self._token = ''
        self._lock = threading.RLock()

    @staticmethod
    def validate_command_name(command_name):
        """
        Validates that the command name is a non-empty string matching
        ``^[A-Za-z0-9_.]+$`` and does not contain ``..``.
        """
        if not isinstance(command_name, (str, type(u""))) or \
                not command_name or \
                not _COMMAND_NAME_PATTERN.match(command_name) or \
                ".." in command_name:
            raise ValueError(
                "Invalid command name specified: {0}".format(command_name))

    def invoke_command(self, command_name, params, output='json'):
        """
        Invokes the given remote command by name with the supplied parameters

        :param command_name: The name of the ePO remote command to invoke
        :param params: A dict of parameters to pass to the remote command
        :param output: the desired output format. Valid output types: json, xml, verbose, and terse
        :return: the response for the ePO remote command
        """
        self.validate_command_name(command_name)

        if params is None:
            req_params = {}
        elif isinstance(params, dict):
            req_params = params.copy()
        else:
            raise ValueError("Invalid parameters specified; expected a dict")

        if output not in ['json', 'xml', 'verbose', 'terse']:
            raise Exception('Invalid output type specified: ' + str(output))

        with self._lock:
            self._save_token()
            token = self._token

        req_params['orion.user.security.token'] = token
        req_params[':output'] = output

        return self._parse_response(self._send_request(command_name, req_params))

    def _send_request(self, command_name, params=None):
        """
        Sends a request to the ePO server with the supplied command name and parameters

        :param command_name: The command name to invoke
        :param params: The parameters to provide for the command
        :return: the response object from ePO
        """
        self.validate_command_name(command_name)
        if params is not None and not isinstance(params, dict):
            raise ValueError("Invalid parameters specified; expected a dict")

        logger.debug(
            'Invoking command %s', command_name)
        if params:
            redacted_params = params.copy()
            if 'orion.user.security.token' in redacted_params:
                redacted_params['orion.user.security.token'] = '--redacted--'
            logger.debug(redacted_params)

        try:
            with warnings.catch_warnings():
                # Only the warning that follows from the caller's own choice is
                # suppressed. There used to be a second filter here for urllib3's
                # SubjectAltNameWarning, applied unconditionally - so it hid a
                # genuine certificate complaint even when verification was on. It
                # has also done nothing since urllib3 2.0, which removed that
                # warning altogether.
                if not self._verify:
                    warnings.filterwarnings("ignore", "Unverified HTTPS request")
                return self._session.get(
                    '{}/{}'.format(self._baseurl, command_name),
                    auth=self._auth,
                    params=params,
                    verify=self._verify,
                    timeout=self._timeout)
        except Exception as ex:
            redacted_msg = _redact_sensitive(
                str(ex),
                token=self._token,
                password=getattr(self._auth, "password", None))
            raise Exception(redacted_msg)

    def _save_token(self):
        """
        Retrieves the security token for this session and saves it for later requests
        """
        with self._lock:
            self._token = self._parse_response(
                self._send_request('core.getSecurityToken'))
            logger.debug('Security token received from ePO')

    @staticmethod
    def _parse_response(response):
        """
        Parses the response object from ePO. Removes the return status and code
        from the response body and returns just the remote command response.
        Throws an exception if an error response is returned.

        :param response: the ePO remote command response object to parse
        :return: the ePO remote command results as a string
        """
        try:
            response_body = response.text

            status = response_body[:response_body.index(':')]
            result = response_body[response_body.index(':') + 1:].strip()

            if 'Error' in status:
                code = int(status[status.index(' '):].strip())
                raise Exception('Response failed with error code ' + str(
                    code) + '. Message: ' + result)

            return result
        except:
            logger.error('Exception while parsing response.')
            raise

