"""
BSD 3-Clause License.

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ThreatConnect Plugin implementation to pull the data from
ThreatConnect Platform.
"""

import datetime
import time
import hmac
import hashlib
import base64
import requests
import urllib.parse
import os
import json
import copy
from typing import Dict, List
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)

THREATCONNECT_TO_INTERNAL_TYPE = {
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
    "url": IndicatorType.URL,
}

RATING_TO_SEVERITY = {
    0: SeverityType.UNKNOWN,
    1: SeverityType.LOW,
    2: SeverityType.LOW,
    3: SeverityType.MEDIUM,
    4: SeverityType.HIGH,
    5: SeverityType.CRITICAL,
}

SEVERITY_TO_RATING = {
    SeverityType.UNKNOWN: 0,
    SeverityType.LOW: 1,
    SeverityType.MEDIUM: 3,
    SeverityType.HIGH: 4,
    SeverityType.CRITICAL: 5,
}

LIMIT = 1000  # Maximum Response LIMIT at Time.
PAGE_LIMIT = 100
MAX_RETRY = 3
TAG_NAME = "Netskope CE"
PLATFORM_NAME = "ThreatConnect"
MODULE_NAME = "CTE"
PLUGIN_VERSION = "1.1.0"


class ThreatConnectPlugin(PluginBase):
    """ThreatConnect Plugin Base Class.

    Args:
        PluginBase (PluginBase): Inherit PluginBase Class from Cloud
        Threat Exchange Integration.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def handle_error(self, resp) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API.
        Returns:
            dict: Returns the dictionary of response JSON when response is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                self.logger.error(
                    f"{self.log_prefix}: "
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 401:
            self.logger.error(
                f"{self.log_prefix}: Received exit code 401, " "Authentication Error.",
                details=resp.text,
            )
        elif resp.status_code == 403:
            self.logger.error(
                f"{self.log_prefix}: " "Received exit code 403, Forbidden User.",
                details=resp.text,
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.logger.error(
                f"{self.log_prefix}: "
                f"Received exit code {resp.status_code}, HTTP client Error.",
                details=resp.text,
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.logger.error(
                f"{self.log_prefix}: "
                f"Received exit code {resp.status_code}, HTTP server Error.",
                details=resp.text,
            )
        else:
            self.logger.error(
                f"{self.log_prefix}: "
                f"Received exit code {resp.status_code}, HTTP Error.",
                details=resp.text,
            )
        resp.raise_for_status()

    def _get_headers_for_auth(
        self, api_path: str, access_id: str, secret_key: str, request_type: str
    ) -> Dict:
        """Return header for authentication.

        Args:
            api_path (str): API path string.
            access_id(str): ThreatConnect API Access ID.
            secret_key(str): ThreatConnect API Secret Key.
            request_type (str): Request Type like GET, POST, PUT, etc.

        Returns:
            header (dict) : Header for authentication.
        """
        unix_epoch_time = int(time.time())
        api_path = f"{api_path}:{request_type}:{unix_epoch_time}"
        bytes_api_path = bytes(api_path, "utf-8")
        bytes_secret_key = bytes(secret_key, "utf-8")

        # HMAC-SHA256
        dig = hmac.new(
            bytes_secret_key, msg=bytes_api_path, digestmod=hashlib.sha256
        ).digest()

        # BASE64 ENCODE
        hmac_sha256 = base64.b64encode(dig).decode()
        signature = f"TC {access_id}:{hmac_sha256}"
        header = {
            "Authorization": str(signature),
            "Timestamp": str(unix_epoch_time),
        }
        return header

    def get_reputation(self, ioc_response_json) -> int:
        """Get reputation value based on confidence score.

        Args:
            ioc_response_json (json): Single response JSON object.

        Returns:
            int: Reputation score ( >= 1 and <= 10).
        """
        # confidence is in between 0 and 100
        # reputation is in between 0 and 10.
        if "confidence" in ioc_response_json:
            reputation = ioc_response_json["confidence"]
            if reputation and reputation > 10:
                return reputation // 10
            else:
                return 1
        else:
            return 5  # default value

    def get_api_url(self, api_path, threat_type):
        """Get API url.

        Args:
            api_path (str): API endpoint.
            threat_type (str): Type of data to pull.

        Returns:
            str: return API url endpoint.
        """
        result_start = 0
        if self.last_run_at:
            last_run_time = self.last_run_at
            last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            last_run_time = datetime.datetime.now() - datetime.timedelta(
                days=self.configuration["days"]
            )
            last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = None

        if threat_type == "Both":
            query = 'typeName IN ("File","URL")'
        else:
            query = f'typeName == "{threat_type}"'

        # adding last run time query
        query += f" AND lastModified >= '{last_run_time}'"

        filtered_string = "tql=" + urllib.parse.quote(query)
        api_url = f"{api_path}?sorting=lastModified%20asc&fields=tags&{filtered_string}"
        api_url += f"&resultStart={result_start}&resultLimit={LIMIT}"
        return api_url

    def get_pull_request(self, api_url):
        """Make pull request to get data from ThreatConnect.

        Args:
            api_url (str): API url endpoint.

        Returns:
            Response: Return API response.
        """
        headers = self._get_headers_for_auth(
            api_url,
            self.configuration["access_id"],
            self.configuration["secret_key"],
            "GET",
        )
        query_endpoint = self.configuration["base_url"] + api_url
        ioc_response = self._api_calls(
            requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            ),
        )
        return ioc_response

    def make_indicators(self, ioc_response_json, indicator_list):
        """Add received data to Netskope.

        Args:
            ioc_response_json (_type_): _description_
            tagging (_type_): _description_
            indicator_list (_type_): _description_
        """
        md5, sha256, url_ioc, file_count, skipped_ioc = 0, 0, 0, 0, 0
        skipped_md5, skipped_sha256, skipped_url = 0, 0, 0
        skipped_tags = set()
        tag_utils = TagUtils()
        for ioc_json in ioc_response_json["data"]:
            if (
                "tags" in ioc_json
                and "data" in ioc_json["tags"]
                and TAG_NAME
                in [
                    tag_info["name"]
                    for tag_info in ioc_json["tags"]["data"]
                    if "name" in tag_info
                ]
            ):
                skipped_ioc += 1
                continue
            tag_list, tags = [], []
            if self.configuration.get("enable_tagging", "No") == "Yes" and "tags" in ioc_json and ioc_json["tags"] != {}:
                for tag_json in ioc_json.get("tags", {}).get("data", []):
                    if tag_json.get("name"):
                        tag_list.append(tag_json["name"])

                tags, skipped = self._create_tags(
                    tag_utils,
                    tag_list,
                    self.configuration,
                )
                skipped_tags.update(skipped)

            if ioc_json["type"] == "File":
                file_count += 1
                if "md5" in ioc_json:
                    try:
                        indicator_list.append(
                            Indicator(
                                value=ioc_json["md5"].lower(),
                                type=IndicatorType.MD5,
                                active=ioc_json.get("active", True),
                                severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                                reputation=self.get_reputation(ioc_json),
                                comments=ioc_json.get("description", ""),
                                firstSeen=ioc_json.get("dateAdded"),
                                lastSeen=ioc_json.get("lastModified"),
                                tags=tags,
                            )
                        )
                        md5 += 1
                    except Exception:
                        skipped_md5 += 1

                if "sha256" in ioc_json:
                    try:
                        indicator_list.append(
                            Indicator(
                                value=ioc_json["sha256"].lower(),
                                type=IndicatorType.SHA256,
                                active=ioc_json.get("active", True),
                                severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                                reputation=self.get_reputation(ioc_json),
                                comments=ioc_json.get("description", ""),
                                firstSeen=ioc_json.get("dateAdded"),
                                lastSeen=ioc_json.get("lastModified"),
                                tags=tags,
                            )
                        )
                        sha256 += 1
                    except Exception:
                        skipped_sha256 += 1
            else:
                for url in ioc_json["text"].split(","):
                    try:
                        indicator_list.append(
                            Indicator(
                                value=url,
                                type=IndicatorType.URL,
                                active=ioc_json.get("active", True),
                                severity=RATING_TO_SEVERITY[ioc_json.get("rating", 0)],
                                reputation=self.get_reputation(ioc_json),
                                comments=ioc_json.get("description", ""),
                                firstSeen=ioc_json.get("dateAdded"),
                                lastSeen=ioc_json.get("lastModified"),
                                tags=tags,
                            )
                        )
                        url_ioc += 1
                    except Exception:
                        skipped_url += 1

        if len(skipped_tags) > 0:
            self.logger.warn(
                f"{self.log_prefix}: Skipping following tag(s) because they are too long: {', '.join(skipped_tags)}"
            )
        self.logger.debug(
            f"{self.log_prefix}: Stats - Total File IOCs: {file_count}, MD5: {md5}, SHA256: {sha256}, URL: {url_ioc}, Skipped IOC as they already exists: {skipped_ioc}, "
            f"Skipped MD5: {skipped_md5}, Skipped SHA256: {skipped_sha256}, Skipped URL: {skipped_url}."
        )

    def pull_data_from_threatconnect(
        self,
        api_path: str,
        threat_type: str
    ) -> List[Indicator]:
        """Fetch Data from ThreatConnect API.

        Args:
            api_path (str): API endpoint.
            threat_type (str): Type of threat data.
            tagging (bool): Enable or disable tagging.

        Returns:
            List[Indicator]: List of Indicator Models.
        """
        indicator_list = []
        page_count = 0
        api_url = None
        if self.storage is not None:
            storage = self.storage
        else:
            storage = {}
        display_storage = copy.deepcopy(storage)
        configuration_details = {}
        next_uri = ""
        if display_storage and display_storage.get("configuration_details") and display_storage.get("configuration_details").get("access_id") and display_storage.get("configuration_details").get("secret_key"):
            del display_storage["configuration_details"]["access_id"]
            del display_storage["configuration_details"]["secret_key"]
            next_uri = display_storage.get("next_uri", "")
            configuration_details = display_storage.get("configuration_details", {})
        self.logger.debug(
            f"{self.log_prefix}: Pulling the indicators, storage value(next uri): {next_uri}, storage value(configuration_details): {configuration_details}"
        )
        api_url = storage.get("next_uri")
        prev_configuration = storage.get("configuration_details", {})
        prev_base_url = prev_configuration.get("base_url", "")
        prev_access_id = prev_configuration.get("access_id", "")
        prev_secret_key = prev_configuration.get("secret_key", "")
        prev_threat_type = prev_configuration.get("threat_type", "")
        base_url = self.configuration["base_url"]
        access_id = self.configuration["access_id"]
        secret_key = self.configuration["secret_key"]

        configuration_match = (
            prev_base_url.strip("/") == base_url.strip("/")
            and prev_access_id == access_id
            and prev_secret_key == secret_key
            and prev_threat_type == threat_type
        )
        # self.logger.info(f"Here is the configuration match: {configuration_match}")
        self.logger.debug(
            f"{self.log_prefix}: Previous configuration's comparison with current configuration. Match result: {configuration_match}"
        )
        if not (api_url and configuration_match):
            api_url = self.get_api_url(api_path, threat_type)

        while True:
            self.logger.debug(
                f"{self.log_prefix}: API URL to fetch the indicators: {api_url}"
            )
            try:
                for retry_count in range(MAX_RETRY):
                    ioc_response = self.get_pull_request(
                        api_url,
                    )
                    if ioc_response.status_code in [500, 503]:
                        retry_after = (retry_count+1)*30
                        self.logger.error(
                            f"Received Error Code {ioc_response.status_code}, "
                            f"Retrying after {retry_after} seconds."
                        )
                        time.sleep(retry_after)
                        continue
                    else:
                        break
                self.logger.debug(
                    f"{self.log_prefix}: API Response code: {ioc_response.status_code}"
                )
                ioc_response_json = self.handle_error(ioc_response)
            except Exception as ex:
                storage.clear()
                storage["next_uri"] = api_url
                storage["configuration_details"] = self.configuration
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while executing th pull cycle. Error: {ex}. "
                    "The pulling of the indicators will be resumed in the next pull cycle"
                )
                self.logger.debug(
                    f"{self.log_prefix}: The pulling of the indicators will be resumed in the next pull cycle"
                )
                return indicator_list
            if ioc_response_json.get("status", "") != "Success":
                raise requests.exceptions.HTTPError(
                    f"{self.log_prefix}: Unable to fetch Indicator. "
                    f"Error: {ioc_response_json.get('message', '')}."
                )
            elif ioc_response_json.get("data", None):
                self.make_indicators(
                    ioc_response_json,
                    indicator_list,
                )
                # Handling Result Limit Of API
                if ioc_response_json.get("next", None):
                    api_url = ioc_response_json["next"].replace(
                        self.configuration["base_url"].strip("/"), ""
                    )
                else:
                    storage.clear()
                    storage["configuration_details"] = self.configuration
                    return indicator_list
            else:
                # case: status -> Success, return -> []
                storage.clear()
                storage["configuration_details"] = self.configuration
                return []

            page_count += 1
            if page_count >= PAGE_LIMIT:
                storage["next_uri"] = api_url
                storage["configuration_details"] = self.configuration
                self.logger.info(
                    f"{self.log_prefix}: Page limit of {PAGE_LIMIT} has reached. Returning {len(indicator_list)} indicators"
                )
                return indicator_list

    def _create_tags(
        self, utils: TagUtils, tags: List[dict], configuration: dict
    ) -> (List[str], List[str]):
        """Create new tag(s) in database if required."""
        if configuration["enable_tagging"] != "Yes":
            return [], []

        tag_names, skipped_tags = [], []
        for tag in tags:
            try:
                if tag is not None and not utils.exists(tag.strip()):
                    utils.create_tag(
                            TagIn(name=tag.strip(), color="#ED3347")
                        )
            except ValueError:
                skipped_tags.append(tag)
            except Exception:
                skipped_tags.append(tag)
            else:
                tag_names.append(tag)
        return tag_names, skipped_tags

    def _api_calls(self, request):
        """Call API and handle request exception.

        Args:
            request(Response): Lambda function to request the API.

        Raises:
            HTTPError: When response code is not 200.
            Exception

        Returns:
            response: Return response from API.
        """
        try:
            return request
        except requests.exceptions.ProxyError as err:
            self.logger.error(f"{self.log_prefix}: Invalid proxy configuration.")
            raise err
        except requests.exceptions.ConnectionError as err:
            self.logger.error(f"{self.log_prefix}: Connection Error occurred: {err}.")
            raise err
        except requests.exceptions.RequestException as err:
            self.logger.error(
                f"{self.log_prefix}: " f"Request Exception occurred: {err}."
            )
            raise err
        except Exception as err:
            self.logger.error(f"{self.log_prefix}: Exception occurred: {err}.")
            raise err

    def _is_valid_credentials(
        self, base_url: str, access_id: str, secret_key: str
    ) -> bool:
        """Validate credentials.

        Args:
            access_id (str): Access ID for ThreatConnect.
            secret_key (str): Secret Key for ThreatConnect.

        Returns:
            bool: True for valid credentials and false for not valid.
        """
        api_path = "/api/v3/security/owners"
        query_endpoint = base_url + api_path
        headers = self._get_headers_for_auth(
            api_path,
            access_id,
            secret_key,
            "GET",
        )
        response = self._api_calls(
            requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            ),
        )

        if response.status_code == 200 or response.status_code == 201:
            return True
        else:
            return False

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urllib.parse.urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            configuration(dict): Configuration from manifest.json.

        Returns:
            ValidationResult: Valid configuration fields or not.
        """
        # Base URL
        if (
            "base_url" not in configuration
            or not isinstance(configuration["base_url"], str)
            or not configuration["base_url"].strip()
            or not self._validate_url(configuration["base_url"])
            or "threatconnect" not in configuration["base_url"].split(".")
        ):
            self.logger.error(
                f"{self.log_prefix}: "
                "Invalid Base URL found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Base URL provided.",
            )
        # Access_ID
        if (
            "access_id" not in configuration
            or not isinstance(configuration["access_id"], str)
            or not configuration["access_id"].strip()
        ):
            self.logger.error(
                f"{self.log_prefix}: "
                "Invalid Access ID found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Access ID provided.",
            )
        # Secret Key
        if (
            "secret_key" not in configuration
            or not isinstance(configuration["secret_key"], str)
            or not configuration["secret_key"].strip()
        ):
            self.logger.error(
                f"{self.log_prefix}: "
                "No Secret key found in configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Secret key provided."
            )
        # Enable Tagging
        if "enable_tagging" not in configuration or configuration[
            "enable_tagging"
        ] not in ["Yes", "No"]:
            self.logger.error(
                f"{self.log_prefix}: "
                "Value of Enable Tagging should be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Tagging' provided."
                "Allowed values are 'Yes', or 'No'.",
            )
        # Enable Polling
        if "is_pull_required" not in configuration or configuration[
            "is_pull_required"
        ] not in ["Yes", "No"]:
            self.logger.error(
                f"{self.log_prefix}: "
                "Value of Enable Polling should be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided."
                "Allowed values are 'Yes', or 'No'.",
            )
        if not self._is_valid_credentials(
            configuration["base_url"],
            configuration["access_id"],
            configuration["secret_key"],
        ):
            return ValidationResult(
                success=False,
                message="Invalid Access ID or Secret key provided.",
            )
        # Initial Range
        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
                or int(configuration["days"]) > 365
            ):
                self.logger.error(
                    f"{self.log_prefix}: "
                    "Validation error occurred Error: "
                    "Invalid Initial Range provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Initial Range provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Initial Range provided.",
            )
        else:
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

    def pull(self) -> List[Indicator]:
        """Pull Indicators data from ThreatConnect API.

        Returns:
            List[Indicator] : Return List of Indicators Models.
        """
        if self.configuration["is_pull_required"] == "Yes":
            self.logger.info(f"{self.log_prefix}: Polling is enabled.")
            api_path = "/api/v3/indicators"
            return self.pull_data_from_threatconnect(
                api_path,
                self.configuration["threat_type"]
            )
        else:
            self.logger.info(f"{self.log_prefix}: Polling is disabled, skipping.")
            return []

    def get_group_id(self, action_dict):
        """Return group id based on condition.

        Args:
            action_dict (Dict): Aciton dictionary.

        Returns:
            str: Return group id.
        """
        if action_dict.get("parameters").get("group_name") != "create_group":
            return action_dict.get("parameters")["group_name"]
        else:
            # Creating  New Group
            api_path = "/api/v3/groups/"
            create_group_api = self.configuration["base_url"] + api_path
            headers = self._get_headers_for_auth(
                api_path,
                self.configuration["access_id"],
                self.configuration["secret_key"],
                "POST",
            )
            group_names = self.get_group_names()
            if (
                action_dict.get("parameters")["new_group_name"].strip()
                not in group_names
            ):
                data = {
                    "name": action_dict.get("parameters")["new_group_name"].strip(),
                    "type": action_dict.get("parameters")["new_group_type"],
                    "tags": {
                        "data": [
                            {"name": TAG_NAME},
                        ]
                    },
                }
                response = self._api_calls(
                    requests.post(
                        create_group_api,
                        headers=add_user_agent(headers),
                        json=data,
                        proxies=self.proxy,
                        verify=self.ssl_validation,
                    )
                )
                if (
                    response.json()["status"] == "Success"
                    and "data" in response.json()
                    and "name" in response.json()["data"]
                    and "id" in response.json()["data"]
                ):
                    action_dict.get("parameters")["group_name"] = response.json()[
                        "data"
                    ]["name"]
                    return response.json()["data"]["id"]
                else:
                    self.logger.error(
                        f"{self.log_prefix}: Error while creating a group. "
                        f"Error: {response.json()['message']}"
                    )
            else:
                return group_names[action_dict.get("parameters")["new_group_name"]]

    def prepare_payload(self, indicator, existing_group_id):
        """Prepare payload for request.

        Args:
            indicator (Indicator): given indicators.
            existing_group_id (_type_): group id.

        Returns:
            Dict: return dictionary of data.
        """
        data = {}
        if indicator.type == IndicatorType.URL and 1 <= len(indicator.value) <= 500:
            data["text"] = indicator.value
            data["type"] = "url"
        elif indicator.type == IndicatorType.MD5:
            data["md5"] = indicator.value
            data["type"] = "File"
        elif indicator.type == IndicatorType.SHA256:
            data["sha256"] = indicator.value
            data["type"] = "File"
        data["associatedGroups"] = {
            "data": [
                {
                    "id": existing_group_id,
                }
            ]
        }
        data["tags"] = {"data": [{"name": TAG_NAME}]}
        data["rating"] = SEVERITY_TO_RATING[indicator.severity]
        data["confidence"] = indicator.reputation * 10
        return data

    def update_ioc(self, value, group_id):
        """Update IoCs metadata for mutiple groups.

        Args:
            value (str): value of IoC
            group_id (str): group id

        Returns:
            Response: return Response object.
        """
        api_path = f"/api/v3/indicators/{value}"
        url = self.configuration["base_url"] + api_path
        headers = self._get_headers_for_auth(
            api_path,
            self.configuration["access_id"],
            self.configuration["secret_key"],
            "PUT",
        )
        update_data = {
            "associatedGroups": {
                "data": [
                    {"id": group_id},
                ],
                "mode": "append",
            },
        }
        response = self._api_calls(
            requests.put(
                url,
                headers=add_user_agent(headers),
                json=update_data,
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
        )
        return response

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push Indicators to ThreatConnect Platform.

        Args:
            indicators (List[Indicator]): List of Indicators to push.
            action_dict (Dict): action dictionary for performing actions.

        Returns:
            PushResult: return PushResult object with success and message
            parameters.
        """
        existing_group_id = self.get_group_id(action_dict)
        api_path = "/api/v3/indicators"
        query_endpoint = self.configuration["base_url"] + api_path
        invalid_ioc = 0
        already_exists = 0
        for indicator in indicators:
            if indicator.type == IndicatorType.URL and len(indicator.value) > 500:
                invalid_ioc += 1
                continue
            data = self.prepare_payload(indicator, existing_group_id)
            headers = self._get_headers_for_auth(
                api_path,
                self.configuration["access_id"],
                self.configuration["secret_key"],
                "POST",
            )
            response = self._api_calls(
                requests.post(
                    query_endpoint,
                    headers=add_user_agent(headers),
                    json=data,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                )
            )
            if (
                response.json()["status"] == "Success"
                and response.json()["message"] == "Created"
            ):
                continue
            elif response.json()["message"].endswith("already exists"):
                response = self.update_ioc(
                    indicator.value.upper(),
                    data["associatedGroups"]["data"][0]["id"],
                )
                if response.json()["status"] == "Success":
                    already_exists += 1
                else:
                    self.logger.error(
                        f"{self.log_prefix}: Error while updating indicator metadata. "
                        f"Error: {response.json()['message']}."
                    )
            elif (
                response.json()["message"].startswith("Please enter a valid")
                or response.json()["message"] == "This Indicator is contained on a "
                "system-wide exclusion list."
            ):
                invalid_ioc += 1
            else:
                self.logger.error(
                    f"{self.log_prefix}: Error while pushing IoCs to ThreatConnect. "
                    f"Error: {response.json()['message']}."
                )
                return PushResult(
                    success=False,
                    message="Error while pushing IoCs to ThreatConnect.",
                )
        if invalid_ioc != 0:
            self.logger.error(
                f"{self.log_prefix}: Skipping {invalid_ioc} invalid IoCs while pushing to "
                f"ThreatConnect."
            )
        if already_exists != 0:
            self.logger.warn(
                f"{self.log_prefix}: Updated {already_exists} IoC(s) on ThreatConnect."
            )
        return PushResult(
            success=True,
            message="Indicators pushed successfully to ThreatConnect.",
        )

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available Actions.

        Returns:
            List[ActionWithoutParams]: Return list of actions.
        """
        return [ActionWithoutParams(label="Add to Group", value="add_to_group")]

    def get_owner(self):
        """Get owner information from given API credentials.

        Returns:
            str: Name of owner.
        """
        api_path = "/api/v2/owners/mine"
        headers = self._get_headers_for_auth(
            api_path,
            self.configuration["access_id"],
            self.configuration["secret_key"],
            "GET",
        )
        endpoint = self.configuration["base_url"] + api_path

        # Fetching owner_name
        response = self._api_calls(
            requests.get(
                endpoint,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
        )
        if (
            response.json()["status"] == "Success"
            and "data" in response.json()
            and "owner" in response.json()["data"]
            and "name" in response.json()["data"]["owner"]
        ):
            return response.json()["data"]["owner"]["name"]

        # Owner not able to fetch.
        self.logger.error(
            f"{self.log_prefix}: Error while fetching owner information. "
            f"Error: {response.json()['message']}."
        )
        return None

    def get_group_names(self) -> Dict:
        """Get names of available group along with id.

        Returns:
            Dict: dictionary of group name as key and group id as value.
        """
        owner_name = self.get_owner()
        if owner_name:
            query = urllib.parse.quote(f"ownerName == '{owner_name}'")
            api_path = f"/api/v3/groups?tql={query}&resultLimit={LIMIT}"
            url = self.configuration.get("base_url") + api_path
            group_names = {}

            while True:
                headers = self._get_headers_for_auth(
                    api_path,
                    self.configuration["access_id"],
                    self.configuration["secret_key"],
                    "GET",
                )

                # Fetching group Name based on owner name.
                response = self._api_calls(
                    requests.get(
                        url,
                        headers=add_user_agent(headers),
                        proxies=self.proxy,
                        verify=self.ssl_validation,
                    )
                )
                if response.json()["status"] == "Success":
                    for group_info in response.json()["data"]:
                        if (
                            "name" in group_info
                            and "id" in group_info
                            and group_info["name"] not in group_names
                        ):
                            group_names[group_info["name"]] = group_info["id"]

                    if response.json().get("next", None):
                        api_path = (
                            response.json()
                            .get("next")
                            .replace(self.configuration["base_url"], "")
                        )
                        url = response.json().get("next")
                    else:
                        return group_names
                else:
                    # Groups not able to fetch.
                    self.logger.error(
                        f"{self.log_prefix}: Error while fetching group details. "
                        f"Error: {response.json()['message']}."
                    )
                    break

    def get_action_fields(self, action: Action) -> List[Dict]:
        """Get action fields for a given action.

        Args:
            action (Action): Given action.

        Returns:
            List[Dict]: List of configuration parameters for a given action.
        """
        if action.value == "add_to_group":
            group_names = dict(sorted(self.get_group_names().items()))
            group_types = [
                "Adversary",
                "Attack Pattern",
                "Campaign",
                "Course of Action",
                "Email",
                "Event",
                "Incident",
                "Intrusion Set",
                "Malware",
                "Tactic",
                "Task",
                "Threat",
                "Tool",
                "Vulnerability",
            ]  # Document, Report, Signature not supported.
            return [
                {
                    "label": "Add to Existing Group.",
                    "key": "group_name",
                    "type": "choice",
                    "choices": [
                        {"key": group_name, "value": group_id}
                        for group_name, group_id in group_names.items()
                    ]
                    + [{"key": "Create New Group", "value": "create_group"}],
                    "mandatory": True,
                    "description": "Available groups.",
                },
                {
                    "label": "Name of New Group (only applicable for Create "
                    "New Group).",
                    "key": "new_group_name",
                    "type": "text",
                    "mandatory": False,
                    "default": "",
                    "description": "Name of  new group in which you want to "
                    "add all your IoCs.",
                },
                {
                    "label": "Type of New Group (only applicable for Create "
                    "New Group).",
                    "key": "new_group_type",
                    "type": "choice",
                    "choices": [
                        {"key": group_type, "value": group_type}
                        for group_type in group_types
                    ],
                    "mandatory": False,
                    "default": "Incident",
                    "description": "Select group type for new group.",
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action configuration.

        Returns:
            ValidationResult: Valid configuration or not for action.
        """
        if action.value not in ["add_to_group"]:
            return ValidationResult(success=False, message="Invalid Action Provided.")
        if (
            action.value in ["add_to_group"]
            and action.parameters["group_name"] == "create_group"
            and action.parameters["new_group_name"].strip() == ""
        ):
            return ValidationResult(
                success=False, message="Invalid Name of New Group provided."
            )
        return ValidationResult(
            success=True,
            message="Action configuration validated.",
        )
