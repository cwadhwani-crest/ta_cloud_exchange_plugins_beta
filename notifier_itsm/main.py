"""
BSD 3-Clause License

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
"""

"""Notifier CTO plugin."""


import json
import os
import traceback
import uuid
from typing import List, Dict, Tuple
from functools import partial
import requests

from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)
from netskope.integrations.itsm.models import (
    FieldMapping,
    Queue,
    Task,
    Alert,
    TaskStatus,
)

from .lib.notifiers import get_notifier
from .lib.notifiers.exceptions import BadArguments
from .lib.notifiers.utils import requests as notifier_requests


MAPPED_FIELDS = {
    "email": ["message", "subject", "to_"],
    "gitter": ["message"],
    "gmail": ["message", "subject", "to_"],
    "hipchat": ["message"],
    "join": ["message", "clipboard", "title"],
    "mailgun": ["message", "html", "subject"],
    "pagerduty": ["message"],
    "popcornnotify": ["message", "subject"],
    "pushbullet": ["message", "title", "url"],
    "pushover": ["message", "title", "url", "url_title"],
    "simplepush": ["message", "title"],
    "slack": ["message"],
    "statuspage": ["message", "body"],
    "telegram": ["message"],
    "twilio": ["message"],
    "zulip": ["message", "subject"],
}


PASSWORD_FIELDS = {
    "email": ["password"],
    "gitter": ["token"],
    "gmail": ["password"],
    "hipchat": ["token"],
    "join": ["apikey"],
    "mailgun": ["api_key"],
    "pagerduty": ["routing_key"],
    "popcornnotify": ["api_key"],
    "pushbullet": ["token"],
    "pushover": ["token"],
    "simplepush": ["key"],
    "slack": [],
    "statuspage": ["api_key"],
    "telegram": ["token"],
    "twilio": ["auth_token"],
    "zulip": ["api_key"],
}

EXCLUDED_FIELDS = {
    "email": ["attachments"],
    "gitter": [],
    "gmail": ["attachments"],
    "hipchat": [],
    "join": [],
    "mailgun": ["attachment"],
    "pagerduty": [],
    "popcornnotify": [],
    "pushbullet": ["type_"],
    "pushover": ["attachment"],
    "simplepush": [],
    "slack": [],
    "statuspage": [],
    "telegram": [],
    "twilio": [],
    "zulip": [],
}

MODULE_NAME = "CTO"
PLUGIN_NAME = "Notifier"
PLUGIN_VERSION = "1.1.0"


class NotifierPlugin(PluginBase):
    """Jira plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Notifier plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"Debug: {MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> Tuple:
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
                plugin_name = manifest_json.get("name", PLUGIN_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_notifier(self, configuration):
        """Get notifier object from configuration."""
        platform = configuration.get("platform").get("name")
        self.logger.info(f"{self.log_prefix}: Inside get notifier method.")
        notifier = get_notifier(platform)
        self.logger.info(f'{self.log_prefix}: Notifier object "{notifier}"')
        if notifier is None:
            self.logger.error(
                f"{self.log_prefix}: Notifier value is {notifier} i.e. Notifier not found."
            )
            raise ValueError("Notifier not found.")
        return notifier

    def _remove_empties(self, data):
        """Remove empty values from dictionary."""
        self.logger.info(
            f"{self.log_prefix}: Inside removed empties method. Data: {data}"
        )
        new_dict = {}
        for key, value in data.items():
            if type(value) is str:
                if value.strip() != "":
                    new_dict[key] = value
            elif type(value) in [int, bool]:
                new_dict[key] = value
        self.logger.info(
            f"{self.log_prefix}: Successfully removed empty values from data. Final data: {new_dict}"
        )
        return new_dict

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an issue/ticket on Jira platform."""
        self.logger.info(f"{self.log_prefix}: Inside create task method.")
        notifier = self._get_notifier(self.configuration)
        self.logger.info(
            "{}: Successfully fetch notifier object. {}".format(
                self.log_prefix, notifier
            )
        )
        params = {**self.configuration.get("params"), **mappings}
        self.logger.info(f"{self.log_prefix}: Params: {params}")
        filtered_args = self._get_args_from_params(params)
        self.logger.info(f"{self.log_prefix}: filtered args: {filtered_args}")
        notifier_requests.get = partial(
            notifier_requests.get, proxies=self.proxy
        )
        self.logger.info(
            f"{self.log_prefix}: Notifier_request.get {notifier_requests.get}"
        )
        notifier_requests.post = partial(
            notifier_requests.post, proxies=self.proxy
        )
        self.logger.info(
            "{}: Notifier_request.post {}".format(
                self.log_prefix, notifier_requests.post
            )
        )
        requests.get = partial(requests.get, proxies=self.proxy)
        requests.post = partial(requests.post, proxies=self.proxy)
        self.logger.info(f"{self.log_prefix}: Calling notify method.")
        response = notifier.notify(
            **filtered_args, logger=self.logger, log_prefix=self.log_prefix
        )
        self.logger.info(
            f"{self.log_prefix}: Response for notify method: {response}"
        )
        response.raise_on_errors()
        if response.ok:
            self.logger.info(
                f"{self.log_prefix}: Ticket created successfully."
            )
            return Task(id=uuid.uuid4().hex, status=TaskStatus.NOTIFICATION)

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync all task states."""
        self.logger.info(f"{self.log_prefix}: Sync state task triggered.")
        return tasks

    def update_task(
        self, task: Task, alert: Alert, mappings: Dict, queue: Queue
    ) -> Task:
        """Add a comment in existing Jira issue."""
        self.logger.info(f"{self.log_prefix}: Update task triggered.")
        return task

    def _get_args_from_params(self, params: dict) -> dict:
        """Get dictionary that can be unpacked and used as argument."""
        self.logger.info(
            f"{self.log_prefix}: Inside _get_args_from_params. Params: {params}."
        )
        new_dict = {}
        for key, value in params.items():
            if value == "boolean_true":
                new_dict[key] = True
            elif value == "boolean_false":
                new_dict[key] = False
            else:
                new_dict[key] = value
        self.logger.info(
            "{}: Calling _remove_empties with new dict: {}".format(
                self.log_prefix, new_dict
            )
        )
        return self._remove_empties(new_dict)

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step."""
        self.logger.info(
            "{}: Inside validate step method. Name: {} "
            "Configuration: {}".format(self.log_prefix, name, configuration)
        )
        if name != "params":
            self.logger.info(
                "{}: name {} is params hence returning "
                "validation success".format(self.log_prefix, name)
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )

        platform = configuration.get("platform").get("name")
        self.logger.info(f"{self.log_prefix}: Calling get_notifier method.")
        notifier = self._get_notifier(configuration)
        self.logger.info(
            f"{self.log_prefix}: Successfully got notifier object. {notifier}."
        )
        mapped_fields = {key: "" for key in MAPPED_FIELDS.get(platform, [])}
        self.logger.info(f"{self.log_prefix}: Mapped fields: {mapped_fields}")
        self.logger.info(f"{self.log_prefix}: Calling _get_args_from_params")
        args = self._get_args_from_params(configuration.get("params", {}))
        self.logger.info(
            "{}: args returned by _get_args_from_params method. {}".format(
                self.log_prefix, args
            )
        )
        args = {**args, **mapped_fields}
        self.logger.info(f"{self.log_prefix}: Final args {args}")
        try:
            self.logger.info(
                "{}: Calling notifier.validate_data with args: {}".format(
                    self.log_prefix, args
                )
            )
            notifier._validate_data(args)
        except BadArguments as ex:
            self.logger.error(
                message="{}: Received Bad Arguments error. Error: {}".format(
                    self.log_prefix, ex
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=ex.message)
        return ValidationResult(success=True, message="Validation successful.")

    def get_available_fields(self, configuration: dict) -> List[MappingField]:
        """Get list of all the mappable fields."""
        self.logger.info(
            f"{self.log_prefix}: Inside get_available_fields method."
        )
        platform = configuration.get("platform").get("name")
        self.logger.info(
            "{}: Calling _get_notifier method with configuration: {}".format(
                self.log_prefix, configuration
            )
        )
        notifier = self._get_notifier(configuration)
        args = notifier.arguments
        fields = []
        keys = set()
        for key, val in args.items():
            if val.get("duplicate", False):
                continue
            if key in keys:
                continue
            if key not in MAPPED_FIELDS.get(platform, []):
                continue
            keys.add(key)
            fields.append(
                MappingField(label=" ".join(key.split("_")).title(), value=key)
            )
        self.logger.info(f"{self.log_prefix}: Final fields: {fields}")
        return fields

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings."""
        platform = configuration.get("platform").get("name")
        mapping = {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    custom_message="$user",
                    destination_field=field,
                )
                if field == "to_"
                else FieldMapping(
                    extracted_field="custom_message",
                    custom_message="",
                    destination_field=field,
                )
                for field in MAPPED_FIELDS.get(platform, [])
            ],
            "dedup": [],
        }
        self.logger.info(
            "{}: Mappings returned by get_default_mappings {}".format(
                self.log_prefix, mapping
            )
        )
        return mapping

    def get_fields(self, name: str, configuration: dict):
        """Get available fields."""
        self.logger.info(
            "{}: Inside get_fields method with configuration: {}".format(
                self.log_prefix, configuration
            )
        )
        if name == "params":
            platform = configuration.get("platform").get("name")
            self.logger.info(
                "{}: Calling _get_notifier with configuration: {}".format(
                    self.log_prefix, configuration
                )
            )
            notifier = self._get_notifier(configuration)
            args = notifier.arguments
            fields = []
            keys = set()
            for key, val in args.items():
                if val.get("duplicate", False):
                    continue
                if key in keys:
                    continue
                if key in MAPPED_FIELDS.get(
                    platform, []
                ) or key in EXCLUDED_FIELDS.get(platform, []):
                    continue
                keys.add(key)
                if val.get("type") == "string":
                    if "enum" in val:
                        field = {
                            "label": " ".join(key.split("_")).title(),
                            "key": key,
                            "type": "choice",
                            "description": f"({key}) {val.get('title', '')}",
                            "choices": [
                                {"key": key.title(), "value": key}
                                for key in val.get("enum", [])
                            ],
                            "default": val.get("enum")[0]
                            if val.get("enum", [])
                            else "",
                        }
                    else:
                        field = {
                            "label": " ".join(key.split("_")).title(),
                            "key": key,
                            "type": "password"
                            if key in PASSWORD_FIELDS.get(platform, [])
                            else "text",
                            "description": f"({key}) {val.get('title', '')}",
                        }
                    fields.append(field)
                elif val.get("type") == "integer":
                    field = {
                        "label": " ".join(key.split("_")).title(),
                        "key": key,
                        "type": "number",
                        "description": f"({key}) {val.get('title', '')}",
                    }
                    fields.append(field)
                elif val.get("oneOf") is not None:
                    string_fields = list(
                        filter(
                            lambda x: x.get("type") == "string",
                            val.get("oneOf", []),
                        )
                    )
                    if not string_fields:
                        continue
                    string_field = string_fields.pop()
                    fields.append(
                        {
                            "label": " ".join(key.split("_")).title(),
                            "key": key,
                            "type": "text",
                            "description": f"({key}) {string_field.get('title', '')}",
                        }
                    )
                elif val.get("type") == "boolean":
                    field = {
                        "label": " ".join(key.split("_")).title(),
                        "key": key,
                        "type": "choice",
                        "choices": [
                            {"key": "Yes", "value": "boolean_true"},
                            {"key": "No", "value": "boolean_false"},
                        ],
                        "default": "boolean_true",
                        "description": f"({key}) {val.get('title', '')}",
                    }
                    fields.append(field)
            self.logger.info(
                "{}: Fields to be return by get_fields are fields {}".format(
                    self.log_prefix, fields
                )
            )
            return fields
        else:
            raise NotImplementedError()

    def get_queues(self) -> List[Queue]:
        """Get list of Jira projects as queues."""
        return [Queue(label="Notification", value="notification")]
