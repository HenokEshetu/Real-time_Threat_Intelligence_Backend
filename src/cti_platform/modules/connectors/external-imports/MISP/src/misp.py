#!/usr/bin/env python3
"""
Modernized MISP Connector for OpenCTI.

Improvements:
- Uses yaml.safe_load for secure YAML loading.
- Uses modern f-string formatting and type hints.
- Replaces deprecated datetime.utcfromtimestamp with datetime.fromtimestamp(..., tz=pytz.UTC).
- Modularizes functionality for easier maintenance.
"""

import json
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytz
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    AttackPattern,
    CustomObservableHostname,
    CustomObservablePhoneNumber,
    CustomObservableText,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    Note,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    StixSightingRelationship,
    Tool,
    get_config_variable,
)
from pymisp import PyMISP

PATTERNTYPES = ["yara", "sigma", "pcre", "snort", "suricata"]

OPENCTISTIX2 = {
    "autonomous-system": {
        "type": "autonomous-system",
        "path": ["number"],
        "transform": {"operation": "remove_string", "value": "AS"},
    },
    "mac-addr": {"type": "mac-addr", "path": ["value"]},
    "hostname": {"type": "hostname", "path": ["value"]},
    "domain": {"type": "domain-name", "path": ["value"]},
    "ipv4-addr": {"type": "ipv4-addr", "path": ["value"]},
    "ipv6-addr": {"type": "ipv6-addr", "path": ["value"]},
    "url": {"type": "url", "path": ["value"]},
    "link": {"type": "url", "path": ["value"]},
    "email-address": {"type": "email-addr", "path": ["value"]},
    "email-subject": {"type": "email-message", "path": ["subject"]},
    "mutex": {"type": "mutex", "path": ["name"]},
    "file-name": {"type": "file", "path": ["name"]},
    "file-path": {"type": "file", "path": ["name"]},
    "file-md5": {"type": "file", "path": ["hashes", "MD5"]},
    "file-sha1": {"type": "file", "path": ["hashes", "SHA-1"]},
    "file-sha256": {"type": "file", "path": ["hashes", "SHA-256"]},
    "directory": {"type": "directory", "path": ["path"]},
    "registry-key": {"type": "windows-registry-key", "path": ["key"]},
    "registry-key-value": {"type": "windows-registry-value-type", "path": ["data"]},
    "pdb-path": {"type": "file", "path": ["name"]},
    "x509-certificate-issuer": {"type": "x509-certificate", "path": ["issuer"]},
    "x509-certificate-serial-number": {
        "type": "x509-certificate",
        "path": ["serial_number"],
    },
    "text": {"type": "text", "path": ["value"]},
    "user-agent": {"type": "user-agent", "path": ["value"]},
    "phone-number": {"type": "phone-number", "path": ["value"]},
    "user-account": {"type": "user-account", "path": ["account_login"]},
    "user-account-github": {
        "type": "user-account",
        "path": ["account_login"],
        "account_type": "github",
    },
    "identity-individual": {"type": "identity", "identity_class": "individual"},
}

FILETYPES = ["file-name", "file-md5", "file-sha1", "file-sha256"]


def is_uuid(val: Any) -> bool:
    """Return True if the given value is a valid UUID."""
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def filter_event_attributes(event: Dict, **filters) -> Optional[List]:
    """Filter event attributes based on provided key-value pairs."""
    if not filters:
        return None
    return [
        attribute
        for attribute in event["Event"]["Attribute"]
        if all(attribute.get(key) == value for key, value in filters.items())
    ]


def parse_filter_config(config: Optional[str]) -> Dict:
    """Parse a configuration string into a dictionary of filters."""
    filters = {}
    if not config:
        return filters
    for item in config.split(","):
        key, value = item.split("=")
        filters[key.strip()] = value.strip()
    return filters


class Misp:
    def __init__(self) -> None:
        """Initialize the MISP connector and load configuration."""
        config_path = Path(__file__).resolve().parent / "config.yml"
        if config_path.is_file():
            with config_path.open("r") as cf:
                config = yaml.safe_load(cf)
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config)
        self.misp_url = get_config_variable("MISP_URL", ["misp", "url"], config)
        self.misp_reference_url = get_config_variable(
            "MISP_REFERENCE_URL", ["misp", "reference_url"], config
        )
        self.misp_key = get_config_variable("MISP_KEY", ["misp", "key"], config)
        self.misp_ssl_verify = get_config_variable(
            "MISP_SSL_VERIFY", ["misp", "ssl_verify"], config
        )
        self.misp_client_cert = get_config_variable(
            "MISP_CLIENT_CERT", ["misp", "client_cert"], config
        )
        self.misp_datetime_attribute = get_config_variable(
            "MISP_DATETIME_ATTRIBUTE",
            ["misp", "datetime_attribute"],
            config,
            default="timestamp",
        )
        self.misp_filter_date_attribute = get_config_variable(
            "MISP_DATE_FILTER_FIELD",
            ["misp", "date_filter_field"],
            config,
            default="timestamp",
        )
        self.misp_report_description_attribute_filter = parse_filter_config(
            get_config_variable(
                "MISP_REPORT_DESCRIPTION_ATTRIBUTE_FILTER",
                ["misp", "report_description_attribute_filter"],
                config,
            )
        )
        self.misp_create_reports = get_config_variable(
            "MISP_CREATE_REPORTS", ["misp", "create_reports"], config
        )
        self.misp_create_indicators = get_config_variable(
            "MISP_CREATE_INDICATORS", ["misp", "create_indicators"], config
        )
        self.misp_create_observables = get_config_variable(
            "MISP_CREATE_OBSERVABLES", ["misp", "create_observables"], config
        )
        self.misp_create_object_observables = get_config_variable(
            "MISP_CREATE_OBJECT_OBSERVABLES",
            ["misp", "create_object_observables"],
            config,
            default=False,
        )
        self.misp_create_tags_as_labels = get_config_variable(
            "MISP_CREATE_TAGS_AS_LABELS",
            ["misp", "create_tags_as_labels"],
            config,
            default=True,
        )
        self.misp_guess_threats_from_tags = get_config_variable(
            "MISP_GUESS_THREAT_FROM_TAGS",
            ["misp", "guess_threats_from_tags"],
            config,
            default=False,
        )
        self.misp_author_from_tags = get_config_variable(
            "MISP_AUTHOR_FROM_TAGS", ["misp", "author_from_tags"], config, default=False
        )
        self.misp_markings_from_tags = get_config_variable(
            "MISP_MARKINGS_FROM_TAGS",
            ["misp", "markings_from_tags"],
            config,
            default=False,
        )
        self.keep_original_tags_as_label = get_config_variable(
            "MISP_KEEP_ORIGINAL_TAGS_AS_LABEL",
            ["misp", "keep_original_tags_as_label"],
            config,
            default="",
        ).split(",")
        self.helper.log_info(
            f"keep_original_tags_as_label: {self.keep_original_tags_as_label}"
        )
        self.misp_enforce_warning_list = get_config_variable(
            "MISP_ENFORCE_WARNING_LIST",
            ["misp", "enforce_warning_list"],
            config,
            default=False,
        )
        self.misp_report_type = get_config_variable(
            "MISP_REPORT_TYPE", ["misp", "report_type"], config, False, "misp-event"
        )
        self.misp_import_from_date = get_config_variable(
            "MISP_IMPORT_FROM_DATE", ["misp", "import_from_date"], config
        )
        self.misp_import_tags = get_config_variable(
            "MISP_IMPORT_TAGS", ["misp", "import_tags"], config
        )
        self.misp_import_tags_not = get_config_variable(
            "MISP_IMPORT_TAGS_NOT", ["misp", "import_tags_not"], config
        )
        self.misp_import_creator_orgs = get_config_variable(
            "MISP_IMPORT_CREATOR_ORGS", ["misp", "import_creator_orgs"], config
        )
        self.misp_import_creator_orgs_not = get_config_variable(
            "MISP_IMPORT_CREATOR_ORGS_NOT", ["misp", "import_creator_orgs_not"], config
        )
        self.misp_import_owner_orgs = get_config_variable(
            "MISP_IMPORT_OWNER_ORGS", ["misp", "import_owner_orgs"], config
        )
        self.misp_import_owner_orgs_not = get_config_variable(
            "MISP_IMPORT_OWNER_ORGS_NOT", ["misp", "import_owner_orgs_not"], config
        )
        self.misp_import_keyword = get_config_variable(
            "MISP_IMPORT_KEYWORD", ["misp", "MISP_IMPORT_KEYWORD"], config
        )
        self.import_distribution_levels = get_config_variable(
            "MISP_IMPORT_DISTRIBUTION_LEVELS",
            ["misp", "import_distribution_levels"],
            config,
        )
        self.import_threat_levels = get_config_variable(
            "MISP_IMPORT_THREAT_LEVELS", ["misp", "import_threat_levels"], config
        )
        self.import_only_published = get_config_variable(
            "MISP_IMPORT_ONLY_PUBLISHED", ["misp", "import_only_published"], config
        )
        self.import_with_attachments = bool(
            get_config_variable(
                "MISP_IMPORT_WITH_ATTACHMENTS",
                ["misp", "import_with_attachments"],
                config,
                isNumber=False,
                default=False,
            )
        )
        self.import_to_ids_no_score = get_config_variable(
            "MISP_IMPORT_TO_IDS_NO_SCORE",
            ["misp", "import_to_ids_no_score"],
            config,
            isNumber=True,
        )
        self.import_unsupported_observables_as_text = bool(
            get_config_variable(
                "MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT",
                ["misp", "import_unsupported_observables_as_text"],
                config,
                isNumber=False,
                default=False,
            )
        )
        self.import_unsupported_observables_as_text_transparent = bool(
            get_config_variable(
                "MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT",
                ["misp", "import_unsupported_observables_as_text_transparent"],
                config,
                isNumber=False,
                default=True,
            )
        )
        self.misp_interval = get_config_variable(
            "MISP_INTERVAL", ["misp", "interval"], config, isNumber=True
        )

        self.misp = PyMISP(
            url=self.misp_url,
            key=self.misp_key,
            cert=self.misp_client_cert,
            ssl=self.misp_ssl_verify,
            debug=False,
            tool="OpenCTI MISP connector",
        )

    def get_interval(self) -> int:
        """Return the run interval in seconds."""
        return int(self.misp_interval) * 60

    def run(self) -> None:
        """Main run loop for the connector."""
        while True:
            now = datetime.now(pytz.UTC)
            friendly_name = f"MISP run @ {now.astimezone(pytz.UTC).isoformat()}"
            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            last_run, last_event, last_event_timestamp = self._determine_last_run(
                current_state, now
            )
            self.helper.log_info(f"Connector last run: {last_run.isoformat()}")
            self.helper.log_info(f"Connector latest event: {last_event.isoformat()}")

            complex_query_tag = self._build_complex_query()
            next_event_timestamp = last_event_timestamp + 1
            query_params: Dict[str, Any] = {
                self.misp_filter_date_attribute: next_event_timestamp
            }
            if complex_query_tag:
                query_params["tags"] = complex_query_tag
            if self.import_with_attachments:
                query_params["with_attachments"] = self.import_with_attachments
            if self.misp_import_keyword:
                query_params["value"] = self.misp_import_keyword
                query_params["searchall"] = True
            if self.misp_enforce_warning_list:
                query_params["enforce_warninglist"] = self.misp_enforce_warning_list

            current_page = current_state.get("current_page", 1) if current_state else 1
            total_events = 0

            while True:
                query_params["limit"] = 10
                query_params["page"] = current_page
                self.helper.log_info(
                    f"Fetching MISP events with args: {json.dumps(query_params)}"
                )
                try:
                    events = self.misp.search("events", **query_params)
                    if isinstance(events, dict) and events.get("errors"):
                        raise ValueError(events.get("message"))
                except Exception as e:
                    self.helper.log_error(f"Error fetching MISP event: {e}")
                    self.helper.metric.inc("client_error_count")
                    break

                num_events = len(events)
                self.helper.log_info(f"MISP returned {num_events} events.")
                total_events += num_events
                if num_events == 0:
                    break

                processed_ts = self.process_events(work_id, events)
                if processed_ts and processed_ts > last_event_timestamp:
                    last_event_timestamp = processed_ts

                current_page += 1
                current_state = current_state or {}
                current_state["current_page"] = current_page
                self.helper.set_state(current_state)

            state_payload = {
                "last_run": now.astimezone(pytz.UTC).isoformat(),
                "last_event": datetime.fromtimestamp(
                    last_event_timestamp, tz=pytz.UTC
                ).isoformat(),
                "last_event_timestamp": last_event_timestamp,
                "current_page": 1,
            }
            self.helper.set_state(state_payload)
            msg = (
                f"Connector successfully run ({total_events} events processed), storing state "
                f"(last_run={state_payload['last_run']}, last_event={state_payload['last_event']}, "
                f"last_event_timestamp={last_event_timestamp}, current_page=1)"
            )
            self.helper.log_info(msg)
            self.helper.api.work.to_processed(work_id, msg)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.metric.state("stopped")
                self.helper.force_ping()
                sys.exit(0)

            self.helper.metric.state("idle")
            time.sleep(self.get_interval())

    def _determine_last_run(
        self, current_state: Optional[Dict], now: datetime
    ) -> Tuple[datetime, datetime, int]:
        """Determine the last run and event timestamp from stored state."""
        if current_state and "last_run" in current_state:
            last_run = parse(current_state["last_run"])
            last_event = parse(
                current_state.get("last_event", current_state["last_run"])
            )
            last_event_timestamp = current_state.get(
                "last_event_timestamp", int(last_event.timestamp())
            )
        else:
            last_event = (
                parse(self.misp_import_from_date) if self.misp_import_from_date else now
            )
            last_run = now
            last_event_timestamp = int(last_event.timestamp())
            self.helper.log_info("Connector has never run")
        return last_run, last_event, last_event_timestamp

    def _build_complex_query(self) -> Optional[str]:
        """Build a complex query for tags if configured."""
        if self.misp_import_tags or self.misp_import_tags_not:
            or_parameters = [
                tag.strip()
                for tag in (self.misp_import_tags or "").split(",")
                if tag.strip()
            ]
            not_parameters = [
                ntag.strip()
                for ntag in (self.misp_import_tags_not or "").split(",")
                if ntag.strip()
            ]
            return self.misp.build_complex_query(
                or_parameters=or_parameters if or_parameters else None,
                not_parameters=not_parameters if not_parameters else None,
            )
        return None

    def process_events(self, work_id: str, events: List[Dict]) -> Optional[int]:
        """
        Process a list of events from MISP.
        Returns the latest event timestamp encountered.
        """
        creator_orgs = (
            self.misp_import_creator_orgs.split(",")
            if self.misp_import_creator_orgs
            else None
        )
        creator_orgs_not = (
            self.misp_import_creator_orgs_not.split(",")
            if self.misp_import_creator_orgs_not
            else None
        )
        owner_orgs = (
            self.misp_import_owner_orgs.split(",")
            if self.misp_import_owner_orgs
            else None
        )
        owner_orgs_not = (
            self.misp_import_owner_orgs_not.split(",")
            if self.misp_import_owner_orgs_not
            else None
        )
        distribution_levels = (
            self.import_distribution_levels.split(",")
            if self.import_distribution_levels
            else None
        )
        threat_levels = (
            self.import_threat_levels.split(",") if self.import_threat_levels else None
        )

        last_event_timestamp = None

        for event in events:
            event_uuid = event["Event"]["uuid"]
            self.helper.log_info(f"Processing event {event_uuid}")
            event_ts = int(event["Event"][self.misp_datetime_attribute])
            last_event_timestamp = (
                event_ts
                if last_event_timestamp is None or event_ts > last_event_timestamp
                else last_event_timestamp
            )

            if creator_orgs and event["Event"]["Orgc"]["name"] not in creator_orgs:
                self.helper.log_info(
                    f"Skipping event; creator org {event['Event']['Orgc']['name']} not allowed"
                )
                continue
            if creator_orgs_not and event["Event"]["Orgc"]["name"] in creator_orgs_not:
                self.helper.log_info(
                    f"Skipping event; creator org {event['Event']['Orgc']['name']} excluded"
                )
                continue
            if owner_orgs and event["Event"]["Org"]["name"] not in owner_orgs:
                self.helper.log_info(
                    f"Skipping event; owner org {event['Event']['Org']['name']} not allowed"
                )
                continue
            if owner_orgs_not and event["Event"]["Org"]["name"] in owner_orgs_not:
                self.helper.log_info(
                    f"Skipping event; owner org {event['Event']['Org']['name']} excluded"
                )
                continue
            if (
                distribution_levels
                and event["Event"]["distribution"] not in distribution_levels
            ):
                self.helper.log_info(
                    f"Skipping event; distribution {event['Event']['distribution']} not allowed"
                )
                continue
            if threat_levels and event["Event"]["threat_level_id"] not in threat_levels:
                self.helper.log_info(
                    f"Skipping event; threat level {event['Event']['threat_level_id']} not allowed"
                )
                continue
            if self.import_only_published and not event["Event"]["published"]:
                self.helper.log_info("Skipping event; not published")
                continue

            self._process_single_event(event)

        return last_event_timestamp

    def _process_single_event(self, event: Dict) -> None:
        """
        Process a single event from MISP.
        Extracts indicators, observables, relationships, and bundles them into a STIX2 bundle.
        """
        author = self._extract_author(event)
        event_tags = self._resolve_tags(event.get("Event", {}).get("Tag", []))
        event_markings = self._resolve_markings(
            event.get("Event", {}).get("Tag", [])
        ) or [stix2.TLP_WHITE]
        event_elements = self.prepare_elements(
            event["Event"].get("Galaxy", []),
            event.get("Event", {}).get("Tag", []),
            author,
            event_markings,
        )
        self.helper.log_info(
            f"Event contains {len(event_elements['intrusion_sets']) + len(event_elements['malwares']) + len(event_elements['tools']) + len(event_elements['attack_patterns'])} related elements"
        )
        external_ref = self._build_external_reference(event)
        external_refs = [external_ref]

        indicators = []
        added_files = []
        for attribute in event["Event"].get("Attribute", []):
            ind = self.process_attribute(
                author,
                event_elements,
                event_markings,
                event_tags,
                None,
                [],
                attribute,
                event["Event"]["threat_level_id"],
                len(event["Event"].get("Attribute", [])) < 10000,
            )
            if (
                attribute["type"] == "link"
                and attribute.get("category") == "External analysis"
            ):
                ext_ref = stix2.ExternalReference(
                    source_name=attribute.get("category"),
                    external_id=attribute.get("uuid"),
                    url=attribute.get("value"),
                )
                external_refs.append(ext_ref)
            if ind:
                indicators.append(ind)
            pdf_file = self._get_pdf_file(attribute)
            if pdf_file:
                added_files.append(pdf_file)

        object_indicators = []
        object_observables = []
        object_relationships = []
        for misp_object in event["Event"].get("Object", []):
            attr_ext_refs = []
            for attribute in misp_object.get("Attribute", []):
                if (
                    attribute["type"] == "link"
                    and attribute.get("category") == "External analysis"
                ):
                    ext_ref = stix2.ExternalReference(
                        source_name=attribute.get("category"),
                        external_id=attribute.get("uuid"),
                        url=attribute.get("value"),
                    )
                    attr_ext_refs.append(ext_ref)
                pdf_file = self._get_pdf_file(attribute)
                if pdf_file:
                    added_files.append(pdf_file)
            obj_observable = None
            if self.misp_create_object_observables and misp_object.get("Attribute"):
                first_attr = misp_object["Attribute"][0]
                obj_observable = CustomObservableText(
                    value=first_attr.get("value"),
                    object_marking_refs=event_markings,
                    custom_properties={
                        "description": misp_object.get("description", ""),
                        "x_opencti_score": self.threat_level_to_score(
                            event["Event"]["threat_level_id"]
                        ),
                        "labels": event_tags,
                        "created_by_ref": author["id"],
                        "external_references": attr_ext_refs,
                    },
                )
                object_observables.append(obj_observable)
            for attribute in misp_object.get("Attribute", []):
                ind = self.process_attribute(
                    author,
                    event_elements,
                    event_markings,
                    event_tags,
                    obj_observable,
                    attr_ext_refs,
                    attribute,
                    event["Event"]["threat_level_id"],
                    len(misp_object.get("Attribute", [])) < 10000,
                )
                if ind:
                    object_indicators.append(ind)
            for obj_ref in misp_object.get("ObjectReference", []):
                src_uuid = obj_ref.get("source_uuid")
                tgt_uuid = obj_ref.get("referenced_uuid")
                comment = obj_ref.get("comment", "")
                rel_type = obj_ref.get("relationship_type", "related-to")
                if src_uuid and tgt_uuid:
                    src_obj = self.find_stix_object_by_uuid(
                        src_uuid,
                        [author] + indicators + object_indicators + object_observables,
                    )
                    tgt_obj = self.find_stix_object_by_uuid(
                        tgt_uuid,
                        [author] + indicators + object_indicators + object_observables,
                    )
                    if src_obj and tgt_obj:
                        rel = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                rel_type, src_obj["id"], tgt_obj["id"]
                            ),
                            relationship_type=rel_type,
                            created_by_ref=author["id"],
                            source_ref=src_obj["id"],
                            target_ref=tgt_obj["id"],
                            description=f"Original Relationship: {rel_type}\nComment: {comment}",
                            allow_custom=True,
                        )
                        object_relationships.append(rel)

        bundle_objects = [author]
        for marking in event_markings:
            if marking not in bundle_objects:
                bundle_objects.append(marking)
        for key in ["intrusion_sets", "malwares", "tools", "attack_patterns"]:
            for obj in event_elements.get(key, []):
                if obj not in bundle_objects:
                    bundle_objects.append(obj)
        for ind in indicators + object_indicators:
            if ind.get("indicator"):
                bundle_objects.append(ind["indicator"])
            if ind.get("observable"):
                bundle_objects.append(ind["observable"])
            for rel in ind.get("relationships", []):
                bundle_objects.append(rel)
        for obs in object_observables:
            bundle_objects.append(obs)
        for rel in object_relationships:
            bundle_objects.append(rel)
        if self.misp_create_reports:
            report = self._create_report(
                event,
                author,
                event_markings,
                event_tags,
                bundle_objects,
                external_refs,
                added_files,
            )
            bundle_objects.append(report)
            for note in event["Event"].get("EventReport", []):
                stix_note = stix2.Note(
                    id=Note.generate_id(
                        datetime.fromtimestamp(
                            int(note["timestamp"]), tz=pytz.UTC
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        self._process_note(note["content"], bundle_objects),
                    ),
                    confidence=self.helper.connect_confidence_level,
                    created=datetime.fromtimestamp(
                        int(note["timestamp"]), tz=pytz.UTC
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    modified=datetime.fromtimestamp(
                        int(note["timestamp"]), tz=pytz.UTC
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    created_by_ref=author["id"],
                    object_marking_refs=event_markings,
                    abstract=note.get("name", ""),
                    content=self._process_note(note["content"], bundle_objects),
                    object_refs=[report.id],
                    allow_custom=True,
                )
                bundle_objects.append(stix_note)

        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.log_info("Sending event STIX2 bundle")
        self.helper.send_stix2_bundle(bundle, work_id="")
        self.helper.metric.inc("record_send", len(bundle_objects))

    def _extract_author(self, event: Dict) -> stix2.Identity:
        """Extract the author identity from event tags or use the event organization."""
        author = None
        if self.misp_author_from_tags and "Tag" in event["Event"]:
            for tag in event["Event"]["Tag"]:
                if tag["name"].startswith("creator") and "=" in tag["name"]:
                    author_name = tag["name"].split("=")[1].strip()
                    author = stix2.Identity(
                        id=Identity.generate_id(author_name, "organization"),
                        name=author_name,
                        identity_class="organization",
                    )
                    break
        if not author:
            author = stix2.Identity(
                id=Identity.generate_id(event["Event"]["Orgc"]["name"], "organization"),
                name=event["Event"]["Orgc"]["name"],
                identity_class="organization",
            )
        return author

    def _build_external_reference(self, event: Dict) -> stix2.ExternalReference:
        """Build an external reference from event details."""
        url_base = self.misp_reference_url if self.misp_reference_url else self.misp_url
        url = f"{url_base}/events/view/{event['Event']['uuid']}"
        return stix2.ExternalReference(
            source_name=self.helper.connect_name,
            description=event["Event"]["info"],
            external_id=event["Event"]["uuid"],
            url=url,
        )

    def _get_pdf_file(self, attribute: Dict) -> Optional[Dict]:
        """Return a PDF file attachment if applicable."""
        if not self.import_with_attachments:
            return None
        if (
            attribute["type"] != "attachment"
            or attribute.get("category") != "External analysis"
        ):
            return None
        if not attribute["value"].lower().endswith(".pdf"):
            return None
        if not attribute.get("data"):
            self.helper.log_error(
                f"No data for attribute: {attribute['uuid']} ({attribute['type']}:{attribute['category']})"
            )
            return None
        self.helper.log_info(
            f"Found PDF '{attribute['value']}' for attribute: {attribute['uuid']}"
        )
        return {
            "name": attribute["value"],
            "data": attribute["data"],
            "mime_type": "application/pdf",
            "no_trigger_import": True,
        }

    def process_attribute(
        self,
        author: stix2.Identity,
        event_elements: Dict,
        event_markings: List,
        event_labels: List,
        object_observable: Any,
        attribute_external_references: List,
        attribute: Dict,
        event_threat_level: Any,
        create_relationships: bool,
    ) -> Optional[Dict]:
        """
        Process a MISP attribute into STIX objects.
        Returns a dictionary containing the indicator, observable, relationships, etc.
        """
        if (
            attribute["type"] in ["link", "attachment"]
            and attribute.get("category") == "External analysis"
        ):
            return None
        resolved_attributes = self.resolve_type(attribute["type"], attribute["value"])
        if not resolved_attributes:
            return None

        file_name = None
        for res_attr in resolved_attributes:
            if res_attr["resolver"] == "file-name":
                file_name = res_attr["value"]

        for res_attr in resolved_attributes:
            attribute_tags = event_labels
            if "Tag" in attribute:
                attribute_markings = self._resolve_markings(
                    attribute["Tag"], with_default=False
                )
                attribute_tags = self._resolve_tags(attribute["Tag"])
                if not attribute_markings:
                    attribute_markings = event_markings
            else:
                attribute_markings = event_markings

            attribute_elements = self.prepare_elements(
                attribute.get("Galaxy", []),
                attribute.get("Tag", []),
                author,
                attribute_markings,
            )
            observable_resolver = res_attr["resolver"]
            observable_type = res_attr["type"]
            observable_value = res_attr["value"]
            name = (
                observable_value
                if len(observable_value) > 2
                else (attribute.get("comment", "") or observable_type)
            )
            pattern_type = "stix"
            pattern = None

            if observable_resolver in PATTERNTYPES:
                pattern_type = observable_resolver
                pattern = observable_value
                name = attribute.get("comment", "") or observable_type
            elif observable_resolver not in OPENCTISTIX2:
                return None
            elif "path" in OPENCTISTIX2[observable_resolver]:
                transform = OPENCTISTIX2[observable_resolver].get("transform")
                if transform and transform.get("operation") == "remove_string":
                    observable_value = observable_value.replace(
                        transform.get("value", ""), ""
                    )
                lhs = stix2.ObjectPath(
                    OPENCTISTIX2[observable_resolver]["type"],
                    OPENCTISTIX2[observable_resolver]["path"],
                )
                genuine_pattern = str(
                    stix2.ObservationExpression(
                        stix2.EqualityComparisonExpression(lhs, observable_value)
                    )
                )
                pattern = genuine_pattern

            score = self.threat_level_to_score(event_threat_level)
            if self.import_to_ids_no_score is not None and not attribute.get(
                "to_ids", True
            ):
                score = self.import_to_ids_no_score

            indicator = None
            if self.misp_create_indicators and pattern:
                try:
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        name=name,
                        description=attribute.get("comment"),
                        confidence=self.helper.connect_confidence_level,
                        pattern_type=pattern_type,
                        pattern=pattern,
                        valid_from=datetime.fromtimestamp(
                            int(attribute["timestamp"]), tz=pytz.UTC
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        labels=attribute_tags,
                        created_by_ref=author["id"],
                        object_marking_refs=attribute_markings,
                        external_references=attribute_external_references,
                        created=datetime.fromtimestamp(
                            int(attribute["timestamp"]), tz=pytz.UTC
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        modified=datetime.fromtimestamp(
                            int(attribute["timestamp"]), tz=pytz.UTC
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        custom_properties={
                            "x_opencti_main_observable_type": observable_type,
                            "x_opencti_detection": attribute.get("to_ids", True),
                            "x_opencti_score": score,
                        },
                        allow_custom=True,
                    )
                except Exception as e:
                    self.helper.log_error(f"Error processing indicator {name}: {e}")
                    self.helper.metric.inc("error_count")
            observable = None
            if self.misp_create_observables and observable_type:
                try:
                    custom_properties = {
                        "x_opencti_description": attribute.get("comment", ""),
                        "x_opencti_score": score,
                        "labels": attribute_tags,
                        "created_by_ref": author["id"],
                        "external_references": attribute_external_references,
                    }
                    if observable_type == "Autonomous-System":
                        observable = stix2.AutonomousSystem(
                            number=observable_value.replace("AS", ""),
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Mac-Addr":
                        observable = stix2.MACAddress(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Hostname":
                        observable = CustomObservableHostname(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Domain-Name":
                        observable = stix2.DomainName(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "IPv4-Addr":
                        observable = stix2.IPv4Address(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "IPv6-Addr":
                        observable = stix2.IPv6Address(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Url":
                        observable = stix2.URL(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Email-Addr":
                        observable = stix2.EmailAddress(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Email-Message":
                        observable = stix2.EmailMessage(
                            subject=observable_value,
                            is_multipart=True,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Mutex":
                        observable = stix2.Mutex(
                            name=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "User-Account":
                        if "account_type" in OPENCTISTIX2[observable_resolver]:
                            observable = stix2.UserAccount(
                                account_login=observable_value,
                                account_type=OPENCTISTIX2[observable_resolver][
                                    "account_type"
                                ],
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        else:
                            observable = stix2.UserAccount(
                                account_login=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "File":
                        if OPENCTISTIX2[observable_resolver]["path"][0] == "name":
                            observable = stix2.File(
                                name=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        elif OPENCTISTIX2[observable_resolver]["path"][0] == "hashes":
                            hashes = {
                                OPENCTISTIX2[observable_resolver]["path"][
                                    1
                                ]: observable_value
                            }
                            observable = stix2.File(
                                name=file_name,
                                hashes=hashes,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "Directory":
                        observable = stix2.Directory(
                            path=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Windows-Registry-Key":
                        observable = stix2.WindowsRegistryKey(
                            key=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Windows-Registry-Value-Type":
                        observable = stix2.WindowsRegistryValueType(
                            data=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "X509-Certificate":
                        if OPENCTISTIX2[observable_resolver]["path"][0] == "issuer":
                            observable = stix2.File(
                                issuer=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        elif (
                            OPENCTISTIX2[observable_resolver]["path"][1]
                            == "serial_number"
                        ):
                            observable = stix2.File(
                                serial_number=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "Phone-Number":
                        observable = CustomObservablePhoneNumber(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Text":
                        observable = CustomObservableText(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Identity":
                        observable = stix2.Identity(
                            id=Identity.generate_id(
                                observable_value,
                                OPENCTISTIX2[observable_resolver]["identity_class"],
                            ),
                            name=observable_value,
                            identity_class=OPENCTISTIX2[observable_resolver][
                                "identity_class"
                            ],
                            description=attribute.get("comment", ""),
                            labels=attribute_tags,
                            created_by_ref=author["id"],
                            external_references=attribute_external_references,
                        )
                except Exception as e:
                    self.helper.log_error(
                        f"Error creating observable {observable_type} with value {observable_value}: {e}"
                    )
                    self.helper.metric.inc("error_count")
            relationships = []
            if create_relationships and indicator and observable:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on", indicator.id, observable.id
                        ),
                        relationship_type="based-on",
                        created_by_ref=author["id"],
                        source_ref=indicator.id,
                        target_ref=observable.id,
                        allow_custom=True,
                    )
                )
            return {
                "indicator": indicator,
                "observable": observable,
                "relationships": relationships,
                "attribute_elements": attribute_elements,
                "markings": attribute_markings,
                "identities": [],
                "sightings": [],
            }

    def prepare_elements(
        self, galaxies: List, tags: List, author: stix2.Identity, markings: List
    ) -> Dict:
        """
        Process galaxies and tags to extract related STIX objects.
        Returns a dictionary of categorized elements.
        """
        elements = {
            "intrusion_sets": [],
            "malwares": [],
            "tools": [],
            "attack_patterns": [],
            "sectors": [],
            "countries": [],
            "regions": [],
        }
        added_names = set()
        for galaxy in galaxies:
            namespace = galaxy.get("namespace", "")
            name = galaxy.get("name", "")
            if (namespace == "mitre-attack" and name == "Intrusion Set") or (
                namespace == "misp"
                and name
                in [
                    "Threat Actor",
                    "Microsoft Activity Group actor",
                    "ESET Threat Actor",
                ]
            ):
                for entity in galaxy.get("GalaxyCluster", []):
                    entity_name = (
                        entity["value"].split(" - G")[0]
                        if " - G" in entity["value"]
                        else entity["value"]
                    )
                    if entity_name not in added_names and not is_uuid(entity_name):
                        intrusion_set = stix2.IntrusionSet(
                            id=IntrusionSet.generate_id(entity_name),
                            name=entity_name,
                            confidence=self.helper.connect_confidence_level,
                            labels=["intrusion-set"],
                            description=entity.get("description", ""),
                            created_by_ref=author["id"],
                            object_marking_refs=markings,
                            custom_properties={
                                "x_opencti_aliases": entity.get("meta", {}).get(
                                    "synonyms", [entity_name]
                                )
                            },
                        )
                        elements["intrusion_sets"].append(intrusion_set)
                        added_names.add(entity_name)
            if (namespace == "mitre-attack" and name == "Tool") or (
                namespace == "misp" and name.lower().startswith("tool")
            ):
                for entity in galaxy.get("GalaxyCluster", []):
                    entity_name = (
                        entity["value"].split(" - S")[0]
                        if " - S" in entity["value"]
                        else entity["value"]
                    )
                    if entity_name not in added_names:
                        tool_obj = stix2.Tool(
                            id=Tool.generate_id(entity_name),
                            name=entity_name,
                            confidence=self.helper.connect_confidence_level,
                            description=entity.get("description", ""),
                            created_by_ref=author["id"],
                            object_marking_refs=markings,
                            allow_custom=True,
                        )
                        elements["tools"].append(tool_obj)
                        added_names.add(entity_name)
            if (namespace == "mitre-attack" and name == "Malware") or (
                namespace == "misp"
                and name in ["Tool", "Ransomware", "Android", "Malpedia"]
            ):
                for entity in galaxy.get("GalaxyCluster", []):
                    entity_name = (
                        entity["value"].split(" - S")[0]
                        if " - S" in entity["value"]
                        else entity["value"]
                    )
                    if entity_name not in added_names:
                        malware_obj = stix2.Malware(
                            id=Malware.generate_id(entity_name),
                            name=entity_name,
                            is_family=True,
                            confidence=self.helper.connect_confidence_level,
                            labels=[name],
                            description=entity.get("description", ""),
                            created_by_ref=author["id"],
                            object_marking_refs=markings,
                            allow_custom=True,
                        )
                        elements["malwares"].append(malware_obj)
                        added_names.add(entity_name)
            if namespace == "mitre-attack" and name == "Attack Pattern":
                for entity in galaxy.get("GalaxyCluster", []):
                    entity_name = (
                        entity["value"].split(" - T")[0]
                        if " - T" in entity["value"]
                        else entity["value"]
                    )
                    if entity_name not in added_names:
                        x_mitre_id = None
                        if (
                            "meta" in entity
                            and "external_id" in entity["meta"]
                            and entity["meta"]["external_id"]
                        ):
                            x_mitre_id = entity["meta"]["external_id"][0]
                        attack_pattern = stix2.AttackPattern(
                            id=AttackPattern.generate_id(entity_name, x_mitre_id),
                            name=entity_name,
                            description=entity.get("description", ""),
                            created_by_ref=author["id"],
                            object_marking_refs=markings,
                            custom_properties={
                                "x_mitre_id": x_mitre_id,
                                "x_opencti_aliases": entity.get("meta", {}).get(
                                    "synonyms", [entity_name]
                                ),
                            },
                            allow_custom=True,
                        )
                        elements["attack_patterns"].append(attack_pattern)
                        added_names.add(entity_name)
            if namespace == "misp" and name == "Sector":
                for entity in galaxy.get("GalaxyCluster", []):
                    sector_name = entity["value"]
                    if sector_name not in added_names:
                        sector = stix2.Identity(
                            id=Identity.generate_id(sector_name, "class"),
                            name=sector_name,
                            identity_class="class",
                            description=entity.get("description", ""),
                            created_by_ref=author["id"],
                            object_marking_refs=markings,
                            allow_custom=True,
                        )
                        elements["sectors"].append(sector)
                        added_names.add(sector_name)
            if namespace == "misp" and name == "Country":
                for entity in galaxy.get("GalaxyCluster", []):
                    country_name = entity.get("description", "")
                    if country_name and country_name not in added_names:
                        country = stix2.Location(
                            id=Location.generate_id(country_name, "Country"),
                            name=country_name,
                            country=entity.get("meta", {}).get("ISO", ""),
                            description="Imported from MISP tag",
                            created_by_ref=author["id"],
                            object_marking_refs=markings,
                            allow_custom=True,
                        )
                        elements["countries"].append(country)
                        added_names.add(country_name)
            if (
                namespace == "misp"
                and galaxy.get("type") == "region"
                and name == "Regions UN M49"
            ):
                for entity in galaxy.get("GalaxyCluster", []):
                    region_name = (
                        entity["value"].split(" - ")[1]
                        if " - " in entity["value"]
                        else entity["value"]
                    )
                    if region_name not in added_names:
                        region = stix2.Location(
                            id=Location.generate_id(region_name, "Region"),
                            name=region_name,
                            confidence=self.helper.connect_confidence_level,
                            region=region_name,
                            allow_custom=True,
                        )
                        elements["regions"].append(region)
                        added_names.add(region_name)
        for tag in tags:
            if self.misp_guess_threats_from_tags:
                tag_value = tag["name"].split("=")[-1].strip().replace('"', "")
                if tag_value:
                    threats = self.helper.api.stix_domain_object.list(
                        types=["Intrusion-Set", "Malware", "Tool", "Attack-Pattern"],
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": [
                                        "name",
                                        "x_mitre_id",
                                        "aliases",
                                        "x_opencti_aliases",
                                    ],
                                    "values": [tag_value],
                                }
                            ],
                            "filterGroups": [],
                        },
                    )
                    if threats:
                        threat = threats[0]
                        if threat["name"] not in added_names and not is_uuid(
                            threat["name"]
                        ):
                            if threat["entity_type"] == "Intrusion-Set":
                                intrusion_set = stix2.IntrusionSet(
                                    id=IntrusionSet.generate_id(threat["name"]),
                                    name=threat["name"],
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                                elements["intrusion_sets"].append(intrusion_set)
                                added_names.add(threat["name"])
                            elif threat["entity_type"] == "Malware":
                                malware_obj = stix2.Malware(
                                    id=Malware.generate_id(threat["name"]),
                                    name=threat["name"],
                                    is_family=True,
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                                elements["malwares"].append(malware_obj)
                                added_names.add(threat["name"])
                            elif threat["entity_type"] == "Tool":
                                tool_obj = stix2.Tool(
                                    id=Tool.generate_id(threat["name"]),
                                    name=threat["name"],
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                                elements["tools"].append(tool_obj)
                                added_names.add(threat["name"])
                            elif threat["entity_type"] == "Attack-Pattern":
                                attack_pattern = stix2.AttackPattern(
                                    id=AttackPattern.generate_id(threat["name"]),
                                    name=threat["name"],
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                                elements["attack_patterns"].append(attack_pattern)
                                added_names.add(threat["name"])
        return elements

    def resolve_type(self, attr_type: str, attr_value: str) -> Optional[List[Dict]]:
        """
        Resolve the MISP attribute type to a STIX type.
        Returns a list of dictionaries with keys: 'resolver', 'type', and 'value'.
        """
        if attr_type in OPENCTISTIX2:
            return [
                {
                    "resolver": attr_type,
                    "type": OPENCTISTIX2[attr_type]["type"],
                    "value": attr_value,
                }
            ]
        return None

    def _resolve_markings(self, tags: List, with_default: bool = True) -> List:
        """Resolve markings from tags, checking for TLP levels."""
        markings = []
        for tag in tags:
            if tag["name"].lower().startswith("tlp:"):
                tlp_level = tag["name"].split(":")[1].upper()
                markings.append(getattr(stix2, f"TLP_{tlp_level}", stix2.TLP_WHITE))
        if with_default and not markings:
            markings.append(stix2.TLP_WHITE)
        return markings

    def _resolve_tags(self, tags: List) -> List:
        """Extract tag names from MISP tags."""
        return [tag["name"] for tag in tags]

    def threat_level_to_score(self, threat_level: Any) -> int:
        """Convert a threat level to a numerical score."""
        mapping = {"1": 100, "2": 75, "3": 50, "4": 25}
        return mapping.get(str(threat_level), 50)

    def _process_note(self, note_content: str, bundle_objects: List) -> str:
        """Process note content; currently a passthrough."""
        return note_content

    def _create_report(
        self,
        event: Dict,
        author: stix2.Identity,
        markings: List,
        tags: List,
        bundle_objects: List,
        external_refs: List,
        files: List,
    ) -> stix2.Report:
        """Create a STIX Report from the event."""
        attributes = filter_event_attributes(
            event, **self.misp_report_description_attribute_filter
        )
        description = attributes[0]["value"] if attributes else event["Event"]["info"]
        event_date = datetime.strptime(str(event["Event"]["date"]), "%Y-%m-%d")
        report = stix2.Report(
            id=Report.generate_id(event["Event"]["info"], event_date),
            name=event["Event"]["info"],
            description=description,
            published=event_date,
            created=event_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            modified=datetime.fromtimestamp(
                int(event["Event"]["timestamp"]), tz=pytz.UTC
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            report_types=[self.misp_report_type],
            created_by_ref=author["id"],
            object_marking_refs=markings,
            labels=tags,
            object_refs=[getattr(obj, "id", obj) for obj in bundle_objects],
            external_references=external_refs,
            confidence=self.helper.connect_confidence_level,
            custom_properties={"x_opencti_files": files},
            allow_custom=True,
        )
        return report

    def find_stix_object_by_uuid(
        self, uuid_val: str, stix_objects: List
    ) -> Optional[Dict]:
        """
        Find a STIX object whose ID contains the given UUID.
        Modify this logic to fit your identifier scheme.
        """
        for obj in stix_objects:
            if hasattr(obj, "id") and uuid_val in obj.id:
                return {"id": obj.id, "entity": obj}
        return None


if __name__ == "__main__":
    try:
        connector = Misp()
        connector.run()
    except Exception as e:
        sys.exit(f"Fatal error: {e}")
