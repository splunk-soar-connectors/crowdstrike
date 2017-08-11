#!/usr/bin/env python2.7
# --
# File: ./crowdstrike/parse_cs_events.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --


_container_common = {
    "description": "Container added by Phantom",
    "run_automation": False  # Don't run any playbooks, when this container is added
}

_artifact_common = {
    "label": "event",
    "type": "network",
    "description": "Artifact added by Phantom",
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

_severity_map = {
        '0': 'low',
        '1': 'low',
        '2': 'low',
        '3': 'medium',
        '4': 'high',
        '5': 'high'
}


def _get_value(in_dict, in_key, def_val=None, strip_it=True):

    if (in_key not in in_dict):
        return def_val

    if (type(in_dict[in_key]) != str) and (type(in_dict[in_key]) != unicode):
        return in_dict[in_key]

    value = in_dict[in_key].strip() if (strip_it) else in_dict[in_key]

    return value if len(value) else def_val


def _set_cef_key(src_dict, src_key, dst_dict, dst_key):

    src_value = _get_value(src_dict, src_key)

    # Ignore if None
    if (src_value is None):
        return False

    if (src_value == 'N/A'):
        return False

    dst_dict[dst_key] = src_value

    return True


def parse_events(events):

    results = []

    # extract the type == 'DetectionSummaryEvent' events
    detection_events = [x for x in events if x['metadata']['eventType'] == 'DetectionSummaryEvent']

    if (not detection_events):
        return results

    # Get the set of unique detection name, these will be the containers
    detection_names = set([x['event'].get('DetectName') for x in detection_events])

    container_id = 0

    for i, detection_name in enumerate(detection_names):

        per_detection_events = [x for x in detection_events if x['event'].get('DetectName') == detection_name]

        # Get the set of unique machine names
        machine_names = set([x['event'].get('ComputerName', '') for x in per_detection_events])

        for j, machine_name in enumerate(machine_names):

            per_detection_machine_events = [x for x in per_detection_events if x['event'].get('ComputerName') == machine_name]

            ingest_event = dict()
            results.append(ingest_event)

            # Create the container
            container = dict()
            ingest_event['container'] = container
            container.update(_container_common)
            container['name'] = "{0} {1}".format(detection_name, '' if (not machine_name) else 'on {0}'.format(machine_name))

            # This is just the index right now
            container['source_data_identifier'] = container_id
            container_id += 1

            # now the artifacts
            ingest_event['artifacts'] = artifacts = []
            for j, detection_event in enumerate(per_detection_machine_events):

                artifact = dict()
                cef = dict()
                artifact['cef'] = cef

                event_details = detection_event['event']

                # so this artifact needs to be added
                artifact.update(_artifact_common)
                artifact['source_data_identifier'] = detection_event.get('metadata', {}).get('offset', j)
                artifact['name'] = event_details.get('DetectDescription', 'Artifact # {0}'.format(j))
                artifact['severity'] = _severity_map.get(str(event_details.get('Severity', 3)), 'medioum')

                _set_cef_key(event_details, 'UserName', cef, 'sourceUserName')
                _set_cef_key(event_details, 'FileName', cef, 'fileName')
                _set_cef_key(event_details, 'FilePath', cef, 'filePath')
                _set_cef_key(event_details, 'ComputerName', cef, 'sourceHostName')
                _set_cef_key(event_details, 'MachineDomain', cef, 'sourceNtDomain')
                _set_cef_key(event_details, 'MD5String', cef, 'hash')
                _set_cef_key(event_details, 'SHA1String', cef, 'hash')
                _set_cef_key(event_details, 'SHA256STring', cef, 'hash')

                if ('CommandLine' in event_details):
                    cef['cs1Label'] = 'cmdLine'
                    _set_cef_key(event_details, 'CommandLine', cef, 'cs1')

                if (cef):
                    # append to the artifacts
                    artifacts.append(artifact)

    return results
