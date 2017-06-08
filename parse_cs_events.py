#!/usr/bin/env python2.7
# --
# File: ./crowdstrike/parse_cs_events.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

from datetime import datetime


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


def _set_cef_key(src_dict, src_key, dst_dict, dst_key, move=False):
    src_value = _get_value(src_dict, src_key)

    # Ignore if None
    if (src_value is None):
        return False

    if (src_value == 'N/A'):
        return False

    dst_dict[dst_key] = src_value

    if (move):
        del src_dict[src_key]

    return True


def _set_cef_key_list(event_details, cef):
    _set_cef_key(event_details, 'UserName', cef, 'sourceUserName', move=True)
    _set_cef_key(event_details, 'FileName', cef, 'fileName', move=True)
    _set_cef_key(event_details, 'FilePath', cef, 'filePath', move=True)
    _set_cef_key(event_details, 'ComputerName', cef, 'sourceHostName', move=True)
    _set_cef_key(event_details, 'MachineDomain', cef, 'sourceNtDomain', move=True)
    _set_cef_key(event_details, 'MD5String', cef, 'fileHash')
    _set_cef_key(event_details, 'MD5String', cef, 'hash')
    _set_cef_key(event_details, 'MD5String', cef, 'fileHashMd5', move=True)

    _set_cef_key(event_details, 'SHA1String', cef, 'hash')
    _set_cef_key(event_details, 'SHA1String', cef, 'fileHashSha1', move=True)

    _set_cef_key(event_details, 'SHA256String', cef, 'hash')
    _set_cef_key(event_details, 'SHA256String', cef, 'fileHashSha256', move=True)

    _set_cef_key(event_details, 'DetectId', cef, 'detectId')
    _set_cef_key(event_details, 'FalconHostLink', cef, 'falconHostLink')

    if ('CommandLine' in event_details):
        cef['cs1Label'] = 'cmdLine'
        _set_cef_key(event_details, 'CommandLine', cef, 'cs1')
        _set_cef_key(event_details, 'CommandLine', cef, 'cmdLine', move=True)


def _get_event_types(events):

    event_types = [x.get('metadata', {}).get('eventType', '') for x in events]
    event_types = list(set(event_types))

    return event_types


def _collate_results(detection_events):

    results = []

    # Get the set of unique detection name, these will be the containers
    detection_names = set([x['event'].get('DetectName') for x in detection_events])

    # container_id = 0

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

            # Don't add the SDI for the container, the platform generates the proper thing
            # container['source_data_identifier'] = container_id
            # container_id += 1

            # now the artifacts
            ingest_event['artifacts'] = artifacts = []
            for j, detection_event in enumerate(per_detection_machine_events):

                artifact, cef = _create_artifact_from_event(detection_event)
                # artifact = dict()
                # cef = dict()
                # artifact['cef'] = cef

                # # Make a copy, since the dictionary will be modified
                # event_details = dict(detection_event['event'])
                # event_metadata = detection_event.get('metadata', {})

                # # so this artifact needs to be added
                # artifact.update(_artifact_common)
                # artifact['source_data_identifier'] = event_metadata.get('offset', j)
                # artifact['name'] = event_details.get('DetectDescription', 'Artifact # {0}'.format(j))
                # artifact['severity'] = _severity_map.get(str(event_details.get('Severity', 3)), 'medioum')

                # _set_cef_key_list(event_details, cef)

                # # convert any remaining keys in the event_details to follow the cef naming conventions
                # for k, v in event_details.iteritems():
                #     cef[k[:1].lower() + k[1:]] = v
                #     if (event_metadata):
                #         # add the metadata as is, it already contains the keys in cef naming conventions
                #         cef.update(event_metadata)
                #     # append to the artifacts

                if (cef):
                    artifacts.append(artifact)

    return results


def _create_artifact_from_event(event):

    # Make a copy, since the dictionary will be modified
    event_details = dict(event['event'])
    event_metadata = event.get('metadata', {})

    artifact = dict()
    cef = dict()
    artifact['cef'] = cef

    # so this artifact needs to be added
    artifact.update(_artifact_common)
    artifact['source_data_identifier'] = event_metadata['offset']
    artifact['name'] = event_details.get('DetectDescription', 'Detection Artifact')
    artifact['severity'] = _severity_map.get(str(event_details.get('Severity', 3)), 'medium')

    _set_cef_key_list(event_details, cef)

    # convert any remaining keys in the event_details to follow the cef naming conventions
    for k, v in event_details.iteritems():
        cef[k[:1].lower() + k[1:]] = v

    if (cef):
        if (event_metadata):
            # add the metadata as is, it already contains the keys in cef naming conventions
            cef.update(event_metadata)
        # append to the artifacts
        # artifacts.append(artifact)

    artifact['data'] = event

    return artifact, cef


def _get_dt_from_epoch(epoch_milli):
    return datetime.fromtimestamp(int(epoch_milli) / 1000)


def _get_str_from_epoch(epoch_milli):
    # 2015-07-21T00:27:59Z
    return datetime.fromtimestamp(int(epoch_milli) / 1000).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_events(events, base_connector, collate):
    results = []

    # base_connector.debug_print("Got event_types: {0}".format(', '.join(_get_event_types(events))))

    base_connector.save_progress("Extracting Detection events")

    # extract the type == 'DetectionSummaryEvent' events
    detection_events = [x for x in events if x['metadata']['eventType'] == 'DetectionSummaryEvent']

    if (not detection_events):
        base_connector.save_progress("Did not match any events of type: DetectionSummaryEvent")
        return results

    base_connector.save_progress("Got {0}".format(len(detection_events)))

    if (collate):
        return _collate_results(detection_events)

    for i, curr_event in enumerate(detection_events):

        artifact, cef = _create_artifact_from_event(curr_event)

        event_details = curr_event['event']
        detection_name = event_details.get('DetectName', 'Unknown Detection')
        hostname = event_details.get('ComputerName', 'Unknown Host')
        creation_time = curr_event.get('metadata').get('eventCreationTime', '')
        # creation_time_dt = None

        ingest_event = dict()
        results.append(ingest_event)

        if (creation_time):
            # creation_time_dt = _get_dt_from_epoch(creation_time)
            creation_time = _get_str_from_epoch(creation_time)

        # Create the container
        container = dict()
        ingest_event['container'] = container
        container.update(_container_common)
        container['name'] = "{0} on {1} at {2}".format(detection_name, hostname, creation_time)
        container['severity'] = _severity_map.get(str(event_details.get('Severity', 3)), 'medium')
        base_connector.debug_print("CREATION TIME {0}".format(creation_time))
        container['start_time'] = creation_time

        # now the artifacts, will just be one
        ingest_event['artifacts'] = artifacts = []
        artifacts.append(artifact)

    return results
