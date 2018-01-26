# --
# File: crowdstrike_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
# from phantom.action_result import ActionResult

# THIS Connector imports
from crowdstrike_consts import *

import requests
# from requests.auth import HTTPBasicAuth
from datetime import datetime
from datetime import timedelta
import time
import parse_cs_events as events_parser
import simplejson as json
import cs.hmac.client as client


class CrowdstrikeConnector(BaseConnector):

    # The actions supported by this connector
    ACCESS_KEYS = {'customer': 'customers', 'user': 'ovl'}

    def __init__(self):

        # Call the BaseConnectors init first
        super(CrowdstrikeConnector, self).__init__()

        self._base_url = None
        self._auth = None
        self._parameters = None
        self._token = None
        self._data_feed_url = None
        self._events = []
        self._headers = None
        self._state = {}

    def initialize(self):
        """ Automatically called by the BaseConnector before the calls to the handle_action function"""

        config = self.get_config()

        # Base URL
        self._base_url = config[CROWDSTRIKE_JSON_URL]

        if (self._base_url[-1] == '/'):
            self._base_url = self._base_url[:-1]

        access_key = self.ACCESS_KEYS.get(config[CROWDSTRIKE_JSON_ACCESS])

        if (not access_key):
            return self.set_status(phantom.APP_ERROR, 'Invalid access key')

        # create the Auth
        self._auth = client.Auth(uuid=str(config[CROWDSTRIKE_JSON_UUID]), api_key=str(config[CROWDSTRIKE_JSON_API_KEY]), access=str(access_key))

        # set the params, use the asset id as the appId that is passed Crowdstrike
        app_id = config.get('app_id', self.get_asset_id().replace('-', ''))
        self._parameters = {'appId': app_id}

        self._state = self.load_state()

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _get_stream(self):

        # Progress
        self.save_progress(CROWDSTRIKE_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._base_url)

        self._token = None
        self._data_feed_url = None

        ret_val, resp = self._make_rest_call(CROWDSTRIKE_BASE_ENDPOINT, self)

        if (phantom.is_fail(ret_val)):
            return self.get_status()

        meta = resp.get('meta')
        if (not meta):
            return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_META_KEY_EMPTY)

        try:
            if (int(meta['pagination']['count']) == 0):
                self.debug_print("COUNT is ZERO")
                return phantom.APP_SUCCESS
        except:
                return phantom.APP_ERROR

        # Extract values that we require for other calls
        resources = resp.get('resources')
        if (not resources):
            return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_RESOURCES_KEY_EMPTY)

        self._data_feed_url = resources[0].get('dataFeedURL')
        if (not self._data_feed_url):
            return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_DATAFEED_EMPTY)

        session_token = resources[0].get('sessionToken')
        if (not session_token):
            return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_SESSION_TOKEN_NOT_FOUND)

        self._token = session_token['token']

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        ret_val = self._get_stream()

        if (phantom.is_fail(ret_val)):
            self.save_progress(CROWDSTRIKE_ERR_CONNECTIVITY_TEST)
            self.save_progress(CROWDSTRIKE_ERR_CONN_FAILED)
            return phantom.APP_ERROR

        return self.set_status_save_progress(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_CONNECTIVITY_TEST)

    def _get_str_from_epoch(self, epoch_milli):
        # 2015-07-21T00:27:59Z
        return datetime.fromtimestamp(epoch_milli / 1000.0).strftime('%Y-%m-%dT%H:%M:%SZ')

    def _parse_resp_data(self, data):

        event = None
        try:
            event = json.loads(data.strip('\r\n '))
        except Exception as e:
            self.debug_print("Exception while parsing data: ", e.message)
            return (phantom.APP_ERROR, data)

        return (phantom.APP_SUCCESS, event)

    def _check_for_existing_container(self, container, time_interval, collate):
        if (not time_interval) or (not collate):
            return phantom.APP_ERROR, None

        # gt_date = datetime.strptime(container['start_time'], '%Y-%m-%dT%H:%M:%SZ') - timedelta(seconds=time_interval)
        gt_date = datetime.utcnow() - timedelta(seconds=int(time_interval))
        # Cutoff Timestamp From String
        common_str = ' '.join(container['name'].split()[:-1])
        request_str = CROWDSTRIKE_FILTER_REQUEST_STR.format(self.get_asset_id(), common_str, gt_date.strftime('%Y-%m-%dT%H:%M:%SZ'))

        try:
            r = requests.get(request_str, verify=False)
        except Exception as e:
            self.debug_print("Error making local rest call: {0}".format(str(e)))
            self.debug_print('DB QUERY: {}'.format(request_str))
            return phantom.APP_ERROR, None

        try:
            resp_json = r.json()
        except Exception as e:
            self.debug_print('Exception caught: {0}'.format(str(e)))
            return phantom.APP_ERROR, None

        count = resp_json.get('count', 0)
        if count:
            try:
                most_recent = gt_date
                most_recent_id = resp_json['data'][0]['id']
                for container in resp_json['data']:
                    if most_recent <= datetime.strptime(container['start_time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        most_recent_id = container['id']
                return phantom.APP_SUCCESS, most_recent_id
            except Exception as e:
                self.debug_print("Caught Exception in parsing containers: {0}".format(str(e)))
                return phantom.APP_ERROR, None
        return phantom.APP_ERROR, None

    def _save_results(self, results, param):

        artifact_count = int(param.get(phantom.APP_JSON_ARTIFACT_COUNT, CROWDSTRIKE_DEFAULT_ARTIFACT_COUNT))

        containers_processed = 0
        for i, result in enumerate(results):

            self.send_progress("Adding Container # {0}".format(i))
            # result is a dictionary of a single container and artifacts
            if ('container' not in result):
                continue

            if ('artifacts' not in result):
                # igonore containers without artifacts
                continue

            if (len(result['artifacts']) == 0):
                # igonore containers without artifacts
                continue

            containers_processed += 1

            config = self.get_config()
            time_interval = config.get('merge_time_interval', 0)

            ret_val, container_id = self._check_for_existing_container(
                result['container'], time_interval, config.get('collate')
            )

            if (not container_id):
                # Do not collate this container
                ret_val, response, container_id = self.save_container(result['container'])
                self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, response, container_id))

            if (phantom.is_fail(ret_val)):
                continue

            if (not container_id):
                continue

            if ('artifacts' not in result):
                continue

            artifacts = result['artifacts']
            artifacts = artifacts[:artifact_count]

            # get the length of the artifact, we might have trimmed it or not
            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                # if it is the last artifact of the last container
                if ((j + 1) == len_artifacts):
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                artifact['container_id'] = container_id

            ret_val, status_string, artifact_id = self.save_artifacts(artifacts)
            self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return containers_processed

    def _make_rest_call(self, endpoint, result, headers={}, params={}, method='get'):

        if (self._parameters):
            params.update(self._parameters)

        if (self._headers):
            headers.update(self._headers)

        func_ptr = getattr(client, method)

        if (not func_ptr):
            return (result.set_status(phantom.APP_ERROR, "Invalid Method specified"), None)

        kwargs = {}

        # The client object cribs if params is specified as None
        if (params):
            kwargs['params'] = params

        # The client object cribs if header is specified as None
        if (headers):
            kwargs['headers'] = headers

        config = self.get_config()

        kwargs['verify'] = config[phantom.APP_JSON_VERIFY]

        url = "{0}{1}".format(self._base_url, endpoint)

        try:
            r = client.get(url, Auth=self._auth, **kwargs)
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_CONNECTING, e), None)

        if hasattr(result, 'add_debug_data'):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        try:
            resp_json = r.json()
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, "Response does not look like a valid JSON"), None)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            try:
                err_message = resp_json['errors'][0]['message']
            except:
                err_message = 'None'
            return (result.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_FROM_SERVER, status=r.status_code, message=err_message), None)

        return (phantom.APP_SUCCESS, resp_json)

    def _on_poll(self, param):

        # Connect to the server
        if (phantom.is_fail(self._get_stream())):
            return self.get_status()

        if (self._data_feed_url is None):
            return self.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_NO_MORE_FEEDS_AVAILABLE)

        max_container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, CROWDSTRIKE_DEFAULT_CONTAINER_COUNT))

        config = self.get_config()

        max_events = int(config.get('max_events', 10000))

        lower_id = 0

        if (self.is_poll_now()):
            max_events = int(config.get('max_events_poll_now', 2000))

        if (not self.is_poll_now()):
            # we only manger the ids in case of on_poll on the interval, on POLL NOW always start on 0
            # lower_id = int(self._get_lower_id())
            lower_id = self._state.get('last_offset_id', 0)

        self.save_progress(CROWDSTRIKE_MSG_GETTING_EVENTS.format(lower_id=lower_id, max_events=max_events))

        config = self.get_config()

        # Query for the events
        try:
            r = requests.get(self._data_feed_url + '&offset={0}'.format(lower_id), headers={'Authorization': 'Token {0}'.format(self._token)},
                    stream=True, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_CONNECTING, e)

        # Handle any errors
        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            resp_json = r.json()
            try:
                err_message = resp_json['errors'][0]['message']
            except:
                err_message = 'None'
            return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_ERR_FROM_SERVER, status=r.status_code, message=err_message)

        # Parse the events
        resp_data = ''
        for chunk in r.iter_content(chunk_size=None):
            if chunk == '\r\n':
                # Done with all the event data for now
                break
            resp_data += chunk
            ret_val, resp_data = self._parse_resp_data(resp_data)
            if (phantom.is_fail(ret_val)):
                self.debug_print("Chunk: ", chunk)
                return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_UNABLE_TO_PARSE_DATA)

            # resp_data is a dict
            self._events.append(resp_data)
            len_events = len(self._events)
            if (len_events >= max_events):
                break
            self.send_progress("Pulled {0} events".format(len_events))
            # convert it to string
            resp_data = ''

        collate = config.get('collate', True)

        self.send_progress(" ")
        self.debug_print("Got {0} Events".format(len(self._events)))
        self.save_progress("Got {0} Events".format(len(self._events)))
        if (len(self._events) > 0):
            self.send_progress("Parsing them.")
            results = events_parser.parse_events(self._events, self, collate)
            self.save_progress("Created {0} relevant containers from events".format(len(results)))
            if (results):
                results = results[:max_container_count]
                self.save_progress("Adding {0} Container{1}. Empty containers will be skipped.".format(len(results), 's' if len(results) > 1 else ''))
                self._save_results(results, param)
                self.send_progress("Done")
            if (not self.is_poll_now()):
                last_event = self._events[-1]
                last_offset_id = last_event['metadata']['offset']
                self._state['last_offset_id'] = last_offset_id + 1

        return self.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        if (action == phantom.ACTION_ID_INGEST_ON_POLL):
            start_time = time.time()
            result = self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress("Time taken: {0}".format(human_time))
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_connectivity(param)

        return result


if __name__ == '__main__':

    import sys
    # import simplejson as json

    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = CrowdstrikeConnector()
        connector.print_progress_message = True
        connector._handle_action(json.dumps(in_json), None)

    exit(0)
