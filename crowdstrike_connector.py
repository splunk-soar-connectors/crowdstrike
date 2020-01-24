# File: crowdstrike_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

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
import json
import cs.hmac.client as client
import imp
from bs4 import UnicodeDammit


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

        try:
            # Base URL
            self._base_url = config[CROWDSTRIKE_JSON_URL]

            if (self._base_url[-1] == '/'):
                self._base_url = self._base_url[:-1]

            self._base_url = self._base_url.encode('utf-8')
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, 'Error occurred while processing the base_url provided in the asset configuration parameters. Error: {0}'.format(str(e)))

        access_key = self.ACCESS_KEYS.get(config[CROWDSTRIKE_JSON_ACCESS])

        if (not access_key):
            return self.set_status(phantom.APP_ERROR, 'Invalid access key')

        # create the Auth
        self._auth = client.Auth(uuid=str(config[CROWDSTRIKE_JSON_UUID].encode('utf-8')), api_key=str(config[CROWDSTRIKE_JSON_API_KEY]), access=str(access_key))

        # set the params, use the asset id as the appId that is passed Crowdstrike
        app_id = config.get('app_id', self.get_asset_id().replace('-', ''))
        self._parameters = {'appId': app_id}

        self._state = self.load_state()

        ret = self._handle_preprocess_scripts()
        if phantom.is_fail(ret):
            return ret

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _handle_preprocess_scripts(self):

        config = self.get_config()
        script = config.get('preprocess_script')

        self._preprocess_container = lambda x: x

        if script:
            try:  # Try to laod in script to preprocess artifacts
                self._script_module = imp.new_module('preprocess_methods')
                exec script in self._script_module.__dict__
            except Exception as e:
                self.save_progress("Error loading custom script. Error: {}".format(str(e)))
                return phantom.APP_ERROR

            try:
                self._preprocess_container = self._script_module.preprocess_container
            except:
                self.save_progress("Error loading custom script. Does not contain preprocess_container function")
                return phantom.APP_ERROR

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
        # Even if the collate parameter is selected, the time mentioned in the merge_time_interval
        # config parameter will be considered for the creation of the new container for a given category of DetectionSummaryEvent
        gt_date = datetime.utcnow() - timedelta(seconds=int(time_interval))
        # Cutoff Timestamp From String
        common_str = ' '.join(container['name'].split()[:-1])
        request_str = CROWDSTRIKE_FILTER_REQUEST_STR.format(self.get_phantom_base_url(), self.get_asset_id(), common_str, gt_date.strftime('%Y-%m-%dT%H:%M:%SZ'))

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
                most_recent_id = None
                for container in resp_json['data']:
                    if container.get('parent_container'):
                        # container created through aggregation, skip this
                        continue
                    cur_start_time = datetime.strptime(container['start_time'], '%Y-%m-%dT%H:%M:%S.%fZ')
                    if most_recent <= cur_start_time:
                        most_recent_id = container['id']
                        most_recent = cur_start_time
                if most_recent_id is not None:
                    return phantom.APP_SUCCESS, most_recent_id
            except Exception as e:
                self.debug_print("Caught Exception in parsing containers: {0}".format(str(e)))
                return phantom.APP_ERROR, None
        return phantom.APP_ERROR, None

    def _save_results(self, results, param):

        reused_containers = 0

        containers_processed = 0
        for i, result in enumerate(results):

            self.send_progress("Adding event artifact # {0}".format(i))
            # result is a dictionary of a single container and artifacts
            if ('container' not in result):
                self.debug_print("Skipping empty container # {0}".format(i))
                continue

            if ('artifacts' not in result):
                # ignore containers without artifacts
                self.debug_print("Skipping container # {0} without artifacts".format(i))
                continue

            if (len(result['artifacts']) == 0):
                # ignore containers without artifacts
                self.debug_print("Skipping container # {0} with 0 artifacts".format(i))
                continue

            config = self.get_config()
            time_interval = config.get('merge_time_interval', 0)

            ret_val, container_id = self._check_for_existing_container(
                result['container'], time_interval, config.get('collate')
            )

            if ('artifacts' not in result):
                continue

            artifacts = result['artifacts']

            # get the length of the artifact, we might have trimmed it or not
            len_artifacts = len(artifacts)
            for j, artifact in enumerate(artifacts):

                # if it is the last artifact of the last container
                if ((j + 1) == len_artifacts):
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                artifact['container_id'] = container_id

            if container_id:
                ret_val, status_string, artifact_ids = self.save_artifacts(artifacts)
                self.debug_print("save_artifacts returns, value: {0}, reason: {1}".format(ret_val, status_string))
                self.debug_print("Reusing container with id: {0}".format(container_id))
                reused_containers += 1
            else:
                container = result['container']
                container['artifacts'] = artifacts

                if (hasattr(self, '_preprocess_container')):
                    try:
                        container = self._preprocess_container(container)
                    except Exception as e:
                        self.debug_print('Preprocess error: ' + e.message)

                ret_val, response, container_id = self.save_container(result['container'])
                self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, response, container_id))

                if (phantom.is_fail(ret_val)):
                    continue

            containers_processed += 1

        if (reused_containers and config.get('collate')):
            self.save_progress("Some containers were re-used due to collate set to True")

        return containers_processed

    def _make_rest_call(self, endpoint, result, headers={}, params={}, method='get'):

        if (self._parameters):
            # config = self.get_config()
            # app_id = config.get('app_id', self.get_asset_id().replace('-', ''))
            # self._parameters['appId'] = "{}_{}".format(app_id.split('_')[0], int(time.time()))
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

        config = self.get_config()

        if (self.is_poll_now()):
            # Manual Poll Now
            try:
                max_events = int(config.get('max_events_poll_now', DEFAULT_POLLNOW_EVENTS_COUNT))
            except:
                max_events = DEFAULT_POLLNOW_EVENTS_COUNT
        else:
            # Scheduled and Interval Polling
            try:
                max_events = int(config.get('max_events', DEFAULT_EVENTS_COUNT))
            except:
                max_events = DEFAULT_EVENTS_COUNT

        if max_events <= 0:
            return self.set_status(phantom.APP_ERROR, 'Please provide non-zero positive integer in the "max_events" configuration parameter')

        lower_id = 0
        if (not self.is_poll_now()):
            # we only mange the ids in case of on_poll on the interval
            # For POLL NOW always start on 0
            # lower_id = int(self._get_lower_id())
            try:
                lower_id = int(self._state.get('last_offset_id', 0))
            except:
                lower_id = 0

        # In case of invalid lower_id, set the lower_id offset to the starting point 0
        if lower_id < 0:
            lower_id = 0

        max_crlf = int(config.get("max_crlf", DEFAULT_BLANK_LINES_ALLOWABLE_LIMIT))

        self.save_progress(CROWDSTRIKE_MSG_GETTING_EVENTS.format(lower_id=lower_id, max_events=max_events))

        # Query for the events
        try:
            self._data_feed_url = self._data_feed_url + '&offset={0}&eventType=DetectionSummaryEvent'.format(lower_id)
            r = requests.get(self._data_feed_url, headers={'Authorization': 'Token {0}'.format(self._token), 'Connection': 'Keep-Alive'}, stream=True)
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
        counter = 0   # counter for continuous blank lines
        total_blank_lines_count = 0    # counter for total number of blank lines

        try:
            for chunk in r.iter_content(chunk_size=None):

                if not chunk:
                    # Done with all the event data for now
                    self.debug_print("No data, terminating loop")
                    self.save_progress("No data, terminating loop")
                    break

                if chunk == '\r\n':
                    # increment counter for counting of the continuous as well as total blank lines
                    counter += 1
                    total_blank_lines_count += 1

                    if counter > max_crlf:
                        self.debug_print("CR/LF received on iteration: {} - terminating loop".format(counter))
                        self.save_progress("CR/LF received on iteration: {} - terminating loop".format(counter))
                        break
                    else:
                        self.debug_print("CR/LF received on iteration {} - continuing".format(counter))
                        self.save_progress("CR/LF received on iteration {} - continuing".format(counter))
                        continue

                resp_data += chunk

                ret_val, resp_data = self._parse_resp_data(resp_data)

                if (phantom.is_fail(ret_val)):
                    self.debug_print("On Poll failed for the chunk: ", chunk)
                    self.save_progress("On Poll failed for the chunk: ", chunk)
                    return self.set_status(phantom.APP_ERROR, CROWDSTRIKE_UNABLE_TO_PARSE_DATA)

                if resp_data and resp_data.get('metadata', {}).get('eventType') == 'DetectionSummaryEvent':
                    self._events.append(resp_data)
                    counter = 0   # reset the continuous blank lines counter as we received a valid data in between

                # Calculate length of DetectionSummaryEvents until now
                len_events = len(self._events)

                if max_events and len_events >= max_events:
                    self._events = self._events[:max_events]
                    break

                self.send_progress("Pulled {0} events of type 'DetectionSummaryEvent'".format(len(self._events)))
                self.debug_print("Pulled {0} events of type 'DetectionSummaryEvent'".format(len(self._events)))
                # convert it to string
                resp_data = ''
        except Exception as e:
            err_msg = e.message if e.message else "Unknown error occurred."
            return self.set_status(phantom.APP_ERROR, "{}. Error response from server: {}".format(
                                        CROWDSTRIKE_ERR_EVENTS_FETCH, UnicodeDammit(err_msg).unicode_markup.encode('utf-8')))

        # Check if to collate the data or not
        collate = config.get('collate', True)

        self.send_progress(" ")

        self.debug_print("Total blank lines count: {}".format(total_blank_lines_count))
        self.save_progress("Total blank lines count: {}".format(total_blank_lines_count))
        self.debug_print("Got {0} events of type 'DetectionSummaryEvent'".format(len(self._events)))   # total events count
        self.save_progress("Got {0} events of type 'DetectionSummaryEvent'".format(len(self._events)))

        if self._events:
            self.send_progress("Parsing the fetched DetectionSummaryEvents...")
            results = events_parser.parse_events(self._events, self, collate)
            self.save_progress("Created {0} relevant results from the fetched DetectionSummaryEvents".format(len(results)))
            if (results):
                self.save_progress("Adding {0} event artifact{1}. Empty containers will be skipped.".format(len(results), 's' if len(results) > 1 else ''))
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

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CrowdstrikeConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
