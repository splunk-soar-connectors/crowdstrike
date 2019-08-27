# File: crowdstrike_consts.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Json keys specific to the app's input parameters/config and the output result
CROWDSTRIKE_JSON_URL = "url"

CROWDSTRIKE_FILTER_REQUEST_STR = '{0}rest/container?page_size=0'\
                                 '&_filter_asset={1}'\
                                 '&_filter_name__contains="{2}"'\
                                 '&_filter_start_time__gte="{3}"'

# Status messages for the app
CROWDSTRIKE_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
CROWDSTRIKE_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
CROWDSTRIKE_ERR_CONNECTING = "Error connecting to server"
CROWDSTRIKE_ERR_FROM_SERVER = "Error from Server, Status Code: {status}, Message: {message}"
CROWDSTRIKE_UNABLE_TO_PARSE_DATA = "Unable to parse data from server"

# Progress messages format string
CROWDSTRIKE_USING_BASE_URL = "Using base url: {base_url}"

CROWDSTRIKE_BASE_ENDPOINT = "/sensors/entities/datafeed/v1"
CROWDSTRIKE_ERR_RESOURCES_KEY_EMPTY = "Resources key empty or not present"
CROWDSTRIKE_ERR_DATAFEED_EMPTY = "Datafeed key empty or not present"
CROWDSTRIKE_ERR_META_KEY_EMPTY = "Meta key empty or not present"
CROWDSTRIKE_ERR_SESSION_TOKEN_NOT_FOUND = "Session token, not found"
CROWDSTRIKE_MSG_GETTING_EVENTS = "Getting maximum {max_events} events from id {lower_id} onwards (ids might not be contiguous)"
CROWDSTRIKE_NO_MORE_FEEDS_AVAILABLE = "No more feeds available"
CROWDSTRIKE_JSON_UUID = "uuid"
CROWDSTRIKE_JSON_API_KEY = "api_key"
CROWDSTRIKE_JSON_ACCESS = "access"
CROWDSTRIKE_ERR_CONN_FAILED = "Please make sure the system time is correct."
CROWDSTRIKE_ERR_CONN_FAILED += "\r\nCrowdStrike credentials validation might fail in case the time is misconfigured."
CROWDSTRIKE_ERR_CONN_FAILED += "\r\nYou can also try choosing a different Access Type"

DEFAULT_POLLNOW_EVENTS_COUNT = 2000
DEFAULT_EVENTS_COUNT = 10000
