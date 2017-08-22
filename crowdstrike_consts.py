# --
# File: crowdstrike_consts.py
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

# Json keys specific to the app's input parameters/config and the output result
CROWDSTRIKE_JSON_URL = "url"
CROWDSTRIKE_JSON_DEF_NUM_DAYS = "interval_days"
CROWDSTRIKE_JSON_MAX_EVENTS = "max_events"

CROWDSTRIKE_FILTER_REQUEST_STR = 'https://127.0.0.1/rest/container?page_size=0'\
                                 '&_filter_asset={0}'\
                                 '&_filter_name__contains="{1}"'\
                                 '&_filter_start_time__gte="{2}"'

# Status messages for the app
CROWDSTRIKE_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
CROWDSTRIKE_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
CROWDSTRIKE_ERR_CONNECTING = "Error connecting to server"
CROWDSTRIKE_ERR_FROM_SERVER = "Error from Server, Status Code: {status}, Message: {message}"
CROWDSTRIKE_ERR_END_TIME_LT_START_TIME = "End time less than start time"
CROWDSTRIKE_UNABLE_TO_PARSE_DATA = "Unable to parse data from server"

# Progress messages format string
CROWDSTRIKE_USING_BASE_URL = "Using base url: {base_url}"

CROWDSTRIKE_BASE_ENDPOINT = "/sensors/entities/datafeed/v1"
CROWDSTRIKE_ERR_RESOURCES_KEY_EMPTY = "Resources key empty or not present"
CROWDSTRIKE_ERR_DATAFEED_EMPTY = "Datafeed key empty or not present"
CROWDSTRIKE_ERR_META_KEY_EMPTY = "Meta key empty or not present"
CROWDSTRIKE_ERR_SESSION_TOKEN_NOT_FOUND = "Session token, not found"
CROWDSTRIKE_MSG_GETTING_EVENTS = "Getting maximum {max_events} events from id {lower_id} onwards (ids might not be contiguous)"
CROWDSTRIKE_MILLISECONDS_IN_A_DAY = 86400000
CROWDSTRIKE_NUMBER_OF_DAYS_BEFORE_ENDTIME = 1
CROWDSTRIKE_DEFAULT_ARTIFACT_COUNT = 100
CROWDSTRIKE_DEFAULT_CONTAINER_COUNT = 10
CROWDSTRIKE_NO_MORE_FEEDS_AVAILABLE = "No more feeds available"
CROWDSTRIKE_DEF_ACCESS = "user"
CROWDSTRIKE_JSON_UUID = "uuid"
CROWDSTRIKE_JSON_API_KEY = "api_key"
CROWDSTRIKE_JSON_ACCESS = "access"
CROWDSTRIKE_ERR_CONN_FAILED = "Please make sure the system time is correct."
CROWDSTRIKE_ERR_CONN_FAILED += "\r\nCrowdStrike credentials validation might fail in case the time is misconfigured."
CROWDSTRIKE_ERR_CONN_FAILED += "\r\nYou can also try choosing a different Access Type"

MAX_COUNT_VALUE = 4294967295
MAX_POLLNOW_LOOP = 10
