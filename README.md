[comment]: # "Auto-generated SOAR connector documentation"
# Crowdstrike Streaming API

Publisher: Splunk  
Connector Version: 2\.0\.6  
Product Vendor: CrowdStrike  
Product Name: FalconHost  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.8\.23403  

This app integrates with CrowdStrike security services to implement ingestion of endpoint security data

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2020 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Preprocess Script

The user can add a script file in the configuration parameter **Script with functions to preprocess
containers and artifacts** . The script must contain a function with the name
**preprocess_container** (to pre-process the containers and the artifacts) or else, it will throw an
error.

## App ID

-   Optionally, you can specify an **App ID** to be used with the Streaming API. If one isn't set,
    it will default to the asset id.
-   It is recommended to have a unique **App ID** for each connection to the Streaming API. That is
    to say, if you are planning on having multiple assets using the Streaming API at once, you
    should give them unique App IDs.

## On Poll

-   Common points for both manual and scheduled interval polling
    -   Default parameters of the On Poll action are ignored in the app. i.e. start_time, end_time,
        container_count, artifact_count
    -   The app will fetch all the events based on the value specified in the configuration
        parameters \[Maximum events to get while POLL NOW\] (default 2000 if not specified) and
        \[Maximum events to get while scheduled and interval polling\] (default 10,000 if not
        specified). For ingestion, the events are fetched after filtering them based on the event
        type - **DetectionSummaryEvent** . The app will exit from the polling cycle in the
        below-mentioned 2 cases whichever is earlier.
        -   If the total DetectionSummaryEvents fetched equals the value provided in the \[Maximum
            events to get while POLL NOW\] (for manual polling) or \[Maximum events to get while
            scheduled and interval polling\] (for scheduled \| interval polling) parameters
        -   If the total number of continuous blank lines encountered while streaming the data
            equals the value provided in the \[Maximum allowed continuous blank lines\] (default 50
            if not specified) asset configuration parameter
    -   The default behavior of the app is that each event will be placed in its container. By
        checking the configuration parameter \[Merge containers for Hostname and Eventname\] as well
        as specifying an interval in the configuration parameter \[Merge same containers within
        specified seconds\], all events which are of the same type and on the same host will be put
        into one container, as long as the time between those two events is less than the interval.
    -   The \[Maximum allowed continuous blank lines\] parameter will be used to indicate the
        allowed number of continuous blank lines while fetching **DetectionSummaryEvents** . For
        example, of the entire data of the DetectionSummaryEvents, some of the
        'DetectionSummaryEvents' exists after 100 continuous blank lines and if you've set the
        \[Maximum allowed continues blank lines\] parameter value to 500, it will keep on ingesting
        all the 'DetectionSummaryEvents' until the code gets 500 continuous blank lines and hence,
        it will be able to cover the DetectionSummaryEvents successfully even after the 100 blank
        lines. If you set it to 50, it will break after the 50th blank line is encountered. Hence,
        it won't be able to ingest the events which exist after the 100 continuous blank lines
        because the code considers that after the configured value in the \[Maximum allowed
        continuous blank lines\] configuration parameter (here 50), there is no data available for
        the 'DetectionSummaryEvents'.
-   Manual Polling
    -   During manual poll now, the app starts from the 1st event that it can query up to the value
        configured in the configuration parameter \[Maximum events to get while POLL NOW\] and
        creates artifacts for all the fetched DetectionSummaryEvents. The last queried event's
        offset ID will not be remembered in Manual POLL NOW and it fetches everything every time
        from the beginning.
-   Scheduled \| Interval Polling
    -   During scheduled \| interval polling, the app starts from the 1st event that it can query up
        to the value configured in the configuration parameter \[Maximum events to get while
        scheduled and interval polling\] and creates artifacts for all the fetched
        DetectionSummaryEvents. Then, it remembers the last event's offset ID and stores in the
        state file against the key \[last_offset_id\]. In the next scheduled poll run, it will start
        from the stored offset ID in the state file and will fetch the maximum events as configured
        in the \[Maximum events to get while scheduled and interval polling\] parameter.

The **DetectionSummaryEvent** is parsed to extract the following values into an Artifact.  

| **Artifact Field** | **Event Field** |
|--------------------|-----------------|
| cef.sourceUserName | UserName        |
| cef.fileName       | FileName        |
| cef.filePath       | FilePath        |
| cef.sourceHostName | ComputerName    |
| cef.sourceNtDomain | MachineDomain   |
| cef.hash           | MD5String       |
| cef.hash           | SHA1String      |
| cef.hash           | SHA256STring    |
| cef.cs1            | cmdLine         |

The App also parses the following **sub-events** into their own Artifacts.  

-   Documents Accessed
-   Executables Written
-   Network Access
-   Scan Result
-   Quarantine Files
-   DNS Requests

Each of the sub-events has a CEF key called **parentSdi** that stands for Parent Source Data
Identifier. This is the value of the SDI of the main event that the sub-events were generated from.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a FalconHost asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Base URL
**uuid** |  required  | string | UUID
**api\_key** |  required  | password | API Key
**access** |  required  | string | Access Type
**app\_id** |  optional  | string | App ID
**max\_events** |  optional  | numeric | Maximum events to get for scheduled and interval polling
**max\_events\_poll\_now** |  optional  | numeric | Maximum events to get while POLL NOW
**collate** |  optional  | boolean | Merge containers for hostname and eventname
**merge\_time\_interval** |  optional  | numeric | Merge same containers within specified seconds
**max\_crlf** |  optional  | numeric | Maximum allowed continuous blank lines
**preprocess\_script** |  optional  | file | Script with functions to preprocess containers and artifacts

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action logs into the site to check the connection and credentials  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action logs into the site to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

This action remembers the last event ID that was queried for\. The next ingestion carried out will query for later event IDs\. This way the same events are not queried for in every run\. However, in case of 'POLL NOW' queried event IDs will not be remembered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_count** |  optional  | Parameter ignored in this app | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output