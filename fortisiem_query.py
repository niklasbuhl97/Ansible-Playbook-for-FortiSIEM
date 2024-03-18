#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
#
# Copyright: (C) 2024 Egor Puzanov.
# GNU General Public License v3.0+ (https://www.gnu.org/licenses/gpl-3.0.txt)
#
################################################################################

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: fortisiem_query
short_description: Run FortiSIEM queries
description:
- Execute a query to FortiSIEM using the provided data.
- Retrieves events that match the specified criteria and returns a list of Event objects.
version_added: '???'
options:
  appServer:
    description:
    - FortiSIEM supervisor URL
    type: str
    required: True
  username:
    description:
    - user name
    type: str
    required: False
    default: ''
  password:
    description:
    - user password
    type: str
    required: False
    default: ''
  verify_cert:
    description:
    - Verify Certificate
    type: bool
    required: False
    default: True
  custId:
    description:
    - Customer ID
    type: str
    required: False
    default: 'all'
  query:
    description:
    - specified criteria for returning a list of Event objects
    type: str
    required: False
author:
- (@)
'''

EXAMPLES = r'''
# For test run use the FortiSIEM Mockup.
# The following examples deploy various search queries to FortiSIEM Mockup
- name: FortiSIEM Query1
  hosts: localhost
  tasks:
  - fortisiem_query:
      appServer: http://D76778.local:8080/phoenix/rest
      query: infoURL CONTAIN "malicious.site"
    register: results
  - debug:
      var: results.results

- name: FortiSIEM Query_2
  hosts: localhost
  tasks:
  - fortisiem_query:
      appServer: http://D76778.local:8080/phoenix/rest
      query: "phEventCategory=1 AND incidentId IN (2929711)"
    register: results
  - debug:
      var: results.results
'''

RETURN = r'''

results:
    description: List of Event objects matching the query criteria
    type: list
    sample: ansible-playbook siem_query.yml
    returned: always
'''

import os
import sys
import re
import configparser
import base64
import ssl
import time
import json
import urllib.parse
from datetime import datetime, date
import xml.etree.cElementTree as et
from xml.dom.minidom import Node, Document, parse
from urllib.request import build_opener, Request, HTTPPasswordMgrWithDefaultRealm, HTTPBasicAuthHandler, HTTPSHandler, ProxyHandler
from ansible.module_utils.basic import AnsibleModule

class Client(object):

    '''FortiSIEM client library for use in writing client applications'''

    def __init__(self, appServer, username, password, verify_cert=True, custId="all"):

        '''Initialize to connect an app server

        Parameters:
        - appServer (str): FortiSIEM supervisor URL (Mandatory)
        - username (str): user name (Mandatory)
        - password (str): user password (Mandatory)
        - verify_cert (bool): Verify Certificate (Default: True)
        - custId (str): customer ID (Default: "all")

        Returns:
        - self._opener (client): Builds an opener for handling http requests

        This method builds an opener for handling http requests using given parameters and urllib.
        If the given parameter of verify_cert is not True, the ssl context checker will be set on False.'''

        self.custId = custId
        self.base_url = appServer
        self._headers = {"Content-Type": "text/xml"}
        password_mgr = HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, appServer, username, password)
        authhandler = HTTPBasicAuthHandler(password_mgr)
        sslcontext = ssl.create_default_context()
        if not verify_cert:
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
        self._opener = build_opener(authhandler,
            HTTPSHandler(context=sslcontext))


    def query(self, data):

        '''Execute a query using provided data

        Parameters:
        - data (str): data containing query details (Mandatory)

        Returns:
        - results (list): List of Event objects matching the query criteria

        This method executes a query to FortiSIEM using the provided data.
        It retrieves events that match the specified criteria and returns a list of Event objects.'''

        results = []
        print(data.toxml().encode())
        req = Request("%s/query/eventQuery"%self.base_url, data.toxml().encode(), self._headers)
        try:
            response = Response(self._opener.open(req))
            if response.isValid():
                req = Request("%s/query/progress/%s"%(self.base_url, response.getQueryId()))
                response = Response(self._opener.open(req))
                while response.inProgress():
                    response = Response(self._opener.open(req))
                    time.sleep(5)
                queryId = response.getQueryId()
                while response.hasNext():
                    req = Request("%s/query/events/%s/%s/%s"%(self.base_url, queryId, response.getNextStart(), response.getCount()))
                    response = Response(self._opener.open(req))
                    for event in response.getEvents():
                        if "incidentId" in event.attributes:
                            req = Request("%s/incident/triggeringEvents?incidentIds=%s"%(self.base_url, event.attributes["incidentId"]))
                            teResponse = self._opener.open(req)
                            if teResponse.status == 200:
                                triggerEvents = teResponse.read().decode("UTF-8")
                                triggerEventsEnd = triggerEvents.find("</triggerEvents>")
                                if triggerEventsEnd > 0:
                                    triggerEvents = triggerEvents[:triggerEventsEnd]
                                    triggerEvents = triggerEvents[triggerEvents.rfind(">") + 1:]
                                    if triggerEvents:
                                        event.attributes["triggeringEventList"] = triggerEvents
                        results.append(event)
        except Exception as e:
            print(e)
        return results


class RequestBody(object):

    '''This class represents the request body for querying events to FortiSIEM'''

    def __init__(self, query, intervalLow=-7200, intervalHigh=None, attributes=[], custId="all"):

        ''' Initialize a request body for querying

        Parameters:
        - query (str): Query string to filter events
        - intervalLow (int): Lower bound of the time interval (Default: -120 Min)
        - intervalHigh (int): Upper bound of the time interval (Default: None)
        - attributes (list): List of attributes to retrieve (Default: [])

        This method initialize a request body for querying events by given parameters.'''

        self._doc = Document()
        reports = self._doc.createElement("Reports")
        self._doc.appendChild(reports)
        report = self._doc.createElement("Report")
        report.setAttribute("baseline", "")
        report.setAttribute("rsSync", "")
        reports.appendChild(report)
        name = self._doc.createElement("Name")
        report.appendChild(name)
        nameText = self._doc.createTextNode("All Incidents")
        custScope = self._doc.createElement("CustomerScope")
        custScope.setAttribute("groupByEachCustomer", "true")
        report.appendChild(custScope)
        include = self._doc.createElement("Include")
        include.setAttribute("all", "true")
        custScope.appendChild(include)
        exclude = self._doc.createElement("Exclude")
        custScope.appendChild(exclude)
        description = self._doc.createElement("description")
        report.appendChild(description)
        select = self._doc.createElement("SelectClause")
        select.setAttribute("numEntries", "All")
        report.appendChild(select)
        attrList = self._doc.createElement("AttrList")
        attrList.setAttribute("numEntries", ",".join(attributes))
        select.appendChild(attrList)
        reportInterval = self._doc.createElement("ReportInterval")
        report.appendChild(reportInterval)
        if intervalHigh is None:
            intervalHigh = int(time.time())
        if intervalLow is None:
            intervalLow = -7200
        if intervalLow < 0:
            intervalLow = int(intervalHigh + intervalLow)
        low = self._doc.createElement("Low")
        reportInterval.appendChild(low)
        lowText = self._doc.createTextNode(str(int(intervalLow)))
        low.appendChild(lowText)
        high = self._doc.createElement("High")
        reportInterval.appendChild(high)
        highText = self._doc.createTextNode(str(int(intervalHigh)))
        high.appendChild(highText)
        pattern = self._doc.createElement("PatternClause")
        pattern.setAttribute("window", "3600")
        report.appendChild(pattern)
        subPattern = self._doc.createElement("SubPattern")
        subPattern.setAttribute("displayName", "Events")
        subPattern.setAttribute("name", "Events")
        pattern.appendChild(subPattern)
        single = self._doc.createElement("SingleEvtConstr")
        subPattern.appendChild(single)
        if(custId != "all"):
            query += " and phCustId=" + str(custId)
        singleText = self._doc.createTextNode(query)
        single.appendChild(singleText)
        filter = self._doc.createElement("RelevantFilterAttr")
        report.appendChild(filter)

    def toxml(self):

        '''Convert the request body to XML format

        Returns:
        - xml_string (str): XML representation of the request body

        This method converts the request body object into an XML string format to transfer data to FortiSIEM'''

        return self._doc.toxml()


class Incident(object):

    '''Represent an incident from FortiSIEM'''

    def __init__(self, iDict):

        '''Initialize an incident object

        Parameters:
        - iDict (dict): Dictionary from FortiSIEM containing incident details

        Returns:
        - Incident(incident): erzeugt Instanz für Incident-Objekt

        This method represent an incident by given Parameters from FortiSIEM'''

        self.incidentTitle = iDict["incidentTitle"]
        self.eventSeverity = iDict["eventSeverity"]
        try:
            self.incidentFirstSeen = datetime.fromtimestamp(int(iDict["incidentFirstSeen"])/1000)
        except:
            self.incidentFirstSeen = datetime.strptime(iDict["incidentFirstSeen"], "%a %b %d %H:%M:%S %Z %Y")
        self.incidentReso = iDict["incidentReso"]
        self.incidentRptIp = iDict["incidentRptIp"]
        try:
            self.incidentLastSeen = datetime.fromtimestamp(int(iDict["incidentLastSeen"])/1000)
        except:
            self.incidentLastSeen = datetime.strptime(iDict["incidentLastSeen"], "%a %b %d %H:%M:%S %Z %Y")
        self.incidentSrc = iDict["incidentSrc"]
        self.count = iDict["count"]
        self.eventType = iDict["eventType"]
        self.phIncidentCategory = iDict["phIncidentCategory"]
        try:
            self.incidentClearedTime = datetime.fromtimestamp(int(iDict["incidentClearedTime"])/1000)
        except:
            self.incidentClearedTime = datetime.strptime(iDict["incidentClearedTime"], "%a %b %d %H:%M:%S %Z %Y")
        self.incidentTarget = iDict["incidentTarget"]
        self.phSubIncidentCategory = iDict["phSubIncidentCategory"]
        self.eventSeverityCat = iDict["eventSeverityCat"]
        self.incidentDetail = iDict["incidentDetail"]
        self.incidentRptDevName = iDict["incidentRptDevName"]
        self.eventName = iDict["eventName"]
        self.incidentId = iDict["incidentId"]
        self.incidentStatus = iDict["incidentStatus"]
        self.customer = iDict["customer"]
        self.triggeringEvents = []



class Error(object):
    '''This class represents an Error object'''
    def __init__(self, element):
        '''Initialize an Error object based on an XML element.

        Parameters:
        - element (xml.etree.ElementTree.Element): XML element representing an error

        This method initialize an Error object containing information about an error as per the XML element.'''

        self.code = int(element.attrib.get("code", "0"))
        self.description = element.findtext("description", "")

class Event(object):

    '''This class represents an Event object'''

    def __init__(self, element):

        '''Initialize an Event object with data from an XML element or dictionary.

        Parameters:
        - element (dict) dictionary containing event details.

        This method initialize an event object containing information about an event retrieved from an dictionary or XML element .'''

        if isinstance(element, dict):
            self.custId = element.get("custId", 0)
            self.dataStr = element.get("dataStr", {})
            self.eventType = element.get("eventType", "")
            self.id = element.get("id", 0)
            self.nid = element.get("nid", 0)
            self.receiveTime = datetime.fromtimestamp(int(element.get("receiveTime", 0)) / 1000)
            self.attributes = element.get("attributes", {})
        else:
            self.custId = int(element.findtext("custId", "0"))
            self.dataStr = element.findtext("dataStr", "")
            self.eventType = element.findtext("eventType", "")
            self.id = int(element.findtext("id", "0"))
            self.nid = int(element.findtext("nid", "0"))
            self.receiveTime = datetime.fromisoformat(element.findtext("receiveTime", datetime.now().isoformat()))
            self.attributes = {}
            for attr in element.iter("attribute"):
                self.attributes[attr.attrib["name"]] = attr.text

class QueryResult(object):

    '''This class represents a QueryResult object.'''

    def __init__(self, element):

        '''Initialize a QueryResult object

        Parameters:
        - element (xml.etree.ElementTree.Element): XML element containing query result details

        This method initialize a query result object containing information about query results retrieved from an XML element.'''

        self.count = 1000
        if not isinstance(element, et.Element):
            element = et.parse(element).getroot()
        self.errorCode = int(element.attrib.get("errorCode", "0"))
        self.queryId = int(element.attrib.get("queryId", "0"))
        self.start = int(element.attrib.get("start", 0 - self.count))
        self.totalCount = int(element.attrib.get("totalCount", "0"))
        self.events = []
        for event in element.iter("event"):
            self.events.append(Event(event))

    def getCount(self):

        '''Get the count of events.

        Returns:
        - count (int): Number of events in the query result

        This method retrieves the count of events present in the query result.'''

        return self.count

    def getEvents(self):

        '''Retrieve the list of events

        Returns:
        - events (list): List of event objects

        This method retrieves the list of events present in the query result.'''

        return self.events

    def getNextStart(self):

        '''Get the starting index for the next page of events.

        Returns:
        - nextStart (int): Starting index for the next page of events

        This method retrieves the starting index for the next page of events in the query result.'''

        return self.start + self.count

    def hasNext(self):

        '''Check if there are more events available

        Returns:
        - (bool): True if there are more events, False otherwise

        This method checks whether there are more events available beyond the current page in the query result.'''

        return self.start + self.count <= self.totalCount

class Result(object):

    '''This class represents a Result object'''

    def __init__(self, element):

        '''Initialize a Result object based on an XML element.

        Parameters:
        - element (xml.etree.ElementTree.Element): XML element containing result details

        This method represents a Result object containing information based on the provided XML element.'''

        error = element.find("error")
        self.error = Error(error) if error is not None else None
        self.progress = int(element.findtext("progress", "0"))
        self.expireTime = int(element.findtext("expireTime", "0"))
        self.queryResult = element.find("queryResult")
        if self.queryResult is not None:
            self.queryResult = QueryResult(self.queryResult)

class Response(object):

    '''This class represents a Response object.'''

    def __init__(self, response):

        '''Initialize a Response object based on a server response.

        Parameters:
        - resonse (http.client.HTTPResponse): return HTTP-Response object

        This method represents a Response object containing information based on the provided server response.'''

        self.requestId = ""
        self.timestamp = 0
        self.status = response.status
        element = et.parse(response).getroot()
        self.requestId = element.attrib.get("requestId", "0")
        self.timestamp = element.attrib.get("timestamp", "0")
        print(et.tostring(element).decode())
        self.result = element.find("result")
        if self.result is not None:
            self.result = Result(self.result)

    def inProgress(self):

        '''Check if the response indicates an ongoing process.

        Returns:
        - is_in_progress (bool): True if the process is ongoing, False otherwise

        This method checks whether the response indicates that the associated process is still in progress.'''

        return getattr(self.result, "progress", 100) != 100

    def isValid(self):

        '''Check if the response is valid.

        Returns:
        - is_valid (bool): True if the response is valid, False otherwise

        This method checks whether the response is considered valid based on its status and content.'''

        return self.status == 200 and self.result and getattr(self.result.error, "code", 255) == 0

    def getCount(self):

        '''Get the count of events.

        Returns:
        - count (int): Number of events in the query result

        This method retrieves the count of events present in the query result.'''

        return self.result.queryResult.getCount() if self.result and self.result.queryResult else 1000

    def getQueryId(self):

        '''Get the query identifier associated with the response.

        Returns:
        - query_id (str): Query identifier derived from the response

        This method retrieves the query identifier associated with the current response.'''

        return "%s,%s"%(self.requestId, getattr(self.result, "expireTime", 0))

    def getEvents(self):

        '''Retrieve the list of events

        Returns:
        - events (list): List of Event objects

        This method retrieves the list of events present in the query result.'''

        if self.result and self.result.queryResult:
            return self.result.queryResult.getEvents()
        return []

    def getNextStart(self):

        '''Get the starting index for the next page of events.

        Returns:
        - next_start (int): Starting index for the next page of events

        This method retrieves the starting index for the next page of events in the query result.'''

        return self.result.queryResult.getNextStart() if self.result and self.result.queryResult else 0

    def hasNext(self):

        '''Check if there are more events available

        Returns:
        - has_more_events (bool): True if there are more events, False otherwise

        This method checks whether there are more events available beyond the current page in the query result.'''

        if getattr(self.result, 'queryResult', None) is None and getattr(self.result, 'progress', 0) == 100:
            return True
        return self.result.queryResult.hasNext() if self.result and self.result.queryResult else False

def main():

    '''Main function for executing Ansible module.

    Returns:
            None

    This function utilizes Ansible Module to initialize input arguments and return results.

    Input arguments include appServer, username, password, verify_cert, custId, and query from Ansible Playbook.
    The function attempts to establish a connection to the specified appServer and perform a query.
    The result is returned as a list of event attributes.'''

    module = AnsibleModule(
        argument_spec = dict(
            appServer = dict(required=True, type='str'),
            username = dict(required=False, type='str', default=''),
            password  = dict(required=False, type='str', default=''),
            verify_cert = dict(required=False, type='bool', default=True),
            custId = dict(required=False, type='str', default='all'),
            query = dict(required=False, type='str'),
            attributes = dict(required=False, type='list', default=[]),
            intervalLow = dict(required=False, type='int', default=None),
            intervalHigh = dict(required=False, type='int', default=None),
        )
    )

    appServer = module.params['appServer']
    username = module.params['username']
    password = module.params['password']
    verify_cert = module.params['verify_cert']
    custId = module.params['custId']
    query = module.params['query']
    attributes = module.params['attributes']
    intervalLow = module.params['intervalLow']
    intervalHigh = module.params['intervalHigh']

    results = []


    try:
        cl = Client(appServer, username, password, verify_cert)
        rb = RequestBody(query, intervalLow, intervalHigh, attributes, custId)
        events = cl.query(rb)
        for event in events:
            filteredAttributes = {}
            if not attributes:
                filteredAttributes.update(event.attributes)
            else:
                for attr in attributes:
                    filteredAttributes[attr] = event.attributes.get(attr)
                    if attr not in filteredAttributes:
                        filteredAttributes[attr] = getattr(event, attr)
            results.append(filteredAttributes)
        module.exit_json(changed=False, events=results)
    except Exception as e:
        module.fail_json(msg=e)

if __name__ == "__main__":
    main()
