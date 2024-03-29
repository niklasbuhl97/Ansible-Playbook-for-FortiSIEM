#!/usr/bin/env python3
################################################################################
#
# This program can be used under the GNU General Public License version 2
# You can find full information here: http://www.gnu.org/licenses/gpl-2.0.html
# Copyright (C) 2024 Egor Puzanov.
#
################################################################################

import hashlib
import re
from wsgiref.simple_server import make_server

class application(object):
    def __init__(self, environ, start_response):
        self.environ = environ
        self.start_response = start_response

    def __iter__(self):
        status = "200 OK"
        headers = [('Content-type', 'text/xml; charset=utf-8')]
        exc_info = None
        if self.environ["PATH_INFO"] == "/phoenix/rest/query/eventQuery":
            try:
                request_body_size = int(self.environ.get('CONTENT_LENGTH', 0))

            except (ValueError):
                request_body_size = 0
            print(self.environ.get("wsgi.input"))

            data = self.environ.get("wsgi.input").read(request_body_size).decode()
            requestId = self.getRequestId(data)
            print(requestId)    
            body ="""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<response requestId="%s" timestamp="1696512579291">
    <result>
        <error code="0"/>
        <expireTime>1696530578984</expireTime>
    </result>
</response>"""% requestId
   
        elif self.environ["PATH_INFO"].startswith("/phoenix/rest/query/progress/"):
            body = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<response requestId="%s" timestamp="1696513338479">
    <result>
        <error code="0"/>
        <expireTime>1696531310789</expireTime>
        <progress>100</progress>
    </result>
</response>"""%self.environ["PATH_INFO"][29:35]
        elif self.environ["PATH_INFO"].startswith("/phoenix/rest/query/events/"):
            try:
                with open("%s.xml"%self.environ["PATH_INFO"][27:33], "r") as f:
                    body = f.read()
            except:
                status = "404 Not Found"
                body = status
        else:
            status = "404 Not Found"
            body = status
        self.start_response(status, headers, exc_info)
        yield body.encode("utf-8")

    def getRequestId(self, input):
        query = input[input.find("<SingleEvtConstr>"):input.find("</SingleEvtConstr>")][len("<SingleEvtConstr>"):]
        hash_object = hashlib.md5()
        hash_object.update(query.encode())
        return re.sub(r"\D", "", hash_object.hexdigest())[:6]

def main():
    server = make_server("0.0.0.0", 8080, application)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()

if __name__ == "__main__":
    print("serving on Port 8080...")
    main()
