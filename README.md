# pyHttpServ
<h3>Python 3 basic HTTP server with websocket handling</h3>

<b>How to run?</b><br>
python run.py

This is a basic HTTP server with built-in websocket handler, HTTP server supports only method GET and a short list of mime-types, and it can 
upgrade a connection to websocket on browser request so there is no need for a second port for websocket connections. Port is 8080 by default, but 80 is possible if sudo ofc. The default setting is to restrict IP access with a ban list and set what IP addresses to allow, but this is easily changed if wanting to give access to all IP. 

It is easy to add more mime-types to the list upon need, and it is possible to develop and add support for method POST e.g. It is also possible to add an SSL port and add support for php scripts, but those things take a little more elbow grease to code.

The websocket server takes the RFC standard browser websocket encoding and there is really no need to bloat the sent data with more base64 encoding etc, but the websocket server demands all transfers to be in form of standard JSON string enclosed in curly brackets {}, anything else wont be processed.

The idea is that the JSON must contain at least two variables, "cmd" and "msg", but it is easy to customize and add whatever variables you want, make the websock server do something other than a chat ofc, make server parse the JSON for whatever other functions/commands the websocket server would need.

<b>This server is reloadable</b>, i.e. you can edit the source code in "pyHttpServ.py" and reload it <b><i>without</i></b> needing to actually <b>take down</b> the server even for a second, it will keep any existing websocket connections and continue processing them after reloading source code. When server is running, in the terminal you can do "ctr-c" to interrupt the server, it will ask you if you want to quit, type "y" or "yes" to shut it down, or just hit enter to reload source. This is very cool and very neat for developing since you can do lots of changes without needing to spend those extra seconds on shutting down and restarting for testing every little change, just reload.

Included is a html demo file "index.html" with a large picture file, and a html websocket demo "chat.html" with a basic websocket chat.
