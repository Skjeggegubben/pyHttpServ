#!/usr/bin/env python
# -*- coding: utf-8 -*-

import traceback, time
from importlib import reload
import pyHttpServ

server = pyHttpServ.Server()
while True:
	try:
		server.run()
	except (KeyboardInterrupt, Exception):
		print("\r\n--------------------------------------------------------\n "+\
			  "QUIT? ('y' to QUIT, or just hit ENTER to RELOAD)")
		x = input("[quit] ")
		if x.lower() == 'y' or x.lower() == 'yes':
			break
		else:
			server.running = False
			time.sleep(1)
			print("\r\n\r\n ******* SERVER RELOADING! ******* \r\n")
			reload(pyHttpServ)
			old = server
			server = pyHttpServ.Server()
			server.wsClientArr = old.wsClientArr
			continue
server.shutDown()