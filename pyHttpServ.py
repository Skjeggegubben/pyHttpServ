# coding: utf-8
import time, socket, uuid, sys, os, threading, struct, string, select, random, datetime, json
from threading import Thread
from hashlib import sha1
from base64 import b64encode, b64decode
from pytz import timezone

httpPort = 8080 # Same port for both http and websocket. Needs sudo if port 80
srvrTimeZone = 'Europe/Oslo' # Local timezone for the timestamps
webSockPerIP = 4 # Could special cases require moar websocket connections?
allow_ALL_ip = False # If set to True, all IP's (even banned) are allowed
allowed_ip_addresses = ["127.0.0.1", "192.168.0.1"]
allow_all_ip_starting_with = ["192.168.0.", "84.210.71."]
banListFile = "banned_ip_addresses.txt" # Manually added nasty scanners/crawlers


class Server():
	BUFLEN = 4096 # Read and write buffer size, but also file chunk sending size, don't change it.
	wsClientArr = []
	running = True
	
	def __init__(self):
		print("Server starting!")
	
	def shutDown(self):
		self.running = False
	
	def run(self):
		try:
			listenSock = socket.socket(socket.AF_INET)
			listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.BUFLEN)  # Buffer size 4096
			listenSock.bind(("0.0.0.0", httpPort))
			print("Listening for browsers on port %d."%( httpPort ) )
			listenSock.listen(0)
			
			Thread(target=WebsocketHandler, args=(self, )).start() # Start up the websocket thread			
		except Exception as e:
			print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno) + " '" + str(e) + "'")
			return

		while self.running:
			try:
				readable, writable, errors = select.select([listenSock], [], [])
				for s in readable:
					connection, client_address = s.accept()
					Thread(target=HTTPrequestHandler, args=(self, connection, client_address,)).start()
			except Exception as e:
				pass



class HTTPrequestHandler:
	html404 = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
	<html>
		<head><title>404 - Ouch! File Not Found</title>
			<style type="text/css">div { width:40vw; margin:40vh auto; padding:9px; border-radius:9px; box-shadow:9px 15px 20px 9px black} p { border-top:1px solid black; }</style>
		</head>
		<body>
			<div><h1>File Not Found!</h1><p>C:\\404.html</p></div>
		</body>
	</html>"""
	
	def __init__(self, server, theSock, address ):
		self.server = server
		self.ip = address[0]
		self.clientSock = theSock
		self.reqId = "'" + ''.join(random.choice( string.ascii_uppercase + string.ascii_lowercase + string.digits ) for _ in range(10)) + "'"
		print("\n"+timeStamp()+" -reqId: " + self.reqId + " IP: " + self.ip)
		
		if (not allow_ALL_ip):
			if ( not self.ipAllowed() ):
				self.killSocket("-killing a blocked IP"); return
		try:
			self.clientSock.settimeout(3) #3 sec!
		except Exception as e:
			self.killSocket("Could not set timeout on socket, so FU disobeying client!")
			return
		self.receiveBuffer = ""
		try:
			while (1):
				buff1 = self.clientSock.recv(self.server.BUFLEN)
				if (not buff1) | (buff1 == -1):
					self.killSocket("Client is dead/disconnected"); break
				if( len(buff1)> 0 ): #the browser is sending some shit
					self.receiveBuffer += buff1.decode()
					headers = self.parse_http_headers()
					if not headers:
						self.killSocket("Header errors, probably hack attempt.");break
					print("Req: " + headers['path'] + "\nHost: " + headers['host'] + "\nUser-Agent: '" + headers['user-agent'][0:60] + " ...'" )
					if headers['path'].endswith("/"): headers['path'] += "index.html"
					
					if "referer" in headers: print("Referer: " + headers['referer'])
					
					if "cookie" in headers:
						if( headers['cookie'] != ""): print("Cookie: " + headers['cookie'])
					
					if "sec-websocket-key" in headers:
						self.handle_WS( headers['sec-websocket-key'] )
						return
					
					script_directory = os.path.dirname(os.path.abspath(sys.argv[0]))
					self.request = script_directory + "/wwwroot" + headers['path']
					if "/../" in headers['path']: # VERY IMPORTANT SECURITY MEASURE - without this, a user can read files outside of wwwroot!  
						self.send( self.buildHeader("302 Found", "http://www.disney.com/" ) )
						self.killSocket("Redirected to somewhere more fun"); break
					
					if( headers['method'] == "GET"):
						self.handle_GET()
						break
					#elif (method == "POST"): #get that post data :S
					else: #Currently not expecting other method, redirect this asshat
						self.send( self.buildHeader("302 Found", "http://www.disney.com/" ) )
						self.killSocket("Redirected to somewhere more fun"); break
		except Exception as e:
			if( str(e) != "timed out"):
				print('Error on line {} in HTTPrequestHandler : "{}"'.format(sys.exc_info()[-1].tb_lineno, e))
			try:
				self.killSocket()
			except Exception as ex:
				print(str(ex)); pass

	def ipAllowed(self):
		ban_file = open(banListFile)
		for line in ban_file.readlines():
			if (line.rstrip() == self.ip): return False
		if(self.ip in allowed_ip_addresses): return True
		for ipStart in allow_all_ip_starting_with:
			if self.ip.startswith(ipStart): return True
		return False
		
	def parse_http_headers(self):
		headers = {}
		lineArr = self.receiveBuffer.split("\n")
		if( len(lineArr) < 4): #Browser must be sending more than one line, minimum 4
			print("Not nearly enough lines for a valid request\n"); return False		
		tempArr = lineArr.pop(0).split(" ") 
		if( len(tempArr) != 3 ): 
			print("Malformed first line of request\n"); return False
		headers['method'] = tempArr[0]
		headers['path'] = tempArr[1]
		headers['protocol'] = tempArr[2]
		allowedMethods = ["GET", "POST"]
		if (not headers['method'] in allowedMethods) or ( not headers['path'].startswith("/") ):
			print("Headers problems, probably hack attempt");return False
		for line in lineArr:
			if not line:
				break
			if not ":" in line:
				break
			head, value = line.split(':', 1)
			headers[head.lower().strip()] = value.strip()
		required = ["host", "user-agent", "accept-language", "accept-encoding", "connection"] #Most common? Mandatory? "accept"
		for headerName in required:
			if not headerName in headers:
				print("Required headers missing in request!")
				print(self.receiveBuffer)
				return False
		return headers
	
	def handle_WS(self, key):
		try:
			resp = self.make_handshake_response( key )
			self.send(resp.encode() )
			print("- Sent WSkey response")			
			ipCount = 0
			for wsClient in self.server.wsClientArr:
				if wsClient.ip == self.ip: ipCount +=1
			if ipCount < webSockPerIP:
				self.nickname = ""
				self.receiveBuffer = [] #In websocket we need array
				self.ping = time.time()
				self.pong = time.time()
				self.server.wsClientArr.append(self)
				#tell the bastard to log in!
				loginPrompt = WebsocketHandler.websockEncode(self, '{"cmd":"login", "msg":"Please log in ( i.e. set a nickname )!"}', False )
				self.send(loginPrompt)
				return #print something about being handed over to ws?
			else:
				error = WebsocketHandler.websockEncode(self, '{"cmd":"error", "msg":"Are you the infamous browser TABS HOARDER?! Too many websockets!"}', False )
				self.send(error)
				self.killSocket("Too many websockets on IP")
			
		except Exception as e:
			print('Error on line {} in trying to hand over socket to handle_WS'.format(sys.exc_info()[-1].tb_lineno) + " '" + str(e) + "'")
			self.killSocket("Error establishing websocket connection :S ")
	
	def handle_GET(self):
		if(os.path.isfile(self.request) ):
			self.fileSize = os.path.getsize(self.request)
			self.send( self.buildHeader("200 OK") )
			self.sendFile()
			self.killSocket()
		else:
			self.send( self.buildHeader("404 Not Found" ) )
			self.killSocket("Served 404 Not Found")
	
	def killSocket(self, comment=False):
		if comment:
			print(comment)
		try:
			self.clientSock.shutdown(1)
			self.clientSock.close()
			print("-reqId: " + self.reqId + " all closed up now...\n")
		except Exception as e:
			print("Failed to kill socket for "+self.reqId+", sry :/" + str(e) )
			pass
	
	def send(self, data):
		try:
			self.clientSock.send( data )
		except Exception as e:
			print("Unable to send in request: " + self.reqId )
			if e.args[0] == 9:
				print("Already disconnected: " + self.reqId )
				self.killSocket()
			pass
	
	def sendFile(self):
		chunked = False
		crlf = "\r\n".encode()
		if self.fileSize > self.server.BUFLEN:
			chunked = True
		try:
			with open(self.request, "rb") as f:
				while (byteChunk := f.read(self.server.BUFLEN)):
					if chunked:
						lenStr = hex(len(byteChunk))[2:] + "\r\n"
						self.send( lenStr.encode() )
					self.send( byteChunk + crlf )
			self.send( "0\r\n\r\n".encode() )
		except Exception as e:
			print('Error on line {} in self.sendFile(): "{}"'.format(sys.exc_info()[-1].tb_lineno, e))
	
	def buildHeader(self, respCode, redirURL=False):
		serverNameStr = "pyHttpServ - Built on recycled old python 2 code - Running in-pocket mode on a stolen Android phone."
		serverDateStr = "Sun, 25 Dec 2016 12:15:30 GMT"
		headerData = "HTTP/1.1 "+respCode+"\n" + \
					 "Server: "+serverNameStr+"\n" + \
					 "Date: "+serverDateStr+"\n" + \
					 "Connection: close\n" + \
					 "Accept-Ranges: bytes\n"
		
		mimeDict = { "png":"image/png",
					"jpg":"image/jpg",
					"ico":"image/x-icon",
					"js":"application/javascript",
					"css":"text/css",
					"html":"text/html"}
		tmpArr = self.request.split(".")
		if( len(tmpArr) > 1 ):
			ext = tmpArr[-1].lower()
		else:
			ext = "html"
		if (not ext in mimeDict) or (respCode == "404 Not Found"):
			ext = "html"
		contTypeString = "Content-Type: "+mimeDict[ext]+"\n"
		
		if( respCode == "302 Found" ):
			headerData += "Status: 302 Moved Temporarily\nLocation: "+redirURL+"\n"
			return headerData.encode()
		elif(respCode == "404 Not Found"):
			headerData += contTypeString +"\r\n\r\n" + self.html404 + "\r\n\r\n"
			return headerData.encode()
		else:
			if ( self.fileSize > self.server.BUFLEN ):
				headerData += contTypeString + "Transfer-Encoding: chunked\r\n\r\n"
			else:
				headerData += contTypeString + "Content-Length: " + str(self.fileSize) +"\r\n\r\n"
		return headerData.encode()
	
	def make_handshake_response(self, key):
		try:
			GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
			hash = sha1(key.encode() + GUID.encode())
			response_key = b64encode(hash.digest()).strip()
			response_key = response_key.decode('ASCII')
			return \
				'HTTP/1.1 101 Switching Protocols\r\n'\
				'Upgrade: websocket\r\n'              \
				'Connection: Upgrade\r\n'             \
				'Sec-WebSocket-Accept: '+response_key+'\r\n\r\n'
		except Exception as e:
			print('Error on line {} in make_handshake_response : "{}"'.format(sys.exc_info()[-1].tb_lineno, e))



class WebsocketHandler:
	def __init__(self, server):
		OPCODE_PONG = 0x8a #=138
		OPCODE_TEXT = 0x81 #=129
		OPCODE_QUIT = 0x88 #=136

		time.sleep(2)
		self.server = server
		while self.server.running:
			time.sleep(0.100)
			try:
				if len(self.server.wsClientArr) > 0:
					for wsClient in [wsClient for wsClient in self.server.wsClientArr if time.time() - wsClient.ping > 20.0]:
						wsClient.ping = time.time()
						self.ping_send("", wsClient)

					for wsClient in [wsClient for wsClient in self.server.wsClientArr if time.time() - wsClient.pong > 60.0]:
						print("got a ping timeout")
						try:
							self.removeClient(client, "(ping timeout)")
						except Exception as e:
							pass
				

				theSockets = [wsClient.clientSock for wsClient in self.server.wsClientArr]
				if len(theSockets) == 0: #Got 0 client.. sleepy timeee"
					time.sleep(1); continue
					
				readable_socks, writable_socks, errors = select.select(theSockets, [], theSockets, 1)
				if errors:
					for client in errors:
						self.removeClient(client, "(some error occured)")
				if readable_socks:
					for sock in readable_socks:
						time.sleep(0.100)
						data = sock.recv(self.server.BUFLEN)
						client = self.getClient(sock)
						if len(data) > 0:
							
							if( data[0] == OPCODE_QUIT ):
								self.removeClient(client, "(quit)") 
							elif( data[0] == OPCODE_PONG):
								print(timeStamp() +" -reqId:"+client.reqId+" - PONG")
								client.pong = time.time() 
							elif( data[0] == OPCODE_TEXT):
								print("Websock " + client.reqId )
								client.jsonArray = []
								for byteVal in data:
									client.receiveBuffer.append(byteVal)
								#print(client.receiveBuffer)
								while len(client.receiveBuffer) > 0:
									decoded = self.websockDecode(client)
									if not decoded:
										self.punish(client)
										self.removeClient(client, "(sends invalid data, maybe not websocket encoded)"); break
									if self.isJSON(decoded):
										client.jsonArray.append( decoded )
									else:
										self.punish(client)
										self.removeClient(client, "(sends invalid json)"); break
								print(client.jsonArray)
								self.processJSON(client)
							else:
								self.punish(client)
								self.removeClient(client, "(sends invalid opcodes)")
						else:
							self.removeClient(client, "(connection lost?)")
			except Exception as e:
				print('Error on line {} in WebsocketHandler: '.format(sys.exc_info()[-1].tb_lineno) + " '" + str(e) + "'")


	def punish(self, client):
		vals = ['0', '1', '2', '3', '4', '5']
		x = random.choice(vals)
		with open("punish/payload"+x+".txt", 'r') as file:
			fileData = file.read()
		file.close()
		fArr = fileData.split("\n")
		for line in fArr:
			self.websock_send('{"cmd":"msg","msg":"'+ line +'"}', client )
		
	def nickAvailable(self, nickname, theClient):
		disallowed = ["server", "root" , "admin"]
		if nickname.lower() in disallowed:
			self.punish(theClient)
			return False
		for client in self.server.wsClientArr:
			if client.nickname.lower() != "" and client.nickname.lower() == nickname.lower():
				return False
		return True

	def ping_send(self, pingString, to):
		txtEncoded = self.websockEncode( "", True)
		try:
			to.clientSock.send( txtEncoded )
		except Exception as e:
			print("unable to send in ping_send()");pass
		
	def websock_send(self, jsonString, to):
		txtEncoded = self.websockEncode( jsonString )
		try:
			to.clientSock.send( txtEncoded )
		except Exception as e:
			print("unable to send in websock_send()");pass

	def broadCast(self, jsonString):
		txtEncoded = self.websockEncode( jsonString )
		for client in self.server.wsClientArr:
			if client.nickname != "":
				try:
					client.clientSock.send( txtEncoded )
				except Exception as e:
					print("unable to send in broadCast()");pass

	def nickList(self):
		tmpStr = ""
		for client in self.server.wsClientArr:
			if client.nickname != "":
				tmpStr += client.nickname + ", "
		self.broadCast('{"cmd":"list","msg":"'+ tmpStr.rstrip(", ") +'"}')


	def isJSON(self, data):
		try:
			tmpDict = json.loads(data)
			return True
		except Exception as e:
			return False
		
	def processJSON(self, client):
		for jsonStr in client.jsonArray:
			try:
				dataArr = json.loads(jsonStr)
				#for key in dataArr.keys():
				#	print(key + "=" + dataArr[key] )
				if (len(dataArr.keys()) < 2) or  ( (not "cmd" in dataArr) or (not "msg" in dataArr) ) :
					self.punish(client)
					print("problems with data here"); return
				
				# Expecting only "cmd" and "msg"
				if dataArr['cmd'] == "login":
					reqNick = dataArr['msg']
					if (len(reqNick) < 2 ) or (len(reqNick) > 20 ):
						self.websock_send('{"cmd":"login","msg":"Nickname must be 2-20 chars length, sorry!"}', client )
					elif self.nickAvailable( reqNick, client ):
						if not self.inputIsValid( reqNick ):
							self.websock_send('{"cmd":"login","msg":"Nickname must be regular ascii a-zA-Z0-9, sorry!"}', client )
						else:
							client.nickname = reqNick 
							self.websock_send('{"cmd":"nickname","msg":"'+client.nickname+'"}', client )
							self.broadCast('{"cmd":"msg","msg":"New user (\''+client.nickname+'\') connected."}')
							self.nickList()
					else:
						self.websock_send('{"cmd":"login","msg":"The requested nickname is not available, sorry!"}', client )
				elif dataArr['cmd'] == "msg":
					self.broadCast('{"cmd":"msg","msg":"'+dataArr['msg']+'","from":"'+client.nickname+'"}')
				else:
					self.punish(client)
					self.websock_send('{"cmd":"msg","msg":"invalid input"}', client )
					print("sending invalid cmd")

				
			except Exception as e:
				print('Error on line {} in processJSON: '.format(sys.exc_info()[-1].tb_lineno) + " '" + str(e) + "'")


	def getClient(self, sock):
		for wsClient in self.server.wsClientArr:
			if wsClient.clientSock == sock:
				return wsClient

	def removeClient(self, client, reason=""):
		nickname = ""
		self.server.wsClientArr.remove(client)
		if hasattr(client, "nickname"):
			if client.nickname != "":
				nickname = client.nickname
				self.broadCast('{"cmd":"msg","msg":"User (\''+client.nickname+'\') has disconnected '+reason+'"}')
		print("- Closing connections now.. '" + client.nickname + "' " + reason)
		client.clientSock.shutdown(1)
		client.clientSock.close()
		print("-reqId: " + client.reqId + " all closed up now... '"+nickname+"'\n")

	def websockDecode(self, client):
		try:
			#print("receiveBuffer len:"+ str(len(client.receiveBuffer)) )
			datalength = client.receiveBuffer[1] & 127
			if datalength < 126: #normal, short
				indexFirstMask = 2 #; print("datalength normal")
			elif datalength == 126: #payload_length <= 65535: # Extended payload
				indexFirstMask = 4 #; print("datalength extended")
			elif datalength == 127: #payload_length < 18446744073709551616: # Huge extended payload
				indexFirstMask = 10
			else:
				return False

			# Extract masks
			masks = [m for m in client.receiveBuffer[indexFirstMask : indexFirstMask+4]]
			indexFirstDataByte = indexFirstMask + 4 #so if <126 we start reading at byte nr. 6
			client.receiveBuffer = client.receiveBuffer[indexFirstDataByte:] #We got the masks, removing that part from buffer
			decodedChars = "" # Prepare new string to be populated by decoded chars
			
			i = 0
			while i < len(client.receiveBuffer): # Loop through & unmask each byte, add to decoded string
				charCode = client.receiveBuffer[i] ^ masks[i % 4]
				decodedChars += chr(charCode)
				#if charCode > 128: #non-ascii
				#	print("Got a unicode char here: " + str(charCode) )				
				i += 1
				if decodedChars.startswith("{") and decodedChars.endswith("}"):
					client.receiveBuffer = client.receiveBuffer[i:]
					return decodedChars.encode('latin-1').decode('utf-8') # Important for unicode chars! DON'T CHANGE IT!
			print(decodedChars)
			return False

		except Exception as e:
			print('Error on line {} in websockDecode() '.format(sys.exc_info()[-1].tb_lineno) + " '" + str(e) + "'")
			return False

	def websockEncode(self, message, pinging=False):
		OPCODE_TEXT = 0x1 #=1?
		OPCODE_PING = 0x9 #=9?
		FIN = 0x80
		if pinging:
			opcode = OPCODE_PING
		else:
			opcode = OPCODE_TEXT

		header  = bytearray()
		try:
			payload = message.encode('UTF-8')
		except Exception as e:
			print("error" + e)
			return
		payload_length = len(payload)
		# Normal payload
		if payload_length <= 125:
			header.append(FIN | opcode)
			header.append(payload_length)
		# Extended payload
		elif payload_length >= 126 and payload_length <= 65535:
			header.append(FIN | opcode)
			header.append(0x7e) # PAYLOAD_LEN_EXT16, 126
			header.extend(struct.pack(">H", payload_length))
		# Huge extended payload
		elif payload_length < 18446744073709551616:
			header.append(FIN | opcode)
			header.append(0x7f) # PAYLOAD_LEN_EXT64, 127
			header.extend(struct.pack(">Q", payload_length))

		else:
			raise Exception("Message is too big. Consider breaking it into chunks.")
			return
		return header +  payload
	
	def inputIsValid(self, inputStr):
		validChars = "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ0123456789-_" 
		for c in inputStr:
			if c not in validChars:
				return False
		return True



def timeStamp():
	return datetime.datetime.fromtimestamp(time.time(),timezone(srvrTimeZone)).strftime('[%d.%m %H:%M:%S]')

if __name__ == "__main__":
	print("Use file run.py for reloadable server.")