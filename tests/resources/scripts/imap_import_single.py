import imaplib
import socket
import time
from email.message import Message
from email.utils import formatdate
from datetime import datetime, timedelta

conn = imaplib.IMAP4('localhost')
conn.login('john', '12345')
conn.socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
current_date = datetime.now()
timestamp = current_date.timestamp()

msg = Message()
msg['From'] = 'somebody@some.where'
msg['To'] = 'john@example.org'
msg['Message-Id'] = f'unique.message.id.{current_date}@nowhere'
msg['Date'] = formatdate(time.mktime(current_date.timetuple()), localtime=False, usegmt=True)
msg['Subject'] = f"This is message #{timestamp}"
msg.set_payload('...nothing...')

response_code, response_details = conn.append('INBOX', '', imaplib.Time2Internaldate(time.mktime(current_date.timetuple())), str(msg).encode('utf-8'))
if response_code != 'OK':
    print(f'Error while appending message: {response_code} {response_details}')

print("Message appended.")
conn.logout()
