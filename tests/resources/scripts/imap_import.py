import imaplib
import socket
import time
import threading
from email.message import Message

def append_message(thread_id, start, end):
    conn = imaplib.IMAP4('localhost')
    conn.login('john', '12345')
    conn.socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    start_time = time.time()

    for n in range(start, end):
        msg = Message()
        msg['From'] = 'somebody@some.where'
        msg['To'] = 'john@example.org'
        msg['Message-Id'] = f'unique.message.id.{n}@nowhere'
        msg['Subject'] = f"This is message #{n}"
        msg.set_payload('...nothing...')

        response_code, response_details = conn.append('INBOX', '', None, str(msg).encode('utf-8'))
        if response_code != 'OK':
            print(f'Thread {thread_id}: Error while appending message #{n}: {response_code} {response_details}')
            break
        if n != 0 and n % 100 == 0:
          elapsed_time = (time.time() - start_time) * 1000 
          print(f'Thread {thread_id}: Inserting batch {n} took {elapsed_time} ms.', flush=True)
          start_time = time.time()

    conn.logout()

num_threads = 5
num_messages = 10000
messages_per_thread = num_messages // num_threads

threads = []
for i in range(num_threads):
    start = i * messages_per_thread
    end = start + messages_per_thread
    thread = threading.Thread(target=append_message, args=(i, start, end))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

print("All messages appended.")

