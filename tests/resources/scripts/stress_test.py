import smtplib
import imaplib
import ssl
import threading
import random
import time
import string
from email.mime.text import MIMEText

smtp_server = "127.0.0.1"
smtp_port = 465
imap_server = "127.0.0.1"
imap_port = 993
num_threads = 5
runs = 10  # Set to None for infinite loop

def read_credentials(file_path):
    with open(file_path, "r") as file:
        credentials = [line.strip().split(':') for line in file if line.strip()]
    return credentials

def allow_invalid_certificates():
    # Create an SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE 
    return context

def generate_random_string(min_size, max_size):
    """Generates a random string of a size between min_size and max_size."""
    size = random.randint(min_size, max_size)
    chars = string.ascii_letters + string.digits + ' '
    return ''.join(random.choice(chars) for _ in range(size))

def generate_email(username, recipient):
    """Generate random subject and content for email."""
    subject = generate_random_string(10, 100)  # Random subject between 10 and 100 characters
    content_size = random.randint(100, 1048576)  # Random content size between 100 bytes and ~1MB
    content = generate_random_string(content_size, content_size)
    message = MIMEText(content)
    message['Subject'] = subject
    message['From'] = username
    message['To'] = recipient
    return message.as_string()

def smtp_send_message(username, password, recipient):
    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=allow_invalid_certificates()) as server:
            server.login(username, password)
            start_time = time.time()
            server.sendmail(username, recipient, generate_email(username, recipient))
            elapsed_time_ms = (time.time() - start_time) * 1000
            print(f"OK {elapsed_time_ms} SMTP {username} -> {recipient}")
    except Exception as e:
        print(f"ERR SMTP {e}")

def imap_append_message(username, password, recipient):
    try:
        with imaplib.IMAP4_SSL(imap_server, imap_port, ssl_context=allow_invalid_certificates()) as imap:
            imap.login(username, password)
            start_time = time.time()
            imap.append('INBOX', None, imaplib.Time2Internaldate(time.time()), generate_email(username, recipient).encode('utf-8'))
            elapsed_time_ms = (time.time() - start_time) * 1000
            print(f"OK {elapsed_time_ms} IMAP APPEND {username}")
    except Exception as e:
        print(f"ERR IMAP {e}")

def imap_list_fetch(username, password):
    try:
        with imaplib.IMAP4_SSL(imap_server, imap_port, ssl_context=allow_invalid_certificates()) as imap:
            imap.login(username, password)
            imap.select('INBOX')
            start_time = time.time()
            typ, data = imap.search(None, 'ALL')
            if data[0]:
                messages = data[0].split()
                random_msg_num = random.choice(messages)
                typ, msg_data = imap.fetch(random_msg_num, '(RFC822)')
                elapsed_time_ms = (time.time() - start_time) * 1000
                print(f"OK {elapsed_time_ms} IMAP FETCH {username} {random_msg_num}")
    except Exception as e:
       print(f"ERR IMAP {e}")

def imap_delete_message(username, password):
    try:
        with imaplib.IMAP4_SSL(imap_server, imap_port, ssl_context=allow_invalid_certificates()) as imap:
            imap.login(username, password)
            imap.select('INBOX')
            start_time = time.time()
            typ, data = imap.search(None, 'ALL')
            if data[0]:
                messages = data[0].split()
                random_msg_num = random.choice(messages)
                imap.store(random_msg_num, '+FLAGS', '\\Deleted')
                imap.expunge()
                elapsed_time_ms = (time.time() - start_time) * 1000
                print(f"OK {elapsed_time_ms} IMAP DELETE {username} {random_msg_num}")
    except Exception as e:
        print(f"ERR IMAP {e}")

def perform_random_action(credentials):
    username, password = random.choice(credentials)
    recipient, _ = random.choice(credentials)
    action = random.choice([smtp_send_message, imap_append_message, imap_list_fetch, imap_delete_message])
    
    if action == smtp_send_message or action == imap_append_message:
        action(username, password, recipient)
    else:
        action(username, password)

def thread_function(credentials):
    if runs:
        for _ in range(runs):
            perform_random_action(credentials)
    else:
        while True:
            perform_random_action(credentials)

def main():
    credentials = read_credentials("users.txt")
    threads = []

    for _ in range(num_threads):
        thread = threading.Thread(target=thread_function, args=(credentials,))
        threads.append(thread)
        thread.start()
   
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
