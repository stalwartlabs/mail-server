import requests
import random
import string
import urllib3

# Configuration Variables
HOSTNAME = '127.0.0.1'  # Replace with the actual hostname
DOMAIN = 'test.org'  # Replace with your domain name
USERNAME = 'admin'  # Basic auth username
PASSWORD = 'secret'  # Basic auth password
NUM_USERS = 1000  # Number of test user accounts to create

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Generate SHA512 password hash
def generate_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))

# Create Domain
def create_domain():
    url = f"https://{HOSTNAME}/api/domain/{DOMAIN}"
    response = requests.post(url, auth=(USERNAME, PASSWORD), verify=False)
    if response.status_code == 200:
        print(f"Domain '{DOMAIN}' created successfully.")
    else:
        print(f"Failed to create domain '{DOMAIN}'. Status Code: {response.status_code}")
        print(response.text)

# Create User Accounts
def create_user_accounts():
    with open('users.txt', 'w') as file:
        for i in range(1, NUM_USERS + 1):
            username = f"test{i}@{DOMAIN}"
            password = generate_password()
            data = {
                "type": "individual",
                "name": username,
                "secrets": [password],
                "emails": [username],
                "description": f"Tester {i}"
            }
            url = f"https://{HOSTNAME}/api/principal"
            response = requests.post(url, json=data, auth=(USERNAME, PASSWORD), verify=False)
            if response.status_code == 200:
                file.write(f"{username}:{password}\n")
                print(f"User account '{username}' created successfully.")
            else:
                print(f"Failed to create user account '{username}'. Status Code: {response.status_code}")
                print(response.text)

def main():
    create_domain()
    create_user_accounts()

if __name__ == "__main__":
    main()
