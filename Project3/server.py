import socket
import signal
import sys
import random
import urllib.parse # added

# Read a command line argument for the port where the server
# must run.
port = 8080
if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    print("Using default port 8080")
hostname = socket.gethostname()

# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

### Contents of pages we will serve.
# Login form
# http://%s
login_form = """
   <form action = "http://%s" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
"""
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
# http://%s
success_page = """
   <h1>Welcome!</h1>
   <form action="http://%s" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
"""

#### Helper functions
# Printing.
def print_value(tag, value):
    print("Here is the", tag)
    print("\"\"\"")
    print(value)
    print("\"\"\"")
    print()

# Signal handler for graceful exit
def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)
# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)


# TODO: put your application logic here!
# Read login credentials for all the users
# Read secret data of all the users
username_to_password = {}
with open("passwords.txt", "r") as f:
    lines = f.readlines()
    for line in lines:
        username, password = line.strip().split()
        username_to_password[username] = password
    
username_to_secret = {}
with open("secrets.txt", "r") as f:
    lines = f.readlines()
    for line in lines:
        username, secret = line.strip().split()
        username_to_secret[username] = secret

# [print(f"{a}: {b}") for a, b in username_to_password.items()]
# [print(f"{k}: {v}") for k, v in username_to_secret.items()]

sessions = {} # look up valid cookie

### Loop to accept incoming HTTP connections and respond.
while True:
    client, addr = sock.accept()
    req = client.recv(1024)

    # Let's pick the headers and entity body apart
    header_body = req.decode().split('\r\n\r\n')
    headers = header_body[0]
    body = '' if len(header_body) == 1 else header_body[1]

    print_value('headers', headers)
    print_value('entity body', body)

    # TODO: Put your application logic here!
    # Parse headers and body and perform various actions

    submit_hostport = "%s:%d" % (hostname, port)
    html_content_to_send = login_page % submit_hostport
    headers_to_send = ''

    # step 5.2
    cookie = None
    for line in headers.split('\r\n'):
        if line.startswith('Cookie:'):
            cookie_parts = line.split('token=')
            # print(cookie_parts)
            if len(cookie_parts) > 1 and cookie_parts[1].strip():  # check for non-empty token
                cookie = cookie_parts[1].split(';')[0].strip()  # handle cases like "token=123; other=cookie"
                print("cookie: " + cookie)
                break
    # print("cookie value: " + str(cookie))

    # case E
    if body == "action=logout":
        print("Case E: logout")
        headers_to_send = 'Set-Cookie: token=; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n'
        html_content_to_send = logout_page % submit_hostport

    # case C (if cookie exists and is in sessions dictionary)
    elif cookie and cookie in sessions:
        print("Case C: cookie exists")
        username = sessions[cookie]
        secret = username_to_secret[username]
        # print("c, username: " + username)
        # print("c, secret: " + secret)
        html_content_to_send = (success_page % submit_hostport) + secret
    
    # case D (cookie exists, not user/pwd pair)
    elif cookie and cookie not in sessions: # if cookie is not none but not in sessions (valid cookies are in session)
        html_content_to_send = bad_creds_page % submit_hostport
        headers_to_send = 'Set-Cookie: token=; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n' ## not in directions
        print("Case D: invalid")

    elif body and 'username=' in body and 'password=' in body: # POST with credentials
        names, pwd = body.split('&')
        name = names.split('=')[1]
        pwd = pwd.split('=')[1]
        # print('name: {}, password: {}'.format(name,pwd))

        # case A
        if name in username_to_password and pwd == username_to_password[name]:
            secret = username_to_secret[name]
            # step 5.1 & 5.2
            # success page & new cookie
            existing_cookie = None
            print("Case A")
            for stored_cookie, user in sessions.items():
                if user == name:
                    print("existing cookie")
                    existing_cookie = stored_cookie
                    break
            if existing_cookie is None:
                print("cookie does not exist yet")
                rand_val = random.getrandbits(64)
                cookie_str = str(rand_val)
                sessions[cookie_str] = name # store cookie
            else:
                cookie_str = existing_cookie
                # print("cookie_str: " + cookie_str)
            
            headers_to_send = 'Set-Cookie: token=' + cookie_str + '\r\n'
            html_content_to_send = (success_page % submit_hostport) + secret
        # case B
        else:
            html_content_to_send = bad_creds_page % submit_hostport
            print("Case B")
    # Basic case: No special conditions met (show login page)
    else:
        html_content_to_send = login_page % submit_hostport
        print("Basic Case") 
    
    print("-----------------------------------------------------------------------------------")
    # default (redundant)
    # else:
    #     html_content_to_send = login_page % port
    
    # OPTIONAL TODO:
    # Set up the port/hostname for the form's submit URL.
    # If you want POSTing to your server to
    # work even when the server and client are on different
    # machines, the form submit URL must reflect the `Host:`
    # header on the request.
    # Change the submit_hostport variable to reflect this.
    # This part is optional, and might even be fun.
    # By default, as set up below, POSTing the form will
    # always send the request to the domain name returned by
    # socket.gethostname().
    ## submit_hostport = "%s:%d" % (hostname, port)

    # You need to set the variables:
    # (1) `html_content_to_send` => add the HTML content you'd
    # like to send to the client.
    # Right now, we just send the default login page.
    ## html_content_to_send = login_page % submit_hostport
    ## html_content_to_send = login_page % port
    # But other possibilities exist, including
    # html_content_to_send = (success_page % submit_hostport) + <secret>
    # html_content_to_send = bad_creds_page % submit_hostport
    # html_content_to_send = logout_page % submit_hostport
    
    # (2) `headers_to_send` => add any additional headers
    # you'd like to send the client?
    # Right now, we don't send any extra headers.
    ## headers_to_send = ''

    # Construct and send the final response
    response  = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)    
    client.send(response.encode())
    client.close()
    
    print("Served one request/connection!")
    print()

# We will never actually get here.
# Close the listening socket
sock.close()
