# RADIUS EAP-MSCHAPv2 Client

A pure Python 3 RADIUS EAP-MSCHAPv2 client implementation.

# Explanation

This project was developped because no RADIUS client library supports EAP-MSCHAPv2 (A ticket is open for the pyrad 
library, see [here](https://github.com/pyradius/pyrad/issues/40)).

This library **only supports** EAP-MSCHAPv2. This code has been tested with Microsoft Windows Server 2016 Network 
Policy Server.

# Usage

<pre>from RADIUS import RADIUS

radius_host = '10.1.2.3'
radius_secret = 'r4d!us_$3cr3t'
radius_nas_ip = '10.3.2.1'
radius_nas_id = 'mynas'
username = 'myuser'
password = 'mypassword!'

r = RADIUS(radius_host, radius_secret, radius_nas_ip, radius_nas_id)
print(r.is_credential_valid(username, password))</pre>


# Requirements

This script has been written for Python 3.5 and newer.

You must install librairies with <code>pip3 install -r requirements.txt</code>.

# Credits

To make this implementation, I used the [daphp/radius PHP implementation](https://github.com/dapphp/radius).

The article [Understanding PEAP In-Depth](https://sensepost.com/blog/2019/understanding-peap-in-depth/) also helped me 
a lot.

Thanks to them.
