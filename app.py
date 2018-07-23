import os
from flask import Flask, redirect, url_for, request, render_template, jsonify
import json
import requests
import random
import string

app = Flask(__name__)


@app.route('/')
def home_page():
    return render_template("dashboard.html")

@app.route('/oauth')
def oauth_page():
    randoms = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(8)])
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=391943231789-nlso1fuhofpf8hl0basc6lmts089svts.apps.googleusercontent.com&redirect_uri=https://8080-dot-4071604-dot-devshell.appspot.com/access&scope=email&state="+randoms)

@app.route('/access', methods=['GET', 'POST'])
def access_page():
    secret = str(request.args['state'])
    code = str(request.args['code'])
    cid = "391943231789-nlso1fuhofpf8hl0basc6lmts089svts.apps.googleusercontent.com"
    csc = "QnfSRBSmp2H8B24cvd2ppLYo"
    redir = "https://8080-dot-4071604-dot-devshell.appspot.com/access"

    d = {"code": code, "client_id": cid, "client_secret": csc, "redirect_uri": redir, "grant_type": "authorization_code"}

#    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    s = "?"
    for k in d.keys():
        s += k + "=" + d[k] + "&"

    s = s[:-1]


    resp = requests.post('https://www.googleapis.com/oauth2/v4/token'+s)
    token = resp.json()['access_token']
    randoms = resp.json()
    print randoms

    r = requests.get("https://www.googleapis.com/plus/v1/people/me", headers={'Authorization': 'Bearer '+token})

    dd = r.json()

    return dd["displayName"] + "<br>" + dd['url'] + "<br>" + secret

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True, threaded=True)

