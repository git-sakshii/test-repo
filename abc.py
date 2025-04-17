from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Setup database
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
conn.commit()
conn.close()

@app.route('/')
def home():
    return '''<h2>Login</h2>
              <form method="POST" action="/login">
                Username: <input name="username"><br>
                Password: <input name="password" type="password"><br>
                <input type="submit">
              </form>'''

# VULNERABLE TO SQL INJECTION
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = c.execute(query).fetchall()
    conn.close()
    if result:
        return f"<h2>Welcome, {username}!</h2>"
    else:
        return "<h2>Invalid credentials.</h2>"

# VULNERABLE TO EVAL() EXECUTION
@app.route('/calc', methods=['GET'])
def calc():
    expr = request.args.get('expr', '')
    try:
        result = eval(expr)
        return f"<h2>Result: {result}</h2>"
    except:
        return "<h2>Error evaluating expression</h2>"

# VULNERABLE TO COMMAND INJECTION
@app.route('/ping', methods=['GET'])
def ping():
    ip = request.args.get('ip', '')
    response = os.popen(f"ping -c 1 {ip}").read()
    return f"<pre>{response}</pre>"

# VULNERABLE TO PATH TRAVERSAL
@app.route('/view', methods=['GET'])
def view_file():
    filename = request.args.get('file', '')
    try:
        with open(filename, 'r') as f:
            return f"<pre>{f.read()}</pre>"
    except:
        return "<h2>Could not open file.</h2>"

if __name__ == '__main__':
    app.run(debug=True)