from flask import Flask, request, render_template

app = Flask(__name__)

@app.get('/')
def home():
    return render_template('home.html')

@app.get('/vulnerable')
def vulnerable():
    query = request.args.get('q', '')
    return render_template('vulnerable.html', query=query)

@app.get('/secure')
def secure():
    query = request.args.get('q', '')
    return render_template('secure.html', query=query)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
