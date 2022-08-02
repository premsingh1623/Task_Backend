import os
from flask import Flask, render_template, request, redirect, url_for, render_template, jsonify
from functools import wraps
from werkzeug.utils import secure_filename
import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'privatekey'
app.config['ADMIN'] = 'admin'
app.config['PASSWORD'] = 'password'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.errorhandler(429)
def ratelimit_handler(e):
  return jsonify({'message': 'You have exceeded your rate-limit'})

@ app.route('/webcam', methods=['GET'])
def webcam():
    return render_template('webcam.html')


@ app.route('/upload', methods=['POST'])
@ token_required
@ limiter.limit("5 per minute")
def upload_file(current_user):
    f = request.files['file']
    print(f)
    filename = secure_filename(f.filename)
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify({'message': 'file uploaded successfully', 'filename': filename})


@ app.route('/show/<filename>', methods=['GET'])
def show_image(filename):
    return render_template('display.html', filename=filename)


@ app.route('/image/<filename>', methods=['GET', 'POST'])
def get_file(filename):
    return redirect(url_for('static', filename='uploads/' + filename), code=301)


@ app.route('/login', methods=['POST'])
def login_user():
    print(request.form)
    user = request.form.get('user')
    password = request.form.get('password')
    if user == app.config['ADMIN'] and password == app.config['PASSWORD']:
        token = jwt.encode({'user': user, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=120)}, app.config['SECRET_KEY'], "HS256")
        return render_template('upload.html', token=token)
    return render_template('index.html', error='Invalid Credentials. Please try again.')


@ app.route('/limit', methods=['GET'])
@ limiter.limit("5 per minute")
def limit():
    return jsonify({ 'message': 'Request completed successfully' })


@ app.route('/', methods=['GET'])
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
