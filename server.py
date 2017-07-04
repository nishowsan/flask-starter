import sys
import time
from flask import Flask

# view functionality
from contents import *
from functools import wraps
from flask import render_template, flash

# login functionality
import pygal
import gc
import bcrypt
from dbconf import databaseuri
from flask_pymongo import *
from flask import request, url_for, redirect, session

# globally available variables
__author__ = 'nishow'
app = Flask(__name__)
curr_time = str(time.ctime())
time_taken = float(time.time())
appName = 'Learn Python'
all_urls = Urls()
port = int(8080)
secret_key = b'KeyboardCat'

# database configuration
URI = databaseuri()
app.config['MONGO_URI'] = URI
database = PyMongo(app=app)

try:

    @app.route('/')
    def index():
        url = 'Home'
        return render_template('index.html', app=appName, url=url,
                               urls=all_urls)

    @app.route('/about')
    def about():
        url = 'About'
        return render_template('about.html', app=appName, url=url, urls=all_urls)


    @app.route('/dashboard')
    def dashboard():
        url = 'Dashboard'
        topic = Content()  # content.py
        if 'user' in session:
            flash(session['user'])
            return render_template('dashboard.html', app=appName, url=url,
                               TOPIC_DICT=topic, urls=all_urls)
        return render_template('dashboard.html', app=appName, url=url,
                               TOPIC_DICT=topic, urls=all_urls)


    @app.route('/login', methods=['GET', 'POST'])
    def login():
        url = 'Login'
        try:
            if request.method == 'POST':

                attempted_username = request.form['user']
                attempted_password = request.form['password']
                users = database.db.users
                login_users = users.find_one({
                    'name': attempted_username
                })

                if login_users is not None:
                    l_p = login_users['password']
                    attempted_password_encoded = attempted_password.encode('utf-8')
                    salt = bcrypt.gensalt()
                    hashpass = bcrypt.hashpw(password=attempted_password_encoded,salt=l_p)

                    if hashpass == l_p:
                        session['user'] = attempted_username
                        return redirect(url_for('dashboard'))

                return redirect(url_for('index'))

            else:
                return render_template('login.html', app=appName, url=url,
                                    urls=all_urls)

        except Exception as login_err:
            l = str(login_err)
            flash(l)
            return render_template('login.html', app=appName, url=url,
                                   urls=all_urls)


    @app.route('/register', methods=['GET', 'POST'])
    def register():

        url = str('Register')
        if request.method == 'POST':

            attempted_username = request.form['user']
            attempted_password = request.form['password']
            attempted_description = request.form['description']

            if attempted_username is None and attempted_password is None:
                return 'Enter some info about you !!!'

            users = database.db.users
            existing_user = users.find_one({
                'name': attempted_username
            })

            if existing_user is None:
                salt = bcrypt.gensalt()
                attempted_password_encoded = attempted_password.encode('utf-8')
                hashpass = bcrypt.hashpw(password=attempted_password_encoded
                                         , salt=salt)
                users.insert({
                    'name': attempted_username,
                    'password': hashpass,
                    'description': attempted_description
                })
                session['user'] = attempted_username
                session['logged_in'] = True

                if session['user'] is not None:
                    return redirect(url_for('login'))

                else:
                    return redirect(url_for('register'))

            else:
                return render_template('register.html', app=appName, url=url,
                               urls=all_urls)

        else:
            return render_template('register.html', app=appName, url=url,
                               urls=all_urls)

    def login_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user' in session is True:
                return f(*args, **kwargs)
            else:
                return redirect(url_for('index'))
        return wrapper

    @login_required
    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out')
        gc.collect()
        return redirect(url_for('dashboard'))

    @app.route('/profile')
    def profile():
        url = 'Profile'
        db = database.db.users

        try:
            if 'user' in session is not None:
                username = session['user']
                grab_description = db.find_one({
                    'name': username
                })
                if grab_description:
                    data = grab_description['description']
                    flash(message=username)
                    return render_template('profile.html', app=appName, url=url,
                                           urls=all_urls, description=data)

                else:
                    flash('Error we have no data about you ....')
                    return render_template('profile.html', app=appName, url=url,
                                           urls=all_urls)

            else:
                flash('Login please')
                return redirect(url_for('login'))

        except ConnectionAbortedError as conn_err:
            converted_conn_err = str(conn_err)
            flash(converted_conn_err)
            return redirect(url_for('login'))

        except Exception as main_err:
            converted_main_err = str(main_err)
            flash(converted_main_err)
            return redirect(url_for('login'))

    @app.route('/find', methods=['GET', 'POST'])
    def find():
        url = 'Find'
        db = database.db.users

        try:
            if 'user' in session:
                if request.method == 'POST':
                    what_to_find = request.form['search']
                    finder = db.find_one({
                        'name': what_to_find
                    })

                    if finder:
                        found = finder['name']
                        flash(found)
                        return render_template('find.html', app=appName, url=url,
                                               urls=all_urls)

                    else:
                        flash('Did not find anything in the database !')
                        return render_template('find.html', app=appName, url=url,
                                               urls=all_urls)

                else:
                    return render_template('find.html', app=appName, url=url,
                                           urls=all_urls)

            else:
                flash('Search only works when you are logged in ...')
                return render_template('find.html', app=appName, url=url,
                                       urls=all_urls)

        except Exception as find_err:
            encoded_find_err = str(find_err)
            flash(encoded_find_err)
            return render_template('find.html', app=appName, url=url,
                        urls=all_urls)

    @app.route('/update', methods=['GET', 'POST'])
    def update():
        url = 'Update info'
        db = database.db.users

        if 'user' in session:
            flash(session['user'])
            if request.method == 'POST':
                currently_logged_in = session['user']
                logged_in_user = db.find_one({
                    'name': currently_logged_in
                })

                if logged_in_user:
                    get_name = request.form['updater']

                    try:
                        db.update_one({
                            'name': currently_logged_in
                        }, {
                            '$set': {
                                'name': get_name
                            }
                        })
                        session['user'] = get_name

                        return redirect(url_for('profile'))

                    except Exception as update_err:
                        encoded_update_err = str(update_err)
                        flash(encoded_update_err)
                        return redirect(url_for('login'))

                else:
                    flash('Please login ')
                    return redirect(url_for('login'))

            else:
                return render_template('update.html', app=appName, url=url,
                        urls=all_urls)

        else:
            flash('Login please !')
            return redirect(url_for('login'))

    @app.route('/graph')
    def graph_f():
        url = 'Graph'

        try:
            if 'user' in session:
                graph = pygal.Line()
                graph.title = '% Change Coolness of programming languages over time.'
                graph.x_labels = ['2011', '2012', '2013', '2014', '2015', '2016']
                graph.add('Python', [15, 31, 89, 200, 356, 900])
                graph.add('Java', [15, 45, 76, 80, 91, 95])
                graph.add('C++', [5, 51, 54, 102, 150, 201])
                graph.add('All others combined!', [5, 15, 21, 55, 92, 105])
                data = graph.render_data_uri()

                return render_template('graph.html', app=appName, url=url,
                                       urls=all_urls, data=data)

            else:
                flash('Login Please')
                return redirect(url_for('login'))

        except Exception as graph_err:
            encoded_graph_err = str(graph_err)
            flash(encoded_graph_err)
            return redirect(url_for('dashboard'))

    # error code handlers . such as 404 , 405 etc .
    @app.errorhandler(code_or_exception=404)
    def error(not_found):
        url = '404'
        n = str(not_found)
        return render_template('404.html', app=appName, url=url,
                                   urls=all_urls, e=n)


    @app.errorhandler(code_or_exception=405)
    def error(not_found):
        url = '405'
        n = str(not_found)
        return render_template('405.html', app=appName, url=url,
                               urls=all_urls, e=n)

    if __name__ == '__main__':
        app.config['SECRET_KEY'] = secret_key
        app.run(debug=True, port=port)

except Exception as err:
    e = str(err)
    sys.stderr.write(e)
    sys.stderr.flush()

finally:
    print('Done , time taken , {}'
          .format(time_taken))
