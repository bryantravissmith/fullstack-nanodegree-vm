from flask import (
    Flask,
    render_template,
    request,
    url_for,
    redirect,
    flash,
    jsonify,
    session as login_session,
    make_response
)
import random, string
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
import json
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import requests

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read()
)['web']['client_id']

app = Flask(__name__)

engine = create_engine(#'sqlite:///restaurantmenu.db'
    'sqlite:///restaurantmenuwithusers.db'
)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(
            json.dumps('Invalid state parameters!'),
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    app_id = json.loads(open('fb_secret.json', 'r'))['web']['app_id']
    app_secret = json.loads(open('fb_secret.json', 'r'))['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' \
        % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)

    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    url = 'https://graph/facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data['data']['url']

    user_id = getUserId(login_session['email'])
    if user_id is None:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = """
    <h1>Welcome {}!</h1>
    <img src='{}' style="width: 300px; height: 300px; border-radius:150px;
        -webkit-border-radius:150px; -moz-border-radius:150px; radius:150px;">
    """.format(login_session['username'], login_session['picture'])
    flash("You are not logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect', methods=['POST'])
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['facebook_id']
    return 'you have been logged out'


@app.route('/disconnect', methods=['POST'])
def disconnect():
    if 'provider' in login_session:

        if login_session['provider'] == 'google':
            del login_session['gplust_id']
            del login_session['credentials']

        if login_session['provider'] == 'facebook':
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out")
    else:
        flash("You are not loggedin")
    return redirect(url_for('restaurant'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(
            json.dumps('Invalid state parameters!'),
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response('Failed to upgrade authorization code', 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = (
        'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=%s' % access_token
    )
    h = httplib2.Http()
    r = h.request(url, 'GET')
    print(r[1].decode("utf-8"))
    result = json.loads(r[1].decode("utf-8"))
    if result.get('error') is not None:
        response = make_response(json.dump(result.get('error')), 501)
        response.headers['Content-Type'] = 'application/json'

    gplus_id = credentials.id_token['sub']
    if result['sub'] != gplus_id:
        response = make_response(
            "Token's user_id does not match given user_id",
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['azp'] != CLIENT_ID:
        response = make_response(
            "Token's client id does not match given app's client id",
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credientials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and stored_gplus_id == gplus_id:
        response = make_response(
            "Current user is alrady logged in.",
            200
        )
        response.headers['Content-Type'] = 'application/json'

    login_session['credientials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json'
    params = {
        'access_token': credentials.access_token,
        'alt': 'json'
    }
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserId(login_session['email'])
    if user_id is None:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = """
    <h1>Welcome {}!</h1>
    <img src='{}' style="width: 300px; height: 300px; border-radius:150px;
        -webkit-border-radius:150px; -moz-border-radius:150px; radius:150px;">
    """.format(login_session['username'], login_session['picture'])
    flash("You are not logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    print(login_session)
    credentials = login_session.get('credientials')
    if credentials is None:
        response = make_response(
            "User is not logged in.",
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['credientials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        del login_session['email']

        response = make_response(
            json.dumps('Successful disconnnect'),
            200
            )
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Unsuccessful disconnnect'),
            401
            )
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@app.route('/restaurant/')
def restaurant():
    restaurants = session.query(Restaurant).all()

    output = ''
    for r in restaurants:
        output += '<a href="/restaurant/{}">{}</a>'\
            .format(r.id, r.name)
        output += '</br></br>'

    return output


@app.route('/login')
def login():
    state = ''.join([random.choice(
        string.ascii_uppercase + string.digits
    ) for x in range(32)])
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/restaurant/<int:restaurant_id>/')
def restaurant_items(restaurant_id):

    restaurant = session.query(Restaurant)\
        .filter_by(id=restaurant_id).one()
    items = session.query(MenuItem)\
        .filter_by(restaurant_id=restaurant.id).all()
    return render_template(
        'menu.html',
        restaurant=restaurant,
        items=items,
        creator=restaurant.user,
        user_id=login_session['user_id']
    )


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant)\
        .filter_by(id=restaurant_id).one()
    items = session.query(MenuItem)\
        .filter_by(restaurant_id=restaurant.id).all()

    return jsonify(MenuItems=[i.serialize() for i in items])


@app.route('/restaurant/<int:restaurant_id>/<int:menu_item_id>/JSON')
def menuItemJSON(restaurant_id, menu_item_id):

    restaurant = session.query(Restaurant)\
        .filter_by(id=restaurant_id).one()
    item = session.query(MenuItem)\
        .filter_by(
            restaurant_id=restaurant.id,
            id=menu_item_id
        ).one()

    return jsonify(item.serialize())


@app.route('/restaurant/<int:restaurant_id>/<int:menu_item_id>/')
def menu_item(restaurant_id, menu_item_id):

    restaurant = session.query(Restaurant)\
        .filter_by(id=restaurant_id).one()
    item = session.query(MenuItem)\
        .filter_by(
            restaurant_id=restaurant.id,
            id=menu_item_id
        ).one()

    output = ''
    output += item.name
    output += '</br>'
    output += item.description
    output += '</br>'
    output += item.price
    output += '</br></br>'
    return output


@app.route('/restaurant/<int:restaurant_id>/new', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('login')
    if request.method == 'POST':
        newItem = MenuItem(
            name=request.form['name'],
            restaurant_id=restaurant_id,
            user_id=login_session['user_id']
        )
        session.add(newItem)
        session.commit
        flash('new menu item created!')
        return redirect(
            url_for('restaurant_items', restaurant_id=restaurant_id)
            )
    else:
        return render_template(
            'create_menu_item.html',
            restaurant_id=restaurant_id
        )


@app.route(
    '/restaurant/<int:restaurant_id>/<int:menu_item_id>/edit/',
    methods=['GET', 'POST']
)
def editMenuItem(restaurant_id, menu_item_id):
    if 'username' not in login_session:
        return redirect('login')
    if request.method == 'POST':
        item = session.query(MenuItem).filter_by(id=menu_item_id).one()
        for key in ['name', 'description', 'price']:
            if request.form[key] != '':
                setattr(item, key, request.form[key])
        session.add(item)
        session.commit()
        flash('menu item edited!')
        return redirect(
            url_for('restaurant_items', restaurant_id=restaurant_id)
        )
    else:
        item = session.query(MenuItem).filter_by(
            restaurant_id=restaurant_id,
            id=menu_item_id
        ).one()
        return render_template(
            'edit_menu_item.html',
            restaurant_id=restaurant_id,
            menu_item_id=menu_item_id,
            item=item
        )


@app.route(
    '/restaurant/<int:restaurant_id>/<int:menu_item_id>/delete/',
    methods=['GET', 'POST']
)
def deleteMenuItem(restaurant_id, menu_item_id):
    if 'username' not in login_session:
        return redirect('login')
    if request.method == 'POST':
        item = session.query(MenuItem).filter_by(
            restaurant_id=restaurant_id,
            id=menu_item_id
        ).one()
        session.delete(item)
        session.commit()
        flash('menu item deleted!')
        return redirect(
            url_for('restaurant_items', restaurant_id=restaurant_id)
        )
    else:
        return render_template(
            'delete_menu_item.html',
            restaurant_id=restaurant_id,
            menu_item_id=menu_item_id,
        )


def createUser(login_session):
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User)\
        .filter_by(email=login_session['email'])\
        .one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    client_id = '1070036333123-6vnfiak35b2u94dlkcbf4npe7jl5237h.apps.googleusercontent.com'
    client_secret = 'uPNzokmU66zYSH6weK0KqZqB'
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
