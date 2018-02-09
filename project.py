from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

app = Flask(__name__)

# The engine is the starting point for any SQLAlchemy application.
engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

# Create a session and connect to DB
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/restaurants/')
def restaurant_list():
    restaurants = session.query(Restaurant).all()
    output = ''
    for restaurant in restaurants:
        output += "<a href ='/restaurant/%s/'> %s </a>" % (restaurant.id, restaurant.name)
        output += '</br>'
        print restaurant
    return output

# List all items in a restaurant


@app.route('/restaurant/<int:restaurant_id>/')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).get(restaurant_id)
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
    return render_template('menu.html', items=items, restaurant=restaurant,
                           restaurant_id=restaurant_id,
                           )


# Task 1: Create route for newMenuItem function here


@app.route('/restaurant/<int:restaurant_id>/new/', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if request.method == 'POST':
        newItem = MenuItem(
            name=request.form['name'], restaurant_id=restaurant_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))

    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)


# Task 2: Create route for editMenuItem function here


@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    '''NOTES:
    I have named the query editedItem because, after replacing the MenuItem
    name with the new name, we commit this query. At that point in time it is
    edited. Therefore it makes sense to call it editedItem as opposed to
     editItem'''
    editedItem = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    print 'Original Name:', editedItem.name

    if request.method == 'POST':
        if request.form['name']:
            # Fetch the name of the edited Item
            edited_item_name = request.form['name']

            # Replace the old name with edited_item_name
            editedItem.name = edited_item_name
            print 'Updated Name:', editedItem.name

            # Add the new name to DB and commit
            session.add(editedItem)
            session.commit()

            # Redirect to Restaurant Menu Item Page
            return redirect(url_for('restaurantMenu',
                                    restaurant_id=restaurant_id))

    else:
        return render_template('editmenuitem.html',
                               restaurant_id=restaurant_id, menu_id=menu_id,
                               item=editedItem)

# Task 3: Create a route for deleteMenuItem function here


@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    deletedItem = session.query(
        MenuItem).filter_by(id=menu_id).one()

    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()

        # Redirect to Restaurant Menu Item Page
        return redirect(url_for('restaurantMenu',
                                restaurant_id=restaurant_id))

    else:
        return render_template('delete.html', restaurant_id=restaurant_id,
                               menu_id=menu_id, item=deletedItem)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
