#!/usr/bin/python3

from flask import Flask, render_template, redirect
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField
from wtforms.validators import DataRequired
import random

app = Flask(__name__)
app.config.from_object('config')

# list of cat images
cat_images = [
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr05/15/9/anigif_enhanced-buzz-26388-1381844103-11.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr01/15/9/anigif_enhanced-buzz-31540-1381844535-8.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr05/15/9/anigif_enhanced-buzz-26390-1381844163-18.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr06/15/10/anigif_enhanced-buzz-1376-1381846217-0.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr03/15/9/anigif_enhanced-buzz-3391-1381844336-26.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr06/15/10/anigif_enhanced-buzz-29111-1381845968-0.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr03/15/9/anigif_enhanced-buzz-3409-1381844582-13.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr02/15/9/anigif_enhanced-buzz-19667-1381844937-10.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr05/15/9/anigif_enhanced-buzz-26358-1381845043-13.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr06/15/9/anigif_enhanced-buzz-18774-1381844645-6.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr06/15/9/anigif_enhanced-buzz-25158-1381844793-0.gif",
    "http://ak-hdl.buzzfed.com/static/2013-10/enhanced/webdr03/15/10/anigif_enhanced-buzz-11980-1381846269-1.gif"
]

dog_images = [
    "https://img.buzzfeed.com/buzzfeed-static/static/2014-06/14/15/enhanced/webdr07/anigif_enhanced-30127-1402774426-6.gif",
    "https://img.buzzfeed.com/buzzfeed-static/static/2014-06/15/10/enhanced/webdr03/anigif_enhanced-22044-1402842988-8.gif",
    "https://img.buzzfeed.com/buzzfeed-static/static/2014-06/14/15/enhanced/webdr05/anigif_enhanced-23403-1402773525-1.gif",
    "https://img.buzzfeed.com/buzzfeed-static/static/2014-06/15/10/enhanced/webdr04/anigif_enhanced-1906-1402843089-21.gif"
]


@app.route('/')
def index():
    url = random.choice(cat_images)
    return render_template('index.html', url=url)


@app.route('/doggos')
def doggos():
    url = random.choice(dog_images)
    return render_template('dogs.html', url=url)


@app.route('/dogs')
def dogs():
    return redirect("/doggos")


class DogForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    cuteness_level = IntegerField('cuteness')
    url = StringField('url')

@app.route('/doggos/add', methods=['GET', 'POST'])
def add():
    form = DogForm()
    return render_template('dogs_form.html',
                           title='Add doggo',
                           form=form)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)