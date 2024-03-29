import os
import secrets
from flask import render_template, url_for, redirect, flash, request, abort
from projectmlm.forms import RegistrationForm, LoginForm #RecipeForm, UpdateProfileForm
from projectmlm.models import User
from projectmlm import app, db, bcrypt
from flask_login import login_user, current_user, logout_user, login_required

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in')
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get("next")
            return redirect(next_page) if next_page else redirect(url_for("home"))
        else:
            flash("Login Unsuccessful. Please check your username and password")
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash("You have been successfuly logged out!")
    return redirect(url_for("login"))