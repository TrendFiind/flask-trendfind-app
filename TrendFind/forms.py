from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegisterForm(FlaskForm):
    name     = StringField("Full Name",  validators=[DataRequired()])
    email    = StringField("Email",      validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm  = PasswordField("Confirm",  validators=[EqualTo("password")])
    recaptcha= RecaptchaField()
    submit   = SubmitField("Create Account")

class LoginForm(FlaskForm):
    email    = StringField("Email",      validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit   = SubmitField("Sign In")
