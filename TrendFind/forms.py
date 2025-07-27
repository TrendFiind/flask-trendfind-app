from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegisterForm(FlaskForm):
    name     = StringField("Name",     validators=[DataRequired()])
    email    = StringField("Email",    validators=[DataRequired(), Email()])
    password = PasswordField("Password",
                             validators=[DataRequired(), Length(min=8)])
    confirm  = PasswordField("Confirm",
                             validators=[EqualTo('password')])
    submit   = SubmitField("Create account")

class LoginForm(FlaskForm):
    email    = StringField("Email",      validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit   = SubmitField("Sign In")

#wrewrwer#wer
