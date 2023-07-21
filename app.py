import os
import sqlite3
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    # Get user's cash balance
    user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = user[0]["cash"]

    # Retrieve user's holdings from SQL view, this returns a list of dict of symbols and total shares of that symbol
    holdings = db.execute("SELECT symbol, total_shares FROM stock_holdings WHERE user_id=? and total_shares > 0", session["user_id"])

    # initial total value without stocks
    total_value = cash

    #create a new list for displaying rows
    rows = []

    for holding in holdings:
        symbol = holding["symbol"]
        total_shares = holding["total_shares"]
        stock = lookup(symbol)
        price = stock["price"]
        value = price * total_shares
        total_value += value

        # create a dict for each row in rows
        row = {
            "symbol": symbol,
            "shares": total_shares,
            "price": usd(price),
            "value": usd(value)
        }

        # add rows to the list
        rows.append(row)
    if request.method == "GET":
        return render_template("index.html", rows=rows, cash=usd(cash), total_value=usd(total_value))
    else:
        return render_template("addcash.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Get user inputs
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate inputs
        if not symbol:
            return apology("Please enter a stock symbol.")
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Please enter a positive number for number of shares.")

        stock = lookup(symbol) # datatype is dict
        if stock is None:
            return apology("Stock symbol does not exist.")

        # Get user's cash balance
        user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"] )
        cash = user[0]["cash"]

        # Calculate total cost
        share_price = stock["price"]
        total_cost = share_price * int(shares)

        if total_cost > cash:
            return apology("Sorry, you don't have enough cash.")

        new_balance = cash - total_cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])

        db.execute("INSERT INTO purchases (user_id, symbol, shares, price, total) VALUES(?, ?, ?, ?, ?);", session["user_id"], symbol, int(shares), share_price, total_cost)

        return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    # Get user inputs
    add_cash_amount = float(request.form.get("add_cash"))
    if request.method == "GET":

        return render_template("addcash.html")

    else:

        db.execute("UPDATE USERS SET cash = cash + ? WHERE id = ?", add_cash_amount, session["user_id"])

    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # retrieve transaction data from purchases table
    transactions = db.execute("SELECT symbol, shares, price, total, timestamp FROM purchases WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions = transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # display form to request a stock quote if requested via GET
    if request.method == "GET":
        return render_template("quote.html")
    # if via POST,lookup the stock symbol by calling the lookup function, and display results
    else:
        symbol = request.form.get("symbol")
        symbol = symbol.upper()
        stock_dict = lookup(symbol)
        if stock_dict:
            lookup_name = stock_dict.get("name")
            lookup_price = usd(stock_dict.get("price"))
            lookup_symbol = stock_dict.get("symbol")
            if symbol == lookup_symbol:
                quote_placeholder = f"A share of {lookup_name} costs {lookup_price}"
                return render_template("quoted.html", quote_placeholder = quote_placeholder)

        return apology("Please enter a correct stock symbol!")





@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Get user's input
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Generate hash password
        hashed_password = generate_password_hash(password)

        # Validate the user's input

        row = db.execute("SELECT * FROM users WHERE username=(?);", username)
        if not username:
            flash("Please provide username.")
            return render_template("register.html"), 400
        elif not password or not confirmation:
            flash("Please enter password.")
            return render_template("register.html"), 400
        elif password != confirmation:
            flash ("Passwords do not match.")
            return render_template("register.html"), 400
        elif row:
            flash("Username already exist, please pick a different username.")
            return render_template("register.html"), 400
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?,?);", username, hashed_password)
            flash("Congratulations! Your account has been successfully created, please log in.")
            return render_template("login.html"), 200





    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Get user inputs
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        user_holdings = db.execute("SELECT total_shares FROM stock_holdings where user_id = ? AND symbol = ?", session["user_id"], symbol)
        #print(user_holdings)

        #Validate user inputs
        if not shares:
            return apology("Please enter a valid number of shares.")
        elif user_holdings[0]["total_shares"] < shares:
            return apology("You don't own that many shares of the stock")

        # Retrieve current stock price
        stock = lookup(symbol)
        price = stock["price"]

        total_sell_value = price * shares

        # add total sell value to user's cash balance
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_sell_value, session["user_id"])

        # Update purchases table
        db.execute("INSERT INTO purchases (user_id, symbol, shares, price, total) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, -shares, price, total_sell_value)

        return redirect("/")

    else:
        user_symbols = db.execute("SELECT symbol FROM stock_holdings where user_id = ?", session["user_id"])
        return render_template("sell.html", symbols=user_symbols)
