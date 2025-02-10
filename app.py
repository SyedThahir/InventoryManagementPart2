from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Yourpassword@localhost/inventory_db'
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Flask-Limiter for rate-limiting
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# User Model
class User(db.Model, UserMixin):
    __tablename__ = 'Users'
    UserID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(50), unique=True, nullable=False)
    PasswordHash = db.Column(db.String(255), nullable=False)
    Role = db.Column(db.String(10), nullable=False)

    # Override get_id to use UserID instead of id
    def get_id(self):
        return str(self.UserID)

# Product Model
class Product(db.Model):
    __tablename__ = 'Products'
    ProductID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(50), nullable=False)
    Description = db.Column(db.String(255))
    StockQuantity = db.Column(db.Integer, default=0)
    ReorderLevel = db.Column(db.Integer, default=0)
    SupplierID = db.Column(db.Integer, db.ForeignKey('Suppliers.SupplierID'))

# Supplier Model
class Supplier(db.Model):
    __tablename__ = 'Suppliers'
    SupplierID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(50), nullable=False)
    ContactDetails = db.Column(db.String(100))
    Email = db.Column(db.String(50))

# Transaction Model
class Transaction(db.Model):
    __tablename__ = 'Transactions'
    TransactionID = db.Column(db.Integer, primary_key=True)
    ProductID = db.Column(db.Integer, db.ForeignKey('Products.ProductID', ondelete='CASCADE'))
    Quantity = db.Column(db.Integer, nullable=False)
    Date = db.Column(db.DateTime, default=db.func.current_timestamp())
    Type = db.Column(db.String(10))  # 'Add' or 'Remove'

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-Based Access Control (RBAC) decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.Role != 'admin':
            flash("Access denied: Admin privileges required.", 'danger')
            return redirect(url_for('error_page'))
        return f(*args, **kwargs)
    return decorated_function

# Route: Login with rate-limiting
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate-limit: 5 requests per minute per IP
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(Username=username).first()
        if user and bcrypt.check_password_hash(user.PasswordHash, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

# Custom rate-limit exceeded error handler
@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template('error_page.html', message="Too many requests. Please try again later."), 429

# Route: Dashboard
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# Route: Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route: Admin-only (manage users)
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(Username=username, PasswordHash=hashed_password, Role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('New user added successfully!', 'success')
    return render_template('admin_dashboard.html', users=users)

# Route: Delete user (Admin only)
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.Username == 'admin':
        flash("Cannot delete the default admin user.", 'danger')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# Route: Products CRUD
@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    if request.method == 'POST':
        if current_user.Role != 'admin':
            flash("Only admins can add products.", 'danger')
            return redirect(url_for('products'))
        name = request.form['name']
        description = request.form['description']
        stock_quantity = int(request.form['stock_quantity'])
        reorder_level = int(request.form['reorder_level'])
        supplier_id = int(request.form['supplier_id'])
        new_product = Product(Name=name, Description=description,
                              StockQuantity=stock_quantity,
                              ReorderLevel=reorder_level,
                              SupplierID=supplier_id)
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully!', 'success')
    products = Product.query.all()
    return render_template('products.html', products=products)

# Route: Delete Product
@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if current_user.Role != 'admin':
        flash("Permission denied: Only admins can delete products.", 'danger')
        return redirect(url_for('products'))
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product and its associated transactions deleted successfully!', 'success')
    return redirect(url_for('products'))

# Route: Suppliers CRUD
@app.route('/suppliers', methods=['GET', 'POST'])
@login_required
def suppliers():
    if request.method == 'POST':
        name = request.form['name']
        contact_details = request.form['contact_details']
        email = request.form['email']
        new_supplier = Supplier(Name=name, ContactDetails=contact_details, Email=email)
        db.session.add(new_supplier)
        db.session.commit()
        flash('Supplier added successfully!', 'success')
    suppliers = Supplier.query.all()
    return render_template('suppliers.html', suppliers=suppliers)

# Route: Delete Supplier
@app.route('/delete_supplier/<int:supplier_id>', methods=['POST'])
@login_required
def delete_supplier(supplier_id):
    if current_user.Role != 'admin':
        flash("Permission denied: Only admins can delete suppliers.", 'danger')
        return redirect(url_for('suppliers'))
    supplier = Supplier.query.get_or_404(supplier_id)
    associated_products = Product.query.filter_by(SupplierID=supplier_id).all()
    if associated_products:
        flash("Cannot delete supplier with associated products.", 'danger')
        return redirect(url_for('suppliers'))
    db.session.delete(supplier)
    db.session.commit()
    flash('Supplier deleted successfully!', 'success')
    return redirect(url_for('suppliers'))

# Route: Transactions
@app.route('/transactions', methods=['GET', 'POST'])
@login_required
def transactions():
    if request.method == 'POST':
        product_id = request.form['product_id']
        quantity = int(request.form['quantity'])
        transaction_type = request.form['type']
        new_transaction = Transaction(ProductID=product_id, Quantity=quantity, Type=transaction_type)
        product = Product.query.get(product_id)

        if transaction_type == 'Add':
            product.StockQuantity += quantity
        elif transaction_type == 'Remove' and product.StockQuantity >= quantity:
            product.StockQuantity -= quantity
        else:
            flash('Not enough stock for this transaction!', 'danger')
            return redirect(url_for('transactions'))

        db.session.add(new_transaction)
        db.session.commit()
        flash('Transaction recorded successfully!', 'success')
    transactions = Transaction.query.all()
    products = Product.query.all()
    return render_template('transactions.html', transactions=transactions, products=products)

# Route: Error Page
@app.route('/error_page')
def error_page():
    return render_template('error_page.html', message="Access denied: You do not have permission to access this page.")

# Ensure the database is created and set up a default admin user
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(Username='admin').first()
        if not admin:
            hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin = User(Username='admin', PasswordHash=hashed_password, Role='admin')
            db.session.add(admin)
            db.session.commit()
            print('Default admin user created: Username=admin, Password=admin123')

    app.run(debug=True)
