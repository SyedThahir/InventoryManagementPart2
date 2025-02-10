# InventoryManagementPart2

# Inventory Management System Setup on EC2

This guide provides instructions for setting up the **Inventory Management System** on an **Amazon EC2 instance** and connecting it to an **RDS MySQL database**.

---

## Prerequisites

- An **AWS EC2 instance** with a public IP and SSH access.
- An **RDS MySQL instance** for database storage.
- **Apache HTTP Server** installed on the EC2 instance.
- **Git** installed to clone the application repository.

---

## Step 1: Install Apache Web Server

1. **Install Apache**:
   On your EC2 instance, run the following command to install Apache HTTP Server:
   ```bash
   
   sudo yum install -y httpd

Start Apache: After installation, start the Apache web server:
sudo systemctl start httpd

Enable Apache to Start on Boot: It's a good practice to enable Apache to automatically start when the system boots:
sudo systemctl enable httpd

## Step 2: Clone the Application from GitHub

Install Git: To clone the application repository, you first need to install Git:

sudo yum install git -y

Navigate to the Web Directory: Move to the directory where Apache serves web files:

cd /var/www/html

Clone the Repository: Clone the Inventory Management System repository from GitHub:

sudo git clone https://github.com/SyedThahir/InventoryManagementPart2.git .

## Step 3: Configure the Application

Change File Ownership: You need to change the ownership of the application files to the ec2-user to ensure proper access:

sudo chown ec2-user:ec2-user app.py


Modify File Permissions: Allow write permissions to app.py:

sudo chmod u+w app.py


Update the SQLAlchemy database URI to use your RDS MySQL database:

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://<username>:<password>@<hostname>:<port>/<database_name>'

Where:

<username>: Your MySQL database username (e.g., admin).
<password>: The password for your MySQL database.
<hostname>: The endpoint of your RDS instance (e.g., inventorydb.c70g46kaqjbm.us-east-1.rds.amazonaws.com).
<port>: The port on which your MySQL server is listening (typically 3306 for MySQL).
<database_name>: The name of your database (e.g., inventory_db).

Example:
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:Password123@inventorydb.c096hbrrwojq.us-east-1.rds.amazonaws.com:3306/inventory_db'





