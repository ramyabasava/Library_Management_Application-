import sqlite3
import click
from flask import current_app, g
from werkzeug.security import generate_password_hash

def get_db():
    """Connect to the application's configured database."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Close the database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Clear existing data and create new tables."""
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

    # Create an initial admin user
    try:
        db.execute(
            "INSERT INTO user (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ('admin', 'admin@example.com', generate_password_hash('admin123'), 'admin'),
        )
        db.commit()
        print("Admin user created with username 'admin' and password 'admin123'")
    except db.IntegrityError:
        print("Admin user already exists.")

@click.command('init-db')
def init_db_command():
    """CLI command to clear the data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

def init_app(app):
    """Register database functions with the Flask app."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)