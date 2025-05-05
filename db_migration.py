#!/usr/bin/env python3
"""
Database migration script to add folder_path column to Project table
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///testquerypairs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def migrate_database():
    """Add folder_path column to Project table"""
    
    try:
        # Check if column already exists
        with app.app_context():
            result = db.session.execute(text("PRAGMA table_info(project)"))
            columns = [row[1] for row in result]
            
            if 'folder_path' not in columns:
                # Add column
                db.session.execute(text("ALTER TABLE project ADD COLUMN folder_path VARCHAR(500)"))
                db.session.commit()
                print("✅ Added folder_path column to project table")
                
                # Update existing projects with a default path
                projects = db.session.execute(text("SELECT id, name FROM project")).fetchall()
                
                for project in projects:
                    project_id, project_name = project
                    # Create a default path based on project name
                    default_path = os.path.join(os.getcwd(), 'projects', project_name.lower().replace(' ', '_'))
                    
                    # Update the project
                    db.session.execute(
                        text("UPDATE project SET folder_path = :path WHERE id = :id"),
                        {"path": default_path, "id": project_id}
                    )
                    
                    # Create the folders
                    input_folder = os.path.join(default_path, 'input')
                    output_folder = os.path.join(default_path, 'output')
                    
                    os.makedirs(input_folder, exist_ok=True)
                    os.makedirs(output_folder, exist_ok=True)
                    
                    print(f"📁 Created folders for project '{project_name}' at {default_path}")
                
                db.session.commit()
                print("✅ Updated all existing projects with default folder paths")
            else:
                print("ℹ️ folder_path column already exists")
    
    except Exception as e:
        print(f"❌ Error during migration: {str(e)}")
        db.session.rollback()

if __name__ == "__main__":
    migrate_database()