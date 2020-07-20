import sqlite3

from mail import Base, Mail
from utils import *
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker


class MailDBManager:

    def __init__(self, dbname):
        self.dbname = dbname
        print(IMP_PFX + f"Creating {self.dbname}")

        # Create an engine that stores data in the specified sqlite file
        self.engine = create_engine(f'sqlite:///{self.dbname}', echo=True)
        self.create_table()

        # Establishs sessionwith the database
        DBSession = sessionmaker(bind=self.engine)

        # Any change made against the objects in the
        self.session = DBSession()

    def create_table(self):
         # Create all tables in the engine. This is equivalent to "Create Table"
        # statements in raw SQL.
        if not self.engine.dialect.has_table(self.engine, Mail.__tablename__):
            print("Creating table")
            # If table don't exist, Create.
            Mail.metadata.create_all(self.engine)

    def update_db(self, mails):
        for m in mails:
                # Insert new domain in table
                self.session.add(m)
                self.session.commit()



