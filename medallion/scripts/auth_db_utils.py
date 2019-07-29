import uuid
import sys
import six

from werkzeug.security import generate_password_hash, check_password_hash

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError


def make_connection(uri):
    try:
        client = MongoClient(uri)
        # The ismaster command is cheap and does not require auth.
        client.admin.command("ismaster")

        return client
    except ConnectionFailure:
        print "Unable to establish a connection to MongoDB server {}".format(uri)


def delete_user(client, email):
    # TODO: delete user's api keys, delete user
    pass


def delete_api_key_for_user(client, api_key):
    # TODO: delete api key
    pass


def add_api_key_for_user(client, email):
    api_key = str(uuid.uuid4()).replace('-', '')
    api_key_obj = {
        "_id": api_key,
        "user_id": email,
        "created": "",
        "last_used_at": "",
        "last_used_from": ""
    }

    # Check that the user exists. If the user exists, insert the new api_key, and update the corresponding user.
    db = client['auth']
    users = db['users']
    user = users.find_one({"_id": email})

    if user:
        # Add an api key and print it.
        api_keys = db['api_keys']
        api_keys.insert_one(api_key_obj)

        print 'new api key: {} added for email: {}'.format(api_key, email)
    else:
        print 'no user with email: {} was found in the database.'.format(email)


def add_user(client, user):
    # Insert the new user.
    db = client['auth']
    users = db['users']
    users.insert_one(user)


def backup_db():
    pass


def main():
    uri = "mongodb://root:example@localhost:27017/"
    if len(sys.argv) == 2:
        client = make_connection(uri)

        opt = sys.argv[1]

        if opt == '-u':
            email = six.moves.input('email address      :').strip()

            password1 = six.moves.input('password           :').strip()
            password2 = six.moves.input('verify password    :').strip()

            if password1 != password2:
                sys.exit('passwords were not the same')

            company_name = six.moves.input('company name       :').strip()
            contact_name = six.moves.input('contact name       :').strip()
            add_api_key = six.moves.input('add api key (y/n)? :').strip()

            password_hash = generate_password_hash(password1)

            user = {
                "_id": email,
                "password": password_hash,
                "company_name": company_name,
                "contact_name": contact_name,
                "created": "",
                "updated": ""
            }

            add_user(client, user)

            if add_api_key.lower() == 'y':
                add_api_key_for_user(client, email)

        elif opt == '-k':
            email = six.moves.input('email address      :')

            add_api_key_for_user(client, email)
        elif opt == '-du':
            email = six.moves.input('email address      :')

            delete_user(client, email)
        elif opt == '-dk':
            api_key = six.moves.input('api key          :')

            delete_api_key_for_user(client, api_key)
        else:
            print "usage: '-u' (add user), '-k' (add api key), '-du' (delete user), '-dk' (delete api key)"
    else:
        print "usage: '-u' (add user), '-k' (add api key), '-du' (delete user), '-dk' (delete api key)"


if __name__ == "__main__":
    main()
