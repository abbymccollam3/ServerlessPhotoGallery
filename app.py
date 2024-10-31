#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, RDS_DB_HOSTNAME, RDS_DB_USERNAME, RDS_DB_PASSWORD, RDS_DB_NAME
from flask import Flask, jsonify, abort, request, make_response, url_for, session
from flask import render_template, redirect
import time
import exifread
import json
import uuid
import boto3  
import pymysql.cursors
from datetime import datetime
from pytz import timezone
import pytz

"""
    INSERT NEW LIBRARIES HERE (IF NEEDED)
"""

from itsdangerous import URLSafeTimedSerializer
import bcrypt
from botocore.exceptions import ClientError

"""
"""

# GLOBAL VARIABLES
serializer = URLSafeTimedSerializer("hey") #maybe userID

# GENERATE PASSWORD HASH
userID = uuid.uuid4() #generate uuid
encoded_userID = str(userID)
salt = bcrypt.gensalt() # Generating Salt

SENDER = "amccollam3@gatech.edu"
RECEIVER = "abby.mccollam@gmail.com"

app = Flask(__name__, static_url_path="")
app.secret_key = AWS_SECRET_ACCESS_KEY

UPLOAD_FOLDER = os.path.join(app.root_path,'static','media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def getExifData(path_name):
    f = open(path_name, 'rb')
    tags = exifread.process_file(f)
    ExifData={}
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
            key="%s"%(tag)
            val="%s"%(tags[tag])
            ExifData[key]=val
    return ExifData


def s3uploading(filename, filenameWithPath, uploadType="photos"):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                       
    bucket = PHOTOGALLERY_S3_BUCKET_NAME
    path_filename = uploadType + "/" + filename

    s3.upload_file(filenameWithPath, bucket, path_filename)  
    s3.put_object_acl(ACL='public-read', Bucket=bucket, Key=path_filename)
    return f'''http://{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/{path_filename}'''

def get_database_connection():
    conn = pymysql.connect(host=RDS_DB_HOSTNAME,
                             user=RDS_DB_USERNAME,
                             password=RDS_DB_PASSWORD,
                             db=RDS_DB_NAME,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)
    return conn

def send_email(email, token):

    RECEIVER = email
    body = f'This is an email from AWS SES. Click this link to confirm your email: http://3.88.68.128:5000/confirm/{token}/{encoded_userID}'

    try:
        ses = boto3.client('ses', aws_access_key_id=AWS_ACCESS_KEY,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                                region_name=AWS_REGION)
        response = ses.send_email(
            Source=SENDER,
            Destination={'ToAddresses': [RECEIVER]},
            Message={
                'Subject': {'Data': 'Photo Gallery: Confirm Your Account'},
                'Body': {
                    'Text': {'Data': body}
                }
            }
        )

    except ClientError as e:
        print(e.response['Error']['Message'])

        return False
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])

        return True

"""INSERT YOUR NEW FUNCTION HERE (IF NEEDED)"""

# FUNCTION TO GET USERID FROM EMAIL
def get_userID (this_email): 

    conn=get_database_connection()
    cursor = conn.cursor ()

    # getting email that user has enterd
    statement = f'''SELECT userID FROM photogallerydb.User WHERE email LIKE '%{this_email}%';'''
    cursor.execute(statement)
    retrieveID = cursor.fetchall()

    # retrieveID is [{'userID': 'd80f9ca1-a3b7-4de7-8415-d6dd1f5f5821'}]

    if retrieveID:
        for row in retrieveID:
            return row['userID']
            print("retrieveID: ", row['userID'])
    else:
        print ("nothing printed")
        return 0

    conn.close()

# FUNCTION TO DELETE ALBUMS ATTACHED TO ACCOUNT
def now_delete_albums(albumID):

        conn=get_database_connection()
        cursor = conn.cursor ()

        # delete album
        first_statement = f'''DELETE FROM photogallerydb.Album WHERE albumID="{albumID}";'''
        cursor.execute(first_statement)

        try:
            next_statement = f'''DELETE FROM photogallerydb.Photo WHERE albumID="{albumID}";'''
            cursor.execute(next_statement)

        except:
            print("No photos to delete")

        conn.commit()
        conn.close()

        return redirect('/index')


""" INSERT YOUR NEW ROUTE HERE (IF NEEDED) """

"""-----------------------------LOADING DEFAULT PAGE----------------------------------"""
@app.route('/')
def anything():
    return redirect ('/signup')


"""-----------------------------LOADING SIGNUP PAGE----------------------------------"""
@app.route('/signup', methods=['GET', 'POST']) 
def signup_page():

    if request.method == 'POST': #when Sign Up button is clicked
        global first_name, last_name, hash_password, email

        first_name = request.form['first_name'] 
        last_name = request.form['last_name']
        password = request.form['password']
        email = request.form['email']

        query = request.args.get('query', None)

        # Hashing Password
        hash_password = bcrypt.hashpw(
            password=password.encode("utf-8"),
            salt=salt
        )

        conn=get_database_connection()
        cursor = conn.cursor ()
        statement = f'''SELECT * FROM photogallerydb.User WHERE email LIKE '%{email}%';'''
        cursor.execute(statement)

        results = cursor.fetchall()
        print("results: ", results)
        conn.close()

        if len(results) <= 0: #if email is not currently in table
            global createdAtlocalTime, createdAtUTCTime

            # Generating timestamp
            createdAtlocalTime = datetime.now().astimezone()
            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)

            token = serializer.dumps(email, salt="A2B3") #what belongs here
            send_email(email, token) # sending email

            return redirect('/login')

        else:
            print("Email already in use.")
            return redirect('/signup')

    else:
        return render_template('signup.html')

"""-----------------------------LOADING TOKEN PAGE----------------------------------"""
@app.route('/confirm/<token>/<encoded_userID>', methods=['GET']) 
def confirm_page(token, encoded_userID):

    print("Hello")

     # check if token is expired - DOES THIS NEED TO BE MOVED
    try:
        decoded_email = serializer.loads(
            token, 
            salt="A2B3", 
            max_age=600 #expires after 10 minutes
        )

        print(decoded_email)

        conn=get_database_connection()
        cursor = conn.cursor ()
        statement = f'''INSERT INTO photogallerydb.User (userID, email, firstName, lastName, password, createdAt) VALUES ("{encoded_userID}", "{email}", "{first_name}", "{last_name}", "{hash_password}", "{createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S")}");''' 
        new_result = cursor.execute(statement)

        print(new_result)

    except Exception as e:
        print("expired token") 
        return 'URL expired'

    query = request.args.get('query', None)
    lookup = f'''SELECT * FROM photogallerydb.User WHERE email LIKE '%{query}%';'''
    result = cursor.execute(lookup)
    conn.commit()
    conn.close()

    if result == 0:
        print("Entering this loop")
        return redirect('/login')

    else:
        print ("User not verified.")

"""-----------------------------LOADING LOGIN PAGE----------------------------------"""
@app.route('/login', methods=['POST', 'GET'])
def login_page():

    # insert description here

    if request.method == 'POST': 

        entered = request.form['email'] #email user has entered
        this_ID = get_userID(entered) 
        session['userID'] = this_ID

        print("thisID: ", this_ID)

        if this_ID != 0:
            # User-provided Password
            user_password = request.form['password'] 
            
            # Checking Password
            check = bcrypt.checkpw(
                password=user_password.encode("utf-8"),
                hashed_password=hash_password
            )
            
            print(check) #printing true or false
            print ("now in POST")
            
            # Verifying the Password
            if check:
                return redirect ('/index')
                print("Welcome!")
            
            else:
                print("Invalid Credential.")

        else:
            bad_request(400)
            return 'User Not Found'
            print("Error.") 

    else:
        print("Not a post method.")

    return render_template('login.html')


"""-----------------------------LOADING DELETE ACCOUNT----------------------------------"""
@app.route('/delete', methods=['GET', 'POST'])
def delete_account():

    if request.method == 'POST':

        delete_email = request.form['email'] 
        delete_userID = get_userID(delete_email)

        print("Delete userID: ", delete_userID)

        conn=get_database_connection()
        cursor = conn.cursor ()

        # Scan Album table to find createBy = user ID

        statement = f'''SELECT albumID FROM photogallerydb.Album WHERE createdBy LIKE '%{delete_userID}%';'''
        cursor.execute(statement)
        retrieveID = cursor.fetchall()

        print("RetreiveID: ", retrieveID)

        # Call delete_albums, which also calls delete photo
        if retrieveID:
            print("Got tables that matched")
            for row in retrieveID:
                delete_albumID = row['albumID']
                print("deleteAlbumID: ", delete_albumID)
                now_delete_albums(delete_albumID)

        else:
            print("Nothing matched")

        # Delete User
        statement = f'''DELETE FROM photogallerydb.User WHERE userID="{userID}";'''
        cursor.execute(statement)
        results = cursor.fetchall()

        conn.commit()
        conn.close()

        print("Deleted everything")
        return redirect('/login')

    else:
        print("In delete GET")

    return render_template('delete_account.html')


"""-----------------------------LOADING DELETE ALBUM----------------------------------"""
@app.route('/delete/<string:albumID>', methods=['GET', 'POST'])
def delete_album(albumID):

    if request.method == 'GET':

        try:
            conn=get_database_connection()
            cursor = conn.cursor ()

            # delete album
            first_statement = f'''DELETE FROM photogallerydb.Album WHERE albumID="{albumID}";'''
            cursor.execute(first_statement)


            try:
                next_statement = f'''DELETE FROM photogallerydb.Photo WHERE albumID="{albumID}";'''
                cursor.execute(next_statement)

            except:
                print("No photos to delete")

            conn.commit()
            conn.close()

            return redirect('/index')

        except Exception as e:
            print("Could not delete album.") 

    else:
        print("In delete POST")

    return render_template('index.html')

"""-----------------------------LOADING DELETE PHOTO----------------------------------"""
@app.route('/album/<string:albumID>/photo/<string:photoID>/delete', methods=['GET'])
def delete_photo(photoID, albumID):

    try:
        conn=get_database_connection()
        cursor = conn.cursor ()
        print("Hello")
        statement = f'''DELETE FROM photogallerydb.Photo WHERE photoID="{photoID}";'''
        cursor.execute(statement)
        results = cursor.fetchall()
        conn.commit()
        conn.close()

        return redirect('/index')

    except Exception as e:
        print("Could not delete photo.") 
    
    return render_template('viewphotos.html') #, photos=items, albumID=albumID, albumName=albumMeta[0]['name'])


@app.errorhandler(400)
def bad_request(error):
    """ 400 page route.

    get:
        description: Endpoint to return a bad request 400 page.
        responses: Returns 400 object.
    """
    return make_response(jsonify({'error': 'Bad request'}), 400)



@app.errorhandler(404)
def not_found(error):
    """ 404 page route.

    get:
        description: Endpoint to return a not found 404 page.
        responses: Returns 404 object.
    """
    return make_response(jsonify({'error': 'Not found'}), 404)



@app.route('/index', methods=['GET'])
def home_page():
    """ Home page route.

    get:
        description: Endpoint to return home page.
        responses: Returns all the albums.
    """
    conn=get_database_connection()
    cursor = conn.cursor ()
    cursor.execute("SELECT * FROM photogallerydb.Album;")
    results = cursor.fetchall()
    conn.close()
    
    items=[]
    for item in results:
        album={}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']

        createdAt = datetime.strptime(str(item['createdAt']), "%Y-%m-%d %H:%M:%S")
        createdAt_UTC = timezone("UTC").localize(createdAt)
        album['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")

        items.append(album)

    return render_template('index.html', albums=items)



@app.route('/createAlbum', methods=['GET', 'POST'])
def add_album():
    """ Create new album route.

    get:
        description: Endpoint to return form to create a new album.
        responses: Returns all the fields needed to store new album.

    post:
        description: Endpoint to send new album.
        responses: Returns user to home page.
    """
    if request.method == 'POST':
        this_ID = session.get('userID')  # Retrieve userID from session
        print("albumUserID: ", this_ID)
        if this_ID is None:
            print("Could not find UserID")
            return redirect('/login') 

        uploadedFileURL=''
        file = request.files['imagefile']
        name = request.form['name']
        description = request.form['description']

        if file and allowed_file(file.filename):
            albumID = uuid.uuid4()
            
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)
            
            uploadedFileURL = s3uploading(str(albumID), filenameWithPath, "thumbnails");

            createdAtlocalTime = datetime.now().astimezone()
            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)

            conn=get_database_connection()
            cursor = conn.cursor ()
            statement = f'''INSERT INTO photogallerydb.Album (albumID, name, description, thumbnailURL, createdAt, createdBy) VALUES ("{albumID}", "{name}", "{description}", "{uploadedFileURL}", "{createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S")}", "{this_ID}");'''
            
            result = cursor.execute(statement)
            conn.commit()
            conn.close()

        return redirect('/index')
    else:
        return render_template('albumForm.html')



@app.route('/album/<string:albumID>', methods=['GET'])
def view_photos(albumID):
    """ Album page route.

    get:
        description: Endpoint to return an album.
        responses: Returns all the photos of a particular album.
    """
    conn=get_database_connection()
    cursor = conn.cursor ()
    # Get title
    statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    albumMeta = cursor.fetchall()
    
    # Photos
    statement = f'''SELECT photoID, albumID, title, description, photoURL FROM photogallerydb.Photo WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    results = cursor.fetchall()
    conn.close() 
    
    items=[]
    for item in results:
        photos={}
        photos['photoID'] = item['photoID']
        photos['albumID'] = item['albumID']
        photos['title'] = item['title']
        photos['description'] = item['description']
        photos['photoURL'] = item['photoURL']
        items.append(photos)

    return render_template('viewphotos.html', photos=items, albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
def add_photo(albumID):
    """ Create new photo under album route.

    get:
        description: Endpoint to return form to create a new photo.
        responses: Returns all the fields needed to store a new photo.

    post:
        description: Endpoint to send new photo.
        responses: Returns user to album page.
    """
    if request.method == 'POST':    
        uploadedFileURL=''
        file = request.files['imagefile']
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']

        if file and allowed_file(file.filename):
            photoID = uuid.uuid4()
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)            
            
            uploadedFileURL = s3uploading(filename, filenameWithPath);
            
            ExifData=getExifData(filenameWithPath)

            conn=get_database_connection()
            cursor = conn.cursor ()
            ExifDataStr = json.dumps(ExifData)
            statement = f'''INSERT INTO photogallerydb.Photo (PhotoID, albumID, title, description, tags, photoURL, EXIF) VALUES ("{photoID}", "{albumID}", "{title}", "{description}", "{tags}", "{uploadedFileURL}", %s);'''
            
            result = cursor.execute(statement, (ExifDataStr,))
            conn.commit()
            conn.close()

        return redirect(f'''/album/{albumID}''')
    else:
        conn=get_database_connection()
        cursor = conn.cursor ()
        # Get title
        statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
        cursor.execute(statement)
        albumMeta = cursor.fetchall()
        conn.close()

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
def view_photo(albumID, photoID):  
    """ photo page route.

    get:
        description: Endpoint to return a photo.
        responses: Returns a photo from a particular album.
    """ 
    conn=get_database_connection()
    cursor = conn.cursor ()

    # Get title
    statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    albumMeta = cursor.fetchall()

    statement = f'''SELECT * FROM photogallerydb.Photo WHERE albumID="{albumID}" and photoID="{photoID}";'''
    cursor.execute(statement)
    results = cursor.fetchall()
    conn.close()

    if len(results) > 0:
        photo={}
        photo['photoID'] = results[0]['photoID']
        photo['title'] = results[0]['title']
        photo['description'] = results[0]['description']
        photo['tags'] = results[0]['tags']
        photo['photoURL'] = results[0]['photoURL']
        photo['EXIF']=json.loads(results[0]['EXIF'])

        createdAt = datetime.strptime(str(results[0]['createdAt']), "%Y-%m-%d %H:%M:%S")
        updatedAt = datetime.strptime(str(results[0]['updatedAt']), "%Y-%m-%d %H:%M:%S")

        createdAt_UTC = timezone("UTC").localize(createdAt)
        updatedAt_UTC = timezone("UTC").localize(updatedAt)

        photo['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")
        photo['updatedAt']=updatedAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")
        
        tags=photo['tags'].split(',')
        exifdata=photo['EXIF']
        
        return render_template('photodetail.html', photo=photo, tags=tags, exifdata=exifdata, albumID=albumID, albumName=albumMeta[0]['name'])
    else:
        return render_template('photodetail.html', photo={}, tags=[], exifdata={}, albumID=albumID, albumName="")



@app.route('/album/search', methods=['GET'])
def search_album_page():
    """ search album page route.

    get:
        description: Endpoint to return all the matching albums.
        responses: Returns all the albums based on a particular query.
    """ 
    query = request.args.get('query', None)

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Album WHERE name LIKE '%{query}%' UNION SELECT * FROM photogallerydb.Album WHERE description LIKE '%{query}%';'''
    cursor.execute(statement)

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        album={}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']
        items.append(album)

    return render_template('searchAlbum.html', albums=items, searchquery=query)



@app.route('/album/<string:albumID>/search', methods=['GET'])
def search_photo_page(albumID):
    """ search photo page route.

    get:
        description: Endpoint to return all the matching photos.
        responses: Returns all the photos from an album based on a particular query.
    """ 
    query = request.args.get('query', None)

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Photo WHERE title LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE description LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE tags LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE EXIF LIKE '%{query}%' AND albumID="{albumID}";'''
    cursor.execute(statement)

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        photo={}
        photo['photoID'] = item['photoID']
        photo['albumID'] = item['albumID']
        photo['title'] = item['title']
        photo['description'] = item['description']
        photo['photoURL'] = item['photoURL']
        items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=query, albumID=albumID)



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
