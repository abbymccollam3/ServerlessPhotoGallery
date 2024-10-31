#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, DYNAMODB_TABLE
from flask import Flask, jsonify, abort, request, make_response, url_for, session
from flask import render_template, redirect
import time
import exifread
import json
import uuid
import boto3  
from boto3.dynamodb.conditions import Key, Attr
import pymysql.cursors
from datetime import datetime
import pytz

"""
    INSERT NEW LIBRARIES HERE (IF NEEDED)
"""

from itsdangerous import URLSafeTimedSerializer
import bcrypt
from botocore.exceptions import ClientError

"""
"""

# GLOBAL VARIABLES ------------------------------------------------------------
serializer = URLSafeTimedSerializer("hey") #maybe userID

# GENERATE PASSWORD HASH
# userID = uuid.uuid4() #generate uuid
userID = uuid.uuid4() #generate uuid
encoded_userID = str(userID)
salt = bcrypt.gensalt() # Generating Salt

SENDER = "amccollam3@gatech.edu"

# ----------------------------------------------------------------------------

app = Flask(__name__, static_url_path="")
app.secret_key = AWS_SECRET_ACCESS_KEY

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                            region_name=AWS_REGION)

table = dynamodb.Table(DYNAMODB_TABLE)
user_table = dynamodb.Table("PhotoGalleryUser")

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

# Create a new SES resource and specify a region.
ses = boto3.client("ses",
    region_name = AWS_REGION,
    aws_access_key_id = AWS_ACCESS_KEY, #should this have _ID
    aws_secret_access_key = AWS_SECRET_ACCESS_KEY)

"""
   ------------------------------- INSERT YOUR NEW FUNCTION HERE ----------------------------------"""

def try_email(email, token):

    RECEIVER = email

    #Try to send the email
    try:
        # Provide the contents of the email.
        response = ses.send_email(
            Destination={
                'ToAddresses': [RECEIVER],
            },
            Message={
                'Body': {
                    'Text': {
                        'Data': f'This is an email from AWS SES. Click this link to confirm your email: http://3.88.68.128:5000/confirm/{token}/{encoded_userID}' 
                    },
                },
                'Subject': {
                    'Data': 'Hi, I’m sending this email from AWS SES'
                },
            },
            Source=SENDER
        )

    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])

def get_userID (this_email):
    response = user_table.scan(
        FilterExpression=Attr('email').eq(this_email)
    )
    
    items = response['Items']
    
    if items:
        return items[0]['userID'] 
    else:
        return 0

def now_delete_albums(albumID):

    response = table.query(
            KeyConditionExpression=Key('albumID').eq(albumID)
    )

    # Extract photoIDs from the response
    photos = response['Items']
    photoIDs = [photo['photoID'] for photo in photos]

    # Delete each photo one by one
    for photoID in photoIDs:
        table.delete_item(
            Key={
                'albumID': albumID,
                'photoID': photoID
            }
        )

    return redirect('/index')

"""-----------------------------LOADING DEFAULT SIGN UP PAGE----------------------------------"""
@app.route('/')
def anything():
    return redirect ('/signup')

"""-----------------------------LOADING DELETE ACCOUNT----------------------------------"""
@app.route('/delete', methods=['GET', 'POST'])
def delete_account():

    if request.method == 'POST':

        delete_email = request.form['email'] 
        delete_userID = get_userID(delete_email)

        print(delete_userID)

        response = table.scan(FilterExpression=Attr('createdBy').eq(delete_userID))
        delete_albums = response['Items']

        if len(delete_albums) > 0:
            for album in delete_albums:
                album_id = album['albumID']
                now_delete_albums(album_id)

        user_table.delete_item(
                Key={"userID": str(delete_userID)})

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
            response = table.query(
                KeyConditionExpression=Key('albumID').eq(albumID)
            )
            
            # Extract photoIDs from the response
            photos = response['Items']
            photoIDs = [photo['photoID'] for photo in photos]
            print(photoIDs)
            
            # Delete each photo one by one
            for photoID in photoIDs:
                print("PhotoID: ", photoID)
                table.delete_item(
                    Key={
                        'albumID': albumID,
                        'photoID': photoID
                    }
                )

            return redirect('/index')

        except Exception as e:
            print("Could not delete album") 

    else:
        print("In delete album POST")
    
    
    return render_template('index.html')



"""-----------------------------LOADING DELETE PHOTO----------------------------------"""
@app.route('/album/<string:albumID>/photo/<string:photoID>/delete', methods=['GET'])
def delete_photo(albumID, photoID):

    try:
        table.delete_item(
                Key={ 
                    'albumID': albumID,
                    'photoID': photoID
                    }
                )

        return redirect('/index')

    except Exception as e:
        print("Could not delete photo") 
    
    
    return render_template('viewphotos.html')

"""-----------------------------LOADING LOGIN PAGE----------------------------------"""
@app.route('/login', methods=['POST', 'GET'])
def login_page():

    # insert description here

    if request.method == 'POST': 

        entered = request.form['email'] #email user has entered
        this_ID = get_userID(entered) # returns user ID for email entered
        session['userID'] = this_ID

        print(this_ID)

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
            bad_request(400) #need 400 error here
            return 'User Not Found'
            print("Error.") 

    else:
        print("Not a post method.")
        # maybe get email and password in here

    return render_template('login.html')

"""-----------------------------LOADING SIGNUP PAGE----------------------------------"""
@app.route('/signup', methods=['GET', 'POST']) 
def signup_page():

    #input function description here

    if request.method == 'POST': #when Sign Up button is clicked
        global first_name, last_name, hash_password, email

        first_name = request.form['first_name'] 
        last_name = request.form['last_name']
        password = request.form['password']
        email = request.form['email']

        response = user_table.scan(FilterExpression=Attr('email').eq(email))
        results = response['Items']

        # Hashing Password
        hash_password = bcrypt.hashpw(
            password=password.encode("utf-8"),
            salt=salt
        )

        if len(results) <= 0: #if email is not currently in table
            global createdAtlocalTime, createdAtUTCTime

            # Generating timestamp
            createdAtlocalTime = datetime.now().astimezone()
            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)

            token = serializer.dumps(email, salt="A2B3") #what belongs here
            try_email(email, token) # sending email

            return redirect('/login')

        else:
            print("Email already in use.")
            return redirect('/signup')

    else:
        return render_template('signup.html')

"""-----------------------------LOADING TOKEN PAGE----------------------------------"""
@app.route('/confirm/<token>/<encoded_userID>', methods=['GET']) 
def confirm_page(token, encoded_userID):

     # check if token is expired - DOES THIS NEED TO BE MOVED
    try:
        decoded_email = serializer.loads(
            token, 
            salt="A2B3", 
            max_age=600 #expires after 10 minutes
        )

        print(decoded_email)

        user_table.put_item(
            Item={
                "userID": str(userID),
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "password": hash_password, #may not be the right way to store password
                "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S")
            }
        )

    except Exception as e:
        print("expired token") 
        return 'URL expired'

    # query user from database with decoded UserID
    query_user = user_table.query(KeyConditionExpression=Key('userID').eq(encoded_userID))
    items = query_user['Items']

    if len(items) > 0:
        print("Entering this loop")
        return redirect('/login')

    else:
        print ("User not verified.")


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
    response = table.scan(FilterExpression=Attr('photoID').eq("thumbnail"))
    results = response['Items']

    if len(results) > 0:
        for index, value in enumerate(results):
            createdAt = datetime.strptime(str(results[index]['createdAt']), "%Y-%m-%d %H:%M:%S")
            createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
            results[index]['createdAt'] = createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")

    return render_template('index.html', albums=results)



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
        print("userID: ", this_ID)
        if this_ID is None:
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

            table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": "thumbnail",
                    "name": name,
                    "description": description,
                    "thumbnailURL": uploadedFileURL,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "createdBy": this_ID
                }
            )

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
    albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = table.scan(FilterExpression=Attr('albumID').eq(albumID) & Attr('photoID').ne('thumbnail'))
    items = response['Items']

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
            ExifDataStr = json.dumps(ExifData)

            createdAtlocalTime = datetime.now().astimezone()
            updatedAtlocalTime = datetime.now().astimezone()

            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)
            updatedAtUTCTime = updatedAtlocalTime.astimezone(pytz.utc)

            table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": str(photoID),
                    "title": title,
                    "description": description,
                    "tags": tags,
                    "photoURL": uploadedFileURL,
                    "EXIF": ExifDataStr,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "updatedAt": updatedAtUTCTime.strftime("%Y-%m-%d %H:%M:%S")
                }
            )

        return redirect(f'''/album/{albumID}''')

    else:

        albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
        albumMeta = albumResponse['Items']

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
def view_photo(albumID, photoID):
    """ photo page route.

    get:
        description: Endpoint to return a photo.
        responses: Returns a photo from a particular album.
    """ 
    albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = table.query( KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq(photoID))
    results = response['Items']

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

        createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
        updatedAt_UTC = pytz.timezone("UTC").localize(updatedAt)

        photo['createdAt']=createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")
        photo['updatedAt']=updatedAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")
        
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

    response = table.scan(FilterExpression=Attr('name').contains(query) | Attr('description').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] == 'thumbnail':
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

    response = table.scan(FilterExpression=Attr('title').contains(query) | Attr('description').contains(query) | Attr('tags').contains(query) | Attr('EXIF').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] != 'thumbnail' and item['albumID'] == albumID:
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
