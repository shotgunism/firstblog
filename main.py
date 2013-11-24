#FIRST BLOG MAIN.PY

import webapp2
import os
import jinja2

import hashlib
import random
import string
import re
import sys

import time
import logging

import urllib2
from xml.dom import minidom
import json

from google.appengine.ext import db
from google.appengine.api import memcache


IP_URL = "http://api.hostip.info/?ip="
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_environment = jinja2.Environment(autoescape=True, loader = jinja2.FileSystemLoader(template_dir))

def get_coords(ip):
    #ip = "4.2.2.2"
    url = IP_URL + ip
    content = None
    try:
        content  = urllib2.urlopen(url).read()
    except URLError:
        return
    
    if content:
        #parse xml and find coordinates
        d = minidom.parseString(content)
        coords = d.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon = coords[0].childNodes[0].nodeValue.split(',')[0]
            lat = coords[0].childNodes[0].nodeValue.split(',')[1]
            return db.GeoPt(lat, lon)
        
		
def gmaps_img(points):
    gmaps_img = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
    markers = '&'.join('markers=%s,%s' %(points.lat, points.lon))
    return gmaps_img + markers

def gmaps_img(points):
    map_url = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&markers=%s,%s" %(points.lat, points.lon)
    return map_url

def make_json(py_list):
        return json.dumps(py_list)
    
    
def top_posts(update = False):
    key = "top" #just a cache id
    entries = memcache.get(key) #retrieves the entries from the cache
    timestamp = 0
    if entries is None or update: #if there is no cache or a new entry has been added and the bool is true
        entries = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC limit 20") #database is hit
        logging.error("DB HIT LOGGED!") #hit is logged
        entries = list(entries) #bit of formatting
        memcache.set(key, entries) #the cache is updated
        #consider using CAS here
        timestamp = time.time()
    return entries, timestamp  #return as tuple?  
    
    
        
#MAIN RENDERING CLASS, inherited by most things
class RenderBlog(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        j_template = jinja_environment.get_template(template)
        return j_template.render(**params)                                                #returns a rendered html with the template values added in

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


INIT_TIME = time.time()
class MainHandler(RenderBlog):
    def render_frontpage(self):
        counter = time.time() - INIT_TIME
        entries, timestamp = top_posts()
        counter = counter - timestamp
        self.render("frontpage.html", entries=entries, counter=int(counter))                                  #assigns the data in the entries to the template render. would this have worked with applying each individual variable - entries.subject, entries.content, entries.created? 
        
    def get(self):
        self.render_frontpage()
        
class MainHandler_Json(RenderBlog):
    
    def render_frontpage_json(self):
        #load up the database entries
        entries = top_posts()
        #load entries into a dict
        main_page = []
        for entry in entries:
            new_entry = {}
            new_entry["subject"] = str(entry.subject)
            new_entry["content"] = str(entry.content)
            new_entry["created"] = str(entry.created.strftime("%d, %b, %Y"))
            #new_entry['coordinates'] = entry.coordinates
            main_page.append(new_entry)
        self.write(make_json(main_page))
        
    
    def get(self):
        self.response.headers['Content-Type'] = 'application/json; charset-UTF-8'
        self.render_frontpage_json()
        

#BLOG ENTRY CLASS
class BlogEntry(db.Model):
    subject=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    coordinates = db.GeoPtProperty()
    gmap_url = db.StringProperty()

class NewPostHandler(RenderBlog, BlogEntry):
    def get(self):
        self.write(self.request.remote_addr)
        self.render("newpost.html", subject = "", content = "", error = "")
    def post(self):
        subject=self.request.get("subject")
        content=self.request.get("content")
        if (subject and content):
            post=BlogEntry(subject=subject, content=content)
            
            #lookup user coordinates from their ip
            coords = get_coords(self.request.remote_addr)
            # put them in the blog post
            if coords:
                post.coordinates = coords
                post.gmap_url = gmaps_img(coords)
            
            post.put()
            top_posts(True)
            post_id=str(post.key().id()) #the id of the post come from the key of the db.
            perma_cache(int(post_id))
            self.redirect("/blog/%s" %post_id)
        else:
            error = "Please give us a subject and content for you post."
            self.render("newpost.html", subject=subject, content=content, error=error)




def perma_cache(post_id):
    if post_id:
        entry = BlogEntry.get_by_id(post_id) #hits the db
        logging.error("DB HIT LOGGED!") #hit is logged
        memcache.set(str(post_id), entry)
    
class PermaLinkHandler(RenderBlog):
    def get(self, post_id):                                     #adds the extra post_id argument
        p =  memcache.get(str(post_id))# searches the BlogENtry db object for the id passed into the get reqest
        counter = time.time() - INIT_TIME
        entries, timestamp = top_posts()
        counter = counter - timestamp
        counter = int(counter)
        self.render("permalink.html", entries=p, counter = counter)
        
class PermaLinkHandler_Json(PermaLinkHandler):
    def get(self, post_id):
        self.response.headers['Content-Type'] = 'application/json; charset-UTF-8'
        p = BlogEntry.get_by_id(int(post_id))
       
        entry = {}
        entry["subject"] = str(p.subject)
        entry["content"] = str(p.content)
        entry["created"] = str(p.created.strftime("%d, %b, %Y")) 
        
        self.write(make_json(entry))
        
class ThanksHandler(RenderBlog):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        user_id = self.request.cookies.get("user_id", None)
        if user_id:
            username = user_id.split("|")[0]
            self.response.headers['Content-Type'] = 'html'
            self.render("thanks.html", username = username)

#__________________________________________________________Registration class and functions_____________________________________________

#USER REGISTRATION  
class RegisteredUser(db.Model):
    #User db model class - this will have all the necessary vars for the user to be stored in the database
    username = db.StringProperty(required=True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    register_time = db.DateTimeProperty(auto_now_add = True)

#SALT CHCKING SECURITY CLASS - creaes a db.Model that always stores the latest salt value of the user password.
class SaltCheck(db.Model):
    user = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)


#_____1. REGEX CHECKERS

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")

def valid_username(name):
  return USER_RE.match(name)

def valid_password(password):
  return PASS_RE.match(password)

def valid_email(email):
  if email == "":
    return True
  else:
    return EMAIL_RE.match(email)


def make_pw_hash(name, password):
    h = hashlib.sha256(name + password).hexdigest()
    return "%s|%s" %(name, h)
    


class LoginHandler(RenderBlog, RegisteredUser):
    def get(self):
        self.render("login.html", username = "", password = "")
    
    def post(self):
        username_error = ""
        password_error = ""
        
        username = self.request.get("username")
        password = self.request.get("password") 
        user_db_check = db.GqlQuery("SELECT * FROM RegisteredUser WHERE username = '%s'" % username)
       
       #need to re-write this part!
       
        if user_db_check == None:
            username_error = "Not a valid user account!"
            self.render("login.html", username = "", username_error = username_error, password = "")
        else:
            user_password_hash = make_pw_hash(username, password)
            for entry in user_db_check:
                if user_password_hash == entry.password:
                    self.response.headers['Content-Type'] = 'text/plain'
                    self.response.headers.add_header("Set-Cookie","user_id=%s;Path=/" % str(user_password_hash))
                    self.redirect('/blog/thanks')
                else:
                    password_error = "Invalid password!"
                    self.render("login.html", username = username, username_error = username_error, password = "", password_error = password_error)
            
class LogoutHandler(RenderBlog):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        user_id = self.request.cookies.get("user_id", None)
        if user_id:
            self.response.headers.add_header('Set-Cookie','user_id=%s;Path=/' %"")
            self.redirect('/blog/signup')
        else:
            self.response.out.write("No user is logged in!")
    



class RegistrationHandler(RenderBlog, RegisteredUser):
    def get(self): 
        self.response.headers['Contenty-type']='text/plain'
        self.render("registration.html",
                    username = "",
                    username_error = "",
                    password = "",
                    password_error = "",
                    verify = "",
                    verify_error = "",
                    email = "",
                    email_error = "")
        
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        
        validity = True
            
        if not valid_username(username):
            username_error = "Please enter a valid user name!"
            validity = False
        
        user_db_check = db.GqlQuery("SELECT * FROM RegisteredUser")
        for entry in user_db_check:
            if entry.username == username:
                validity = False
                username_error = "User name already exists!"
            
        if not valid_password(password):
            password_error = "Please enter a valid password!"
            validity = False   
        
        if verify != password:
            verify_error = "Password verification failed."
            validity = False
            
        if email and not valid_email(email):
            email_error = "Please enter a valid email address!"
            validity = False
        
        if not validity:
            self.render("registration.html", username = username,
                                            username_error = username_error,
                                            password_error = password_error,
                                            verify_error = verify_error,
                                            email = email,
                                            email_error = email_error)    
        else:
            #make hash
            user_password_hash = str(make_pw_hash(username, password))
            
            #set cookie
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header("Set-Cookie","user_id=%s;Path=/" % user_password_hash)
            
            #add to db
            user = RegisteredUser(username = username, password = user_password_hash, email = email)
            user.put()
            self.response.out.write("welcome !"+ username)
            
            self.redirect('/blog/thanks')
            
            
class FlushHandler(webapp2.RequestHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')
    
         
app = webapp2.WSGIApplication([('/blog', MainHandler),
                                ('/blog/.json', MainHandler_Json),
                                ('/blog/newpost', NewPostHandler),
                                ('/blog/thanks', ThanksHandler),
                                ('/blog/([0-9]+)', PermaLinkHandler),
                                ('/blog/([0-9]+).json', PermaLinkHandler_Json),
                                ('/blog/signup', RegistrationHandler),
                                ('/blog/login', LoginHandler),
                                ('/blog/logout', LogoutHandler),
                                ('/blog/flush', FlushHandler)], debug=True)


