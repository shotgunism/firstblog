
import os
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
environment = jinja2.Environment(autoescape=True, loader = jinja2.FileSystemLoader(template_dir)) 

class BlogEntry(db.Model):
        db_subject = db.StringProperty(required = True)       		
        db_content = db.TextProperty(required = True)
        db_created = db.DateTimeProperty(auto_now_add = True)

class Render(webapp2.RequestHandler):
        def write(self, *a, **kw):
            self.response.out.write(*a, **kw)

        def render_string(self, template, **params):
                template = environment.get_template(template)
                return template.render(**params)

        def render(self, template, **kw):
                self.write(self.render_string(template, **kw))
		
class MainHandler(Render, BlogEntry):
                

        blogentry = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY db_created DESC")



        def get(self):
                
		
class NewPostHandler(Render):
        def get(self):
                self.render('newpost.html', subject="", content="", error = "")

        def post(self):
                subject = self.request.get("subject")
                content = self.request.get("content")
                if subject and content:
                        p=BlogEntry(db_subject=subject,db_content=content)
                        p.put()
                        identity=p.key().id() #create an identity string variable in order to fetch back 
                        self.response.out.write("Thanks")
                else:
                        err = "Please enter both a blog post subject as well as you content!"
                        self.render('newpost.html',  error=err)
                

app = webapp2.WSGIApplication([('/', MainHandler), ('/newpost', NewPostHandler)], debug=True)
