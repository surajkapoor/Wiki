from google.appengine.ext import db

import webapp2
import jinja2
import os
import logging
import re
import random
import hashlib
import hmac
import string

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

PAGE_RE = r'(/?(?:[a-zA-Z0-9_-]+/?)*)'

CONTENT = {}

def escape_html(c):
    return cgi.escape(c, quote = True)
    
def id_to_url(object_id):
    content = WikiEntry.get_by_id(int(object_id))
    url = content.url
    return url     

def name_check(name):
    name_check = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')  
    if name_check.match(name):
        return True
        
def pw_check(pw):
    pw_check = re.compile(r"^.{3,20}$")
    if pw_check.match(pw):
        return True       
        
def valid_email(email):
    valid_email = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    if valid_email.match(email) or email=="":
        return True
        
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h,salt)
    
def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)  
    
SECRET = "jello"

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s,hash_str(s))
    
def check_secure_val(s):
    key = s.split('|')[0]
    return s == make_secure_val(key)
    
def user_key(s):
    key = s.split('|')[0]
    return key  
    
def updates():
    query = db.GqlQuery("SELECT * FROM WikiEntry ORDER BY created DESC limit 10")
    latest_entries = query
    return latest_entries    

class WikiEntry(db.Model):
    
    content = db.TextProperty(required = False)
    url = db.StringProperty(required = True)
    pic = db.BlobProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)
    time = db.TimeProperty(auto_now_add = True)
    
class UserInfo(db.Model):
    
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)    
    
class EditPage(webapp2.RequestHandler):
    
    def render_edit(self, content = '', pic = ''):
        template_values = {'content':content, 'pic':pic}
        
        template = jinja_environment.get_template('edit.html')
        self.response.out.write(template.render(template_values))    

    def get(self, url):
        user_id = self.request.cookies.get('user_id')
        if check_secure_val(str(user_id)):
            key = url
            if key in CONTENT:
                content = CONTENT[key]
            else:
                logging.error('query run')
                query = db.GqlQuery('SELECT * FROM WikiEntry WHERE url = :1 ORDER BY created DESC LIMIT 1', url).get()
                if query:
                    content = query.content    
                else:
                    content = ''   
                self.render_edit(content = content)
        else:
            self.redirect(url)                
             
    def post(self, url):
        #db entry
        content = self.request.get('content')
        pic = self.request.get('pic')
        entry = WikiEntry(content = content, url = url, pic = str(pic))
        entry.put()
        #cache entry
        key = url
        CONTENT[key] = content
        #re-direct
        self.redirect(url)
        
class EditOldEntries(EditPage):
    
    def render_edit(self, content = ''):
        template_values = {'content':content}
        
        template = jinja_environment.get_template('edit.html')
        self.response.out.write(template.render(template_values))
        
    def get(self, object_id):
        content = WikiEntry.get_by_id(int(object_id))
        content = content.content 
        self.render_edit(content = content) 
        
    def post(self, object_id):
        content = self.request.get('content')
        url = id_to_url(object_id)
        entry = WikiEntry(content = content, url = url)
        entry.put()
        #cache entry
        key = url
        CONTENT[key] = content
        self.redirect(url)
        
class HistoryPage(webapp2.RequestHandler):
    
    def render_history(self, entries = '', back_link = ''):
        template_values = {'entries':entries, 'back_link': back_link}
        
        template = jinja_environment.get_template('history.html')
        self.response.out.write(template.render(template_values))
        
    def get(self, url):
        entries = db.GqlQuery('SELECT * FROM WikiEntry WHERE url = :1 ORDER BY created DESC', url)
        back_link = url
        self.render_history(entries = entries, back_link = back_link)

class ViewEntry(HistoryPage): 
    
    def render_wiki(self, content = ''):
        template_values = {'content':content}
        
        template = jinja_environment.get_template('wiki.html')
        self.response.out.write(template.render(template_values))
    
    def get(self, url):
        content = WikiEntry.get_by_id(int(url))
        content = content.content
        self.render_wiki(content = content)    
              
class WikiPage(webapp2.RequestHandler):

    def render_wiki(self, content = '', edit_link = '', history_link = '', wiki_name = '', latest_updates = ''):
        template_values = {'content':content, 'edit_link':edit_link, 'history_link':history_link, 'wiki_name':wiki_name, 'latest_updates':latest_updates}
        
        template = jinja_environment.get_template('wiki.html')
        self.response.out.write(template.render(template_values))

    def get(self, url):    
        
        key = url
        edit_link = '_edit' + url
        history_link = '_history' + url 
        wiki_name = url[1:]
        if wiki_name == '':
            wiki_name = 'HomePage'
            
        if url == '/':
            latest_updates = updates()
        else: 
            latest_updates = ''        
        
        if key in CONTENT:
            content = CONTENT[key]
            self.render_wiki(content = content, edit_link = edit_link, history_link = history_link, wiki_name = wiki_name, latest_updates = latest_updates)
        else:    
            logging.debug("wiki-error")
            query = db.GqlQuery('SELECT * FROM WikiEntry WHERE url = :1 ORDER BY created DESC LIMIT 1', url).get()
            if query:
                content = query.content
                CONTENT[key] = content
                self.render_wiki(content = content, edit_link = edit_link, history_link = history_link, wiki_name = wiki_name, latest_updates = latest_updates)
            else:
                self.redirect('_edit' + url)
                
class SignupPage(webapp2.RequestHandler):

    def render_main(self, name_error='', ent_name='', pw_error='', ver_error='', email='', email_error=''):
        template_values = {'name_error':name_error,
                           'ent_name':ent_name,
                           'pw_error':pw_error,
                           'ver_error':ver_error,
                           'email':email,
                           'email_error':email_error} 
    
        template = jinja_environment.get_template('signup.html')
        self.response.out.write(template.render(template_values))          
                                    
    def get(self): 
        self.render_main()
            
    def post(self, name_error='', ent_name='', pw_error='',ver_error='', email='', email_error=''):
         
        error = False

        #username check
        name_in = self.request.get('username')
        name = name_check(name_in)
        
        #password check#
        pw_in = self.request.get('password')
        password = pw_check(pw_in)
        
        #password verification
        verify = self.request.get('verify')
        
        #email verification
        email_in = self.request.get('email')
        email = valid_email(email_in)

        if not email:
            error = True
            ent_name = name_in
            email = email_in
            email_error = "email invalid"
        
        if not name:
            error = True
            name_error = "username invalid"
            ent_name = name_in
            email = email_in
            
        if not password:
            error = True
            ent_name = name_in
            email = email_in
            pw_error = "password invalid"
            
        if verify != pw_in:
            error = True
            ent_name = name_in
            email = email_in
            ver_error = "password didn't match"
            
        if error:
            self.render_main(name_error, ent_name, pw_error, ver_error, email, email_error)
        
        else:
            db_names = db.GqlQuery('SELECT * FROM UserInfo WHERE name=:1', name_in)
            namecheck = db_names.get()
            if namecheck:
                name_error = 'username already exists'
                self.render_main(name_error)
            else: 
                crypted_pw = make_pw_hash(name_in, pw_in)
                entry = UserInfo(name = name_in, password = crypted_pw, email = email_in)           
                entry.put()
                user_id = entry.key().id()
                hashed_cookie = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' %(hashed_cookie))
                self.redirect('/') 
                
class LoginPage(webapp2.RequestHandler):                       
        
        def render_main(self, login_name='', username_error = '', login_pw_error = ''):
            template_values = {'login_name':login_name, 'username_error':username_error, 'login_pw_error':login_pw_error}
    
            template = jinja_environment.get_template('login.html')
            self.response.out.write(template.render(template_values))    
            
        def get(self):
            self.render_main()
            
        def post(self, login_name='', username_error = '', login_pw_error = ''):
            name_in = self.request.get('username')
            pw_in = self.request.get('password')
            
            user_info = db.GqlQuery('SELECT * FROM UserInfo WHERE name=:1', name_in)
            user = user_info.get()
            error = False
            
            if not user:
                username_error = "invalid username"
                login_name = name_in
                error = True 
            
            if user and not valid_pw(name_in, pw_in, h = user.password):
                login_pw_error = "invalid password"
                login_name = name_in
                error = True         
              
            if error:
                 self.render_main(login_name, username_error, login_pw_error)
                  
            else:
                user_id = user.key().id()
                hashed_cookie = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' %(hashed_cookie))        
                self.redirect('/')
                
class LogOut(webapp2.RequestHandler):                                                                        
            
            def get(self):
                self.response.headers.add_header('Set-Cookie', 'user_id=''; Path=/')
                self.redirect("/")    
                                              
app = webapp2.WSGIApplication([('/logout', LogOut),
                               ('/login', LoginPage),
                               ('/signup', SignupPage),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_past_edit/(\d+)', EditOldEntries),
                               ('/_history' + PAGE_RE, HistoryPage),
                               ('/_view/(\d+)', ViewEntry),
                               (PAGE_RE, WikiPage)], 
                               debug=True)                                

