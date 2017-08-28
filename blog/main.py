#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re
import time
import os
import webapp2
import  jinja2
import json
import hashlib
import hmac
import random
from string import letters
from datetime import datetime,timedelta
from google.appengine.api import memcache
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET ="ad890whi1m34si^.!34@#$%%"



def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#COOKIE HASHING
def make_secure_val(val):
    return "%s|%s"%(val,hmac.new(SECRET,val).hexdigest())

def check_secure_val(h):
    val=h.split("|")[0]
    if h==make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template,**kw))

### COOKIE SET and CHECK
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


    def initialize(self, *a,**kw):
        webapp2.RequestHandler.initialize(self,*a,**kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith(".json"):
            self.format='json'
        else:
            self.format='html'

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)


### PASSWORD HASHING
def make_salt(length=5):
    return ''.join(random.choice(letters)for x in xrange(length))

def make_pw_hash(name,pw,salt=None):
    if not salt:
        salt=make_salt()
    h=hashlib.sha256(name+pw+salt).hexdigest()
    return '%s,%s' %(salt,h)

def valid_pw(name,password,h):
    salt=h.split(',')[0]
    return  h == make_pw_hash(name,password,salt)

## USER DATABASE
# class User(db.Model):
#     name=db.StringProperty(required=True)
#     pw_hash=db.StringProperty(required=True)
#     email=db.StringProperty(required=True)
#
#     @classmethod
#     def by_id(cls,uid):
#         return User.get_by_id(uid)
#
#     @classmethod
#     def by_name(cls,name):
#         u=User.all().filter('name=',name).get()
#         return u
#
#     @classmethod
#     def register(cls,name,pw,email=None):
#         pw_hash=make_pw_hash(name,pw)
#         return User(name=name,
#                     pw_hash=pw_hash,
#                     email=email)
#
#     @classmethod
#     def login(cls, name, pw):
#         u = cls.by_name(name)
#         if u and valid_pw(name, pw, u.pw_hash):
#             return u

class User(db.Model):
    name=db.StringProperty(required=True)
    pw_hash=db.StringProperty(required=True)
    email=db.StringProperty()

    @classmethod
    def by_id(cls,uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls,name):
        u=User.all().filter('name =',name).get()
        return u

    @classmethod
    def register(cls,name,pw,email=None):
        pw_hash=make_pw_hash(name,pw)
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)
    @classmethod
    def login(cls,name,pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


## FORM REGULAR EXPRESSION
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile("^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE=re.compile("^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)




class signup(Handler):
    def get(self):
        if self.user:
            self.redirect('/blog')
        else:
            self.render("signup.html")
    def post(self):
        have_error=False
        self.username=self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, password=self.password)

        if not valid_username(self.username):
            params['error_username'] = "Enter a valid username"
            have_error = True
        if not valid_password(self.password):
            params['error_password'] = "Enter a valid password"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Password did not match"
            have_error = True
        if not valid_email(self.email):
            params['error_email'] = "Enter a valid email id"
            have_error = True

        if have_error:
            self.render('/signup.html', **params)
        else:
            self.done()

    def done(self,*a,**kw):
        raise NotImplementedError



class Register(signup):
    def done(self):
        u=User.by_name(self.username)
        if u:
            msg='That user already exist.'
            self.render('signup.html',error_username=msg)
        else:
            u=User.register(self.username,self.password,self.email)
            u.put()
            x=str(u.key().id())
            self.login(u)
            self.redirect('/blog/')



class Login(Handler):
    def get(self,):
        if self.user:
            self.redirect('/blog/')
        else:
            self.render('login-form.html',error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username,password)


        if u:
            #x = str(u.key().id())
            self.login(u)
            # self.redirect('/welcome/%s'%x)
            self.redirect('/blog/')

        else:
            msg = 'Invalid login'
            self.render('login-form.html', msg = msg)



class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/')

# def render_post(response, post):
#     response.out.write('<b>' + post.subject + '</b><br>')
#     response.out.write(post.blog)

# def blog_key(name = 'default'):
#     return db.Key.from_path('blogs', name)



class Blog(db.Model):
    #id=db.IntegerProperty(required=True)
    user_id=db.IntegerProperty(required=True)
    subject=db.StringProperty(required=True)
    blog=db.TextProperty(required=True)
    submission_time=db.DateTimeProperty(auto_now_add=True)
    last_modified=db.DateTimeProperty(auto_now=True)
    #likes=db.IntegerProperty()

## TO GET THE USERNAME OF THE PERSON WHO WROTE THE BLOG POST
    def getUserName(self):
        user=User.by_id(self.user_id)
        return user.name

    def getUserId(self):
        user=User.by_id(self.user_id)
        return user.key().id()

    # def render(self):
    #     self._render_text = self.blog.replace('\n','<br>')
    #     return render_str("post.html", p=self)

    def as_dict(self):
        time_fmt='%c'
        d={'subject':self.subject,
           'blog':self.blog,
           'submission_time':self.submission_time.strftime(time_fmt),
           'last_modified':self.last_modified.strftime(time_fmt)}
        return d



class Comment(db.Model):
    user_id=db.IntegerProperty(required=True)
    post_id=db.IntegerProperty(required=True)
    comment=db.TextProperty(required=True)
    submission_time = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user=User.by_id(self.user_id)
        return user.name

    def getUserId(self):
        user = User.by_id(self.user_id)
        return user.key().id()

    @classmethod
    def count_by_blog_id(cls, post_id):
        c = Comment.all().filter('post_id =', post_id)
        return c.count()

class Like(db.Model):
    user_id=db.IntegerProperty(required=True)
    post_id=db.IntegerProperty(required=True)

    def getUserName(self):
        user=User.by_id(self.user_id)
        return user.name



class BlogFront(Handler):

    def get(self):
        posts= db.GqlQuery("SELECT * FROM Blog ORDER BY submission_time desc limit 10")
        if self.format=='html':
            self.render("front.html",posts=posts)
        else:
            #for p in posts:
                 #self.render_json([p.as_dict()])
            return self.render_json([p.as_dict() for p in posts])

class compy(Handler):
    def get(self,post_id,comment_id):

        if self.user:

            c = Comment.get_by_id(int(comment_id))

            if c.user_id == self.user.key().id():

                self.render("editcomment.html",comment=c.comment,post=post_id,comment_id=c)

            else:
                self.redirect("/blog/"+post_id+"?error=You don't have " +
"access to edit this comment!")

        else:
            self.redirect("/login?error=You need to be logged, in order to"+" access it!!")

    def post(self, post_id, comment_id):

        if not self.user:
            self.redirect("/blog/")


        if self.request.get('comment'):


            c=Comment.get_by_id(int(comment_id))

            c.comment=self.request.get('comment')
            c.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % post_id)
        else:
            msg = "Please enter the comment"
            self.render("editcomment.html",msg=msg)

class DelComment(Handler):
    def get(self,post_id,comment_id):
        if self.user:

            c=Comment.get_by_id(int(comment_id))
            if c.user_id == self.user.key().id():
                c.delete()
                time.sleep(0.1)
                self.redirect('/blog/'+post_id)
            else:
                self.redirect("/blog/"+post_id+"?error=You dont have access to delete this comment")
        else:
            self.redirect("/login?error=You need to be logged in order to"+"delete the comment")



class EditPost(Handler):

    def get(self,post_id):
        if self.user:
            post=Blog.get_by_id(int(post_id))
            if post.user_id == self.user.key().id():
                self.render("editpost.html",post=post_id, subject=post.subject,blog=post.blog)
            else:
                self.redirect("/blog/"+post_id+"?error=You don't have " +
"access to edit this record.")
        else:
            self.redirect("/login?error=You need to be logged, " +
"in order to edit your post!!")

    def post(self, post_id):

        if not self.user:
            self.redirect('/blog/')

        subject = self.request.get('subject')
        blog = self.request.get('blog')

        if subject and blog:
            # key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            # post = db.get(key)
            post = Blog.get_by_id(int(post_id))
            post.subject = subject
            post.blog = blog
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=blog, error=error)




class Postpage(Handler):
    def get(self,post_id):
        # key=db.Key.from_path('Blog',int(post_id))
        # post= db.get(key)
        post=Blog.get_by_id(int(post_id))
        comments_count = Comment.count_by_blog_id(post.key().id())
        comments=db.GqlQuery("select *from Comment where post_id="+post_id+"ORDER BY submission_time desc")
        likes=db.GqlQuery("select *from Like where post_id="+post_id)

        if not post:
            return self.error(404)

        error=self.request.get('error')

        if self.format=='html':
            self.render("permalink.html",post=post,error=error,comments=comments,comments_count=comments_count,like=likes.count())
        else:
            self.render_json(post.as_dict())

    def post(self,post_id):

        post=Blog.get_by_id(int(post_id))

        if not post:
            self.error(404)
            return

        c = ""
        if self.user:

            # if self.request.get('like') and self.request.get('like')=="update":
            #     likes =db.GqlQuery("SELECT *from Like where post_id="+post_id+ "and user_id="+str(self.user.key().id()))
            #
            #     if self.user.key().id()==post.user_id:
            #         self.redirect("/blog/"+post_id+"?error=You can't like your own post")
            #         return
            #     elif likes.count()==0:
            #         l=Like(user_id=self.user.key().id(),post_id=int(post_id))
            #         l.put()






            if self.request.get('comment'):
                # comment_text=self.request.get('comment')
                # if comment_text:
                #comment=self.request.get('comment')
                    c=Comment(user_id=self.user.key().id(),post_id=int(post_id),comment=self.request.get('comment'))
                    c.put()
                    time.sleep(0.1)
                    comments_count = Comment.count_by_blog_id(post.key().id())
                    comments = db.GqlQuery(
                    "Select *from Comment where post_id=" + post_id + "ORDER BY submission_time desc")

                    likes = db.GqlQuery("select *from Like where post_id=" + post_id)

                    self.render("permalink.html", post=post, comments=comments,comments_count=comments_count,like=likes.count())
            else:
                comments_count = Comment.count_by_blog_id(post.key().id())
                comments = db.GqlQuery(
                        "Select *from Comment where post_id=" + post_id + "ORDER BY submission_time desc")
                msg="please write a comment to post"
                likes = db.GqlQuery("select *from Like where post_id=" + post_id)
                self.render("permalink.html",post=post,comments=comments,msg=msg,comments_count=comments_count,like=likes.count())
        else:
            self.redirect("/login?error=You need to log in before "+
                          "performing comment option")

            return

class postlike(Handler):

    def get(self,post_id):

        if not self.user:
            self.redirect('/login?error=You need to be logged in order to perform the like action.!')

        else:

            post = Blog.get_by_id(int(post_id))
            # likes = db.GqlQuery("select *from Like where post_id=" + post_id)

            if self.user:

                # if self.request.get('like'):
                    likes = db.GqlQuery(
                        "SELECT *from Like where post_id=" + post_id + "and user_id=" + str(self.user.key().id()))

                    if self.user.key().id() == post.user_id:

                        self.redirect("/blog/" + post_id + "?error=You can't like your own post")


                    elif likes.count() == 0:
                        l = Like(user_id=self.user.key().id(), post_id=int(post_id))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/blog/%s' % post_id+"?error=Succesfully Liked.!")
                    else:
                        self.redirect('/blog/%s' % post_id)


class dellike(Handler):
    def get(self,post_id):
        like=db.GqlQuery("select *from Like where post_id="+post_id+"and user_id="+str(self.user.key().id()))
        for s in like:
            s.delete()
            time.sleep(0.1)
            self.redirect('/blog/%s' % post_id+"?error=Succesfully Unliked.!")



class UserDetails(Handler):
    def get(self,post_id):
        if self.user:
            posts = db.GqlQuery("SELECT *FROM Blog WHERE user_id=" +post_id+"ORDER BY submission_time desc ")
            users=User.get_by_id(int(post_id))
            if not posts:
                self.error(404)
                return
            if posts:
                self.render("myarticle.html", posts=posts, users=users)
        else:
            self.redirect("/login?error=You need to be logged, " +
"in order to view Profile Details!!")
        # post=Blog.get_by_id(int(post_id))
        # if not self.user:
        #         self.redirect('/login')



        # if not posts:
        #     self.error(404)
        #     return
        # else:
        #     self.redirect('/login')






class Newpost(Handler):
    def a (self,error="",subject="",blog=""):
        if self.user:
            self.render("newpost.html", error=error,subject=subject)
        else:
            self.redirect("/login")
    def get(self):
        self.a()
    def post(self):

        if not  self.user:
            self.redirect('/blog/')
        subject=self.request.get("subject")
        blog=self.request.get("blog")

        if subject and blog:
            p=Blog(user_id= self.user.key().id(), subject=subject,blog=blog)
            p.put()
            x=str(p.key().id())
            self.redirect('/blog/%s' %x)
        else:
            error="Please give data in both the fields"
            self.render("newpost.html",subject=subject,blog=blog,error=error)



app = webapp2.WSGIApplication([('/blog/(?:\.json)?',BlogFront),
                               ('/blog/([0-9]+)(?:\.json)?',Postpage),
                               ('/blog/newpost', Newpost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/userdetails/([0-9]+)',UserDetails),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',compy),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',DelComment),
                               ('/blog/postlike/([0-9]+)',postlike),
                               ('/blog/dellike/([0-9]+)',dellike),
                               ('/signup',Register),
                               #('/addcomment',AddComment),
                               ('/login',Login),
                               ('/logout',Logout)
                               ], debug=True)
