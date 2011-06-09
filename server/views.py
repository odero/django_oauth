
import oauth2 as oauth
import functools
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.template import RequestContext
from forms import *
import utils
from django.contrib.auth import views

import json
import sys

sys.stderr = sys.stdout

def serve_oauth(func):
    @functools.wraps(func)
    def wrapper(*args):
        request = args[0]
        meta = {}
        postdata = None
        
        if request.method == 'POST':
            postdata = dict([x for x in request.POST.iteritems()])
            
        if request.META.get('HTTP_AUTHORIZATION', None):
            meta['Authorization'] = request.META['HTTP_AUTHORIZATION']
        
        path = request.build_absolute_uri()
        oauth_request = oauth.Request.from_request(request.method, path, headers=meta, parameters=postdata)
        oauth_server = utils.DataStoreServer(data_store=utils.DataStore(oauth_request))
        oauth_server.add_signature_method(oauth.SignatureMethod_PLAINTEXT())
        oauth_server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())
        new_args = [request, oauth_server, oauth_request]
        args = tuple(new_args)
        return func(*args)
    return wrapper

@csrf_exempt
@serve_oauth
def request_token(request, oauth_server, oauth_request):
    # lookup consumer
    # if consumer key and secret dont exist
    # return invalid key/secret combi error
    # else
    # fetch consumer from data store 
    # create request token and return it
    
    try:
        token = oauth_server.fetch_request_token(oauth_request)
    except oauth.Error, err:
        return HttpResponse(err, status=401)
    except ValueError, err:
        return HttpResponse(err, status=401)
    
    return HttpResponse(token)

@login_required
@serve_oauth
def authorize(request, oauth_server, oauth_request):
    # ensure user is logged in
    # if keys (consumer/token) are not ok and/or signed
    # return invalid key/secret error
    # else
    # allow user to authorize what consumer is allowed to do
    # return token with verifier or redirect to callback url
    if request.method == 'GET':
        request.session['oauth_request'] = oauth_request
        return render_to_response('authorize.html', context_instance=RequestContext(request))
    
    if request.POST.get('cancel', False):
        return HttpResponseRedirect('/oauth/cancel/')
    
    if request.session.get('oauth_request', False):
        oauth_request = request.session['oauth_request']
    
    token = oauth_server.fetch_request_token(oauth_request)
    oauth_server.authorize_token(token, request.user)
    
    if token.callback_confirmed:
        return HttpResponseRedirect(token.get_callback_url())
    return HttpResponse(token.to_string() + '&oauth_verifier=' + token.verifier)

@csrf_exempt
#@login_required
@serve_oauth
def access_token(request, oauth_server, oauth_request):
    # if keys are not ok and/or signed
    # return invalid key error
    # else
    # 
    try:
        token = oauth_server.fetch_access_token(oauth_request)
    except oauth.Error, err:
        return HttpResponse(err, status=401)
    
    return HttpResponse(token)

#@login_required
@csrf_exempt
@serve_oauth
def get_resource(request, oauth_server, oauth_request):
    try:
        oauth_server.verify_access_token(oauth_request)
    except oauth.Error, err:
        return HttpResponse(err, status=401)
    
    return HttpResponse(json.dumps(['one', 'two']))

@login_required
def register(request):
    '''
    Shows a registration page for users to register new applications
    '''
    if request.method == 'GET':
        f = ConsumerRegisterForm()
        return render_to_response('register.html', {'form':f}, context_instance=RequestContext(request))
    
    form  = ConsumerRegisterForm(request.POST)
    if form.is_valid():
        f  = form.save(commit=False)
        f.user = request.user
        f.key = utils.generate_key()
        f.secret = utils.generate_secret()
        f.save()
    else:
        return render_to_response('register.html', {'form':form}, context_instance=RequestContext(request))
    
    return HttpResponseRedirect('/api/applications/')

@login_required
def applications(request):
    '''
    Shows a list of the consumers/applications this user has registered
    '''
    return render_to_response('applications.html', 
                              {'apps':ConsumerProfile.objects.filter(user=request.user)},
                              context_instance=RequestContext(request))

@login_required
def logout(request):
    views.logout(request)
    return HttpResponseRedirect('/')
