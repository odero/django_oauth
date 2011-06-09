import oauth2 as oauth
from server.models import *
from hashlib import md5, sha1

def generate_key():
    return md5(oauth.generate_nonce()).hexdigest()

def generate_secret():
    return sha1(oauth.generate_nonce()).hexdigest()

class DataStore(object):
    """
    Uses the database to store and retrieve consumers and tokens
    Note: Borrowed from the Leah Culiver's OAuth server implementation
    """
    def __init__(self, request):
        self.consumer = ''
        self.request_token = ''
        self.access_token = ''
        self.nonce = ''
        self.verifier = ''
        self.request = request
        
    def lookup_consumer(self, key):
        try:
            consumer_prof = ConsumerProfile.objects.get(key = key)
            self.consumer = oauth.Consumer(consumer_prof.key, consumer_prof.secret)
            return self.consumer
        except ConsumerProfile.DoesNotExist:
            return None
    
    def lookup_token(self, token_type, token):
        token_attrib = getattr(self, '%s_token' % token_type)
        
        try:
            t = Token.objects.get(key=token)
            token_attrib = oauth.Token(t.key, t.secret)
            if token_type == 'request':
                self.request_token = token_attrib
            else:
                self.access_token = token_attrib
        except Token.DoesNotExist:
            pass
        
        if token == token_attrib.key:
            token_attrib.set_callback(t.callback_url)
            return token_attrib
        return None
    
    def fetch_request_token(self, consumer, callback):
        
        if consumer.key == self.consumer.key:
            key = generate_key()
            secret = generate_secret()
            
            self.request_token = oauth.Token(key, secret)
            
            if callback:
                from urlparse import urlparse
                
                # check if callback is sensible
                scheme, netloc, path, params, query, fragment = urlparse(callback)
                if scheme not in ('http', 'https') or not netloc:
                    raise oauth.Error('Invalid callback URL')
                self.request_token.set_callback(callback)
            else:
                # set callback to be the one provided at registration
                con = ConsumerProfile.objects.get(key=consumer.key, secret=consumer.secret)
                self.request_token.set_callback(con.callback_url)
                
            url = self.request_token.callback if self.request_token.callback != None else ''    
            t = Token.objects.create(key=key, secret=secret, callback_url=url)
            t.save()
            return self.request_token                    
        return None
    
    def fetch_access_token(self, consumer, token, verifier):
        
        t = Token.objects.get(key=token.key, secret=token.secret)
        self.verifier = t.verifier
        
        if consumer.key == self.consumer.key and token.key == self.request_token.key and verifier == self.verifier:
            # check here if token is authorized
            # verifier will only have been set if user had authorized 
            # so check is valid
            key = generate_key()
            secret = generate_secret()
            self.access_token = oauth.Token(key, secret)
            t = Token.objects.create(key=key, secret=secret)
            t.save()
            return self.access_token
        return None
    
    def authorize_request_token(self, token, user):
        if token.key == self.request_token.key:
            # authorize the request token in the store
            # user authorized it therefore set verifier
            self.request_token.set_verifier()
            t = Token.objects.get(key=token.key, secret=token.secret)
            t.verifier = self.request_token.verifier
            t.save()
            return self.request_token
        return None

class DataStoreServer(oauth.Server):
    """
    Adds data storage abilities to the base OAuth Server
    Note: Borrowed from the Leah Culiver's OAuth server implementation
    """
    def __init__(self, signature_methods=None, data_store=None):
        self.data_store = data_store
        super(DataStoreServer, self).__init__(signature_methods)
        
    def fetch_request_token(self, oauth_request):
        """
        Processes a request_token request and returns the
        request token on success.
        """
        try:
            # Get the request token for authorization.
            token = self._get_token(oauth_request, 'request')
        except oauth.Error:
            
            # No token required for the initial token request.
            version = self._get_version(oauth_request)
            consumer = self._get_consumer(oauth_request)
            
            try:
                callback = self.get_callback(oauth_request)
            except oauth.Error:
                callback = None # 1.0, no callback specified.
            self._check_signature(oauth_request, consumer, None)
            # Fetch a new token.
            token = self.data_store.fetch_request_token(consumer, callback)
        return token
    
    def fetch_access_token(self, oauth_request):
        """
        Processes an access_token request and returns the
        access token on success.
        """
        version = self._get_version(oauth_request)
        consumer = self._get_consumer(oauth_request)
        try:
            verifier = self._get_verifier(oauth_request)
        except oauth.Error:
            verifier = None
        
        # Get the request token.
        token = self._get_token(oauth_request, 'request')
        
        self._check_signature(oauth_request, consumer, token)
        new_token = self.data_store.fetch_access_token(consumer, token, verifier)
        return new_token
    
    def authorize_token(self, token, user):
        """Authorize a request token."""
        return self.data_store.authorize_request_token(token, user)
    
    def get_callback(self, oauth_request):
        """Get the callback URL."""
        return oauth_request.get_parameter('oauth_callback')
    
    def _get_consumer(self, oauth_request):
        consumer_key = oauth_request.get_parameter('oauth_consumer_key')
        consumer = self.data_store.lookup_consumer(consumer_key)
        if not consumer:
            raise oauth.Error('Invalid consumer.')
        return consumer
    
    def _get_token(self, oauth_request, token_type='access'):
        """Try to find the token for the provided request token key."""
        token_field = oauth_request.get_parameter('oauth_token')
        token = self.data_store.lookup_token(token_type, token_field)
        if not token:
            raise oauth.Error('Invalid %s token: %s' % (token_type, token_field))
        return token
    
    def verify_access_token(self, oauth_request):
        """
        Validate the token to see if it exists and passes signature check
        Doesn't return a value but raises an error if sig check fails
        """
        version = self._get_version(oauth_request)
        consumer = self._get_consumer(oauth_request)
        
        token = self._get_token(oauth_request, 'access')
        self._check_signature(oauth_request, consumer, token)

        

