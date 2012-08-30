/* 
 * security middleware unit tests.
 * 
 */

var express = require('express')
, routes = require('./routes')
, http = require('http')
, path = require('path')
, assert = require('assert')
, sha256CredentialsMatcher = require('../lib/security.js').sha256CredentialsMatcher
, utils = require('../lib/utils.js')
, security = require('../lib/middleware.js');

var app = express();

var store = require('../lib/security.js').inMemoryStore;
store.storeAccount({
    username : 'user', 
    password : sha256CredentialsMatcher.encrypt('changeit'),
    roles: ['user'],
    privileges : []
});
store.storeAccount({
    username : 'admin', 
    password : sha256CredentialsMatcher.encrypt('changeit'),
    roles: ['user', 'admin'],
    privileges : []
});
store.storeRole({
    name : 'user', 
    privileges : []
});
store.storeRole({
    name : 'admin', 
    privileges : ['*']
});

console.log(store);

var secret = 'your secret here';

var MemoryStore = require('connect/lib/middleware/session/memory');

app.configure(function(){
    app.set('port', 3000);
    app.set('views', __dirname + '/views');
    app.set('view engine', 'ejs');
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.cookieParser(secret));
    app.use(express.session({
        store: new MemoryStore({
            reapInterval: 60000 * 10
        })
    }));

    app.use(security({ 
        debug : true,
        realm : 'Express-security',
        store : store,
        rememberMe : true,
        secure : true,
        credentialsMatcher: sha256CredentialsMatcher,
        loginUrl : '/login',
        logoutUrl : '/logout',
        loginPage : 'login',
        usernameParam : 'username',
        passwordParam : 'password',
        acl : [
        {
            url : '/admin',
            methods : 'GET, POST',
            authentication : 'BASIC',
            roles : 'admin'
        },
        {
            url : '/products',
            methods : 'GET, POST',
            authentication : 'FORM',
            roles : 'user'
        }
        ]
    }));

    app.use(app.router);
    app.use(require('less-middleware')({
        src: __dirname + '/public'
    }));
    app.use(express.static(path.join(__dirname, 'public')));
});

app.get('/', routes.index);

app.get('/admin', routes.admin);

app.get('/login', routes.login);

app.get('/products', routes.products);

var server = http.createServer(app);

server.listen(app.get('port'), function(){
    console.log("Express server listening on port " + app.get('port'));
});

var retrieveCookies = function(response){
    var cookies = [];
    utils.forEach(response.headers['set-cookie'], function(cookie){
        var parts = cookie.split(';');
        cookies.push(parts[0]);
    });
    return cookies.join(';');
};

var options = {
    host : 'localhost',
    port : app.get('port'),
    method : 'GET'
};

var testRequests = function(requests){
    if(requests.length > 0){
        var request = requests[0];
        utils.copy(options, request.options);
        var req = http.request(options, function (response) {
            var responseCode = response.statusCode;
            console.log('STATUS: ' + responseCode);
            console.log('ASSERT: ' + request.code);
            assert.ok(utils.isEqual(request.code, responseCode));
            console.log('HEADERS: ' + JSON.stringify(response.headers));
            var headers = options['headers'] || {};
            headers['Cookie'] = retrieveCookies(response);
            options['headers'] = headers;
            requests.splice(0, 1);
            testRequests(requests);
        });
        req.on('error', function(e) {
            console.log('problem with request: ' + e.message);
            server.close(function(){
                console.log("Express server stop listening on port " + app.get('port'));
            });
        });
        req.end();
    }
    else{
        server.close(function(){
            console.log("Express server stop listening on port " + app.get('port'));
        });
    }
}

var requests = [];

/**
 * CHECK BASIC AUTHENTICATION
 */

// test without authentication
requests.push({
    options:{
        path: '/admin'
    }, 
    code:401
});

// test with bad principal
requests.push({
    options:{
        auth: 'wrong:wrong'
    }, 
    code:401
});

// test with wrong password
requests.push({
    options:{
        auth: 'admin:wrong'
    }, 
    code:401
});

// test OK
requests.push({
    options:{
        auth: 'admin:changeit'
    }, 
    code:200
});

/**
 * CHECK FORM AUTHENTICATION
 */

requests.push({
    options:{
        path: '/logout'
    }, 
    code:302
});

// test without authentication
requests.push({
    options:{
        path: '/products'
    }, 
    code:302
});

// test with bad username
requests.push({
    options:{
        path: '/login?username=wrong&password=wrong'
    }, 
    code:302
});

// test with bad password
requests.push({
    options:{
        path: '/login?username=admin&password=wrong'
    }, 
    code:302
});

// test OK
requests.push({
    options:{
        path: '/login?username=admin&password=changeit'
    }, 
    code:200
});

testRequests(requests);