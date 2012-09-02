/* 
 * security middleware unit tests.
 * 
 */

var express = require('express')
, routes = require('./routes')
, http = require('http')
, path = require('path')
, MemoryStore = require('connect/lib/middleware/session/memory')

, utils = require('../lib/utils.js')
, credentialsMatcher = require('../lib/security.js').sha256CredentialsMatcher
, store = require('../lib/security.js').inMemoryStore

, security = require('../lib/middleware.js')

, userRolePrivileges = []
, adminRolePrivileges = [ 'admin:*' ]
, userRoles = [ 'user' ]
, userPrivileges = [ 'products:company_1:list', 'products:company_1:show:*' ]
, adminRoles = [ 'user', 'admin' ]
, adminPrivileges = []
, encryptedPassword = credentialsMatcher.encrypt('changeit');

// init inMemoryStore
store.storeRole({
    name : 'user',
    privileges : userRolePrivileges
});

store.storeRole({
    name : 'admin',
    privileges : adminRolePrivileges
});

store.storeAccount({
    username : 'user',
    password : encryptedPassword,
    roles : userRoles,
    privileges : userPrivileges
});

store.storeAccount({
    username : 'admin',
    password : encryptedPassword,
    roles : adminRoles,
    privileges : adminPrivileges
});

var app = express();

app.configure(function(){
    app.set('port', 3000);
    app.set('views', __dirname + '/views');
    app.set('view engine', 'ejs');
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.cookieParser('secret'));
    app.use(express.session({
        store: new MemoryStore({
            reapInterval: 60000 * 10
        })
    }));

    app.use(security({ 
        debug : false,
        realmName : 'Express-security',
        store : store,
        rememberMe : true,
        secure : true,
        credentialsMatcher: 'sha256', // credentialsMatcher
        loginUrl : '/login',
        usernameParam : 'username',
        passwordParam : 'password',
        logoutUrl : '/logout',
        acl : [
               {
                   url : '/admin',
                   methods : 'GET, POST',
                   authentication : 'BASIC',
                   rules : '(([role=user] && [permission=admin]) || [role=admin])'
               },
               {
                   url : '/products/list',
                   methods : 'GET',
                   authentication : 'FORM',
                   rules : '(([role=user] && [permission=products:company_{idCompany}:list]) || [role=admin])'
               },
               {
                   url : '/products',
                   methods : 'GET',
                   authentication : 'FORM',
                   rules : '(([role=user] && [permission=products:company_{idCompany}:show:product_{idProduct}]) || [role=admin])'
               },
               {
                   url : '/products',
                   methods : 'PUT',
                   authentication : 'FORM',
                   rules : '(([role=user] && [permission=products:company_{idCompany}:create]) || [role=admin])'
               },
               {
                   url : '/products',
                   methods : 'POST',
                   authentication : 'FORM',
                   rules : '(([role=user] && [permission=products:company_{idCompany}:update]) || [role=admin])'
               },
               {
                   url : '/products',
                   methods : 'DELETE',
                   authentication : 'FORM',
                   rules : '(([role=user] && [permission=products:company_{idCompany}:delete]) || [role=admin])'
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

var cookies = null;

exports['test middleware#BASIC-AUTH'] = function(beforeExit, assert) {
    // test without authentication
    assert.response(server, {
        url: '/admin',
        method: 'GET'
    }, {
        status: 401
    }, 'test middleware#BASIC-AUTH without authentication');
    // test with bad principal
    assert.response(server, {
        url: '/admin',
        method: 'GET',
        headers : {
            'Authorization': 'Basic ' + new Buffer('wrong:wrong').toString('base64')
        }
    }, {
        status: 401
    }, 'test middleware#BASIC-AUTH with bad principal');
    // test with wrong password
    assert.response(server, {
        url: '/admin',
        method: 'GET',
        headers : {
            'Authorization': 'Basic ' + new Buffer('admin:wrong').toString('base64')
        }
    }, {
        status: 401
    }, 'test middleware#BASIC-AUTH with wrong password');
    // test OK
    assert.response(server, {
        url: '/admin',
        method: 'GET',
        headers : {
            'Authorization': 'Basic ' + new Buffer('admin:changeit').toString('base64')
        }
    }, {
        status: 200,
    }, function(response){
        cookies = retrieveCookies(response);
        assert.ok(cookies.indexOf('account') >= 0);
    }, 'test middleware#BASIC-AUTH OK');
};

exports['test middleware#FORM-AUTH'] = function(beforeExit, assert) {
    assert.response(server, {
        url: '/logout',
        method: 'GET'
    }, {
        status: 302
    });
    // test without authentication
    assert.response(server, {
        url: '/products',
        method: 'GET'
    }, {
        status: 302
    }, 'test without authentication');
    // test with bad username
    assert.response(server, {
        url: '/login?username=wrong&password=wrong',
        method: 'GET'
    }, {
        status: 302
    }, 'test FORM-AUTH with bad username');
    // test with bad password
    assert.response(server, {
        url: '/login?username=admin&password=wrong',
        method: 'GET'
    }, {
        status: 302
    },'test FORM-AUTH with bad password');
    // test ok
    assert.response(server, {
        url: '/login?username=admin&password=changeit',
        method: 'GET'
    }, {
        status: 200
    }, 'test FORM-AUTH OK');
};