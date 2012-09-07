var express = require('express')
, routes = require('./routes')
, http = require('http')
, path = require('path')
, MemoryStore = require('connect/lib/middleware/session/memory')

, security = require('../lib/middleware.js')
, Store = require('./lib/stores/mongoose.js').Store;

var store = new Store();

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
        debug : true,
        realmName : 'Security middleware samples',
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

app.get('/products/list', routes.products);

var server = http.createServer(app);

server.listen(app.get('port'), function(){
    console.log("Express server listening on port " + app.get('port'));
});

