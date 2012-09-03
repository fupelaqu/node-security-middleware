node-security-middleware
========================

## About

node-security-middleware is a security middleware for [Connect](http://senchalabs.github.com/connect/)/[Express](http://expressjs.com/)

It supplies both BASIC and FORM authentication, as well as authorization based on an Access Control List.
The latter is a set of rules that can be defined per url and rely on privileges and roles granted to the authenticated user.
The authentication as well as the authorization mechanisms rely on a store which will be used to retrieve the user credentials as well as its roles and privileges.

Installation
====================

    $ npm install security-middleware

Using It
====================

### Configure the middleware within express

    var security = require('security-middleware');

    var app = express();

    app.configure(function(){
      app.use(security({ 
        debug : false, // for debug purpose
        realmName : 'Express-security', // realm name
        store : store, // store which will be used to retrieve user information - inMemoryStore by default
        rememberMe : true, // whether a cookie will be set after authentication or not - false by default
        secure : true, // whether to use secured cookies or not - false by default
        credentialsMatcher: 'sha256', // a credentialsMatcher must be provided to check if the provided token credentials match the stored account credentials using the encrypted algoithm specified
        loginUrl : '/login', // url used by the application to sign in - `/login` by default
        usernameParam : 'username', // name of the username parameter which will be used during form authentication
        passwordParam : 'password', // name of the password parameter which will be used during form authentication
        logoutUrl : '/logout', // url used by the application to sign out - `/logout` by default
        acl : [ // array of Access Controls to apply per url
               {
                   url : '/admin', // web resource (s) on which this access control will be applied
                   methods : 'GET, POST', // HTTP method (s) for which this access control will be applied
                   authentication : 'BASIC', // authentication type - FORM or BASIC
                   rules : '(([role=user] && [permission=admin]) || [role=admin])' // access control rules to check
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
    });
