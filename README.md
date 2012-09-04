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

### Configure security-middleware within express

```javascript
    var security = require('security-middleware')
    , inMemoryStore = require('security-middleware/lib/security.js').inMemoryStore;

    var app = express();

    app.configure(function(){
    ...
      app.use(security({ 
        debug : false, // for debug purpose
        realmName : 'Express-security', // realm name
        store : inMemoryStore, // store which will be used to retrieve user information - inMemoryStore by default if none specified
        rememberMe : true, // whether a cookie will be set after authentication or not - false by default
        secure : true, // whether to use secured cookies or not - false by default
        credentialsMatcher: 'sha256', // a credentialsMatcher must be provided to check if the provided token credentials match the stored account credentials using the encryption algorithm specified
        loginUrl : '/login', // url used by the application to sign in - `/login` by default
        usernameParam : 'username', // name of the username parameter which will be used during form authentication - `username` by default
        passwordParam : 'password', // name of the password parameter which will be used during form authentication - `password` by default
        logoutUrl : '/logout', // url used by the application to sign out - `/logout` by default
        acl : [ // array of Access Controls to apply per url
               {
                   url : '/admin', // web resource (s) on which this access control will be applied - `/*` if none specified
                   methods : 'GET, POST', // HTTP method (s) for which this access control will be applied (GET, POST, PUT, DELETE or * for ALL) - `*` by default
                   authentication : 'BASIC', // authentication type - FORM or BASIC
                   rules : '(([role=user] && [permission=admin]) || [role=admin])' // access control rules to check
               },
               {
                   url : '/products/list',
                   methods : 'GET',
                   authentication : 'FORM',
                   // a rule can be based on query parameter (s) which will be valued at runtime (eg {idCompany})
                   rules : '(([role=user] && [permission=products:company_{idCompany}:list]) || [role=admin])'
               }
        ]
      }));
      ...
    });
```

### Use inMemoryStore

The inMemoryStore should not be used in a production environment. It may nevertheless be useful during the development phase.

It allows to save in memory both users and roles as in the example below.

```javascript
var inMemoryStore = require('security-middleware/lib/security.js').inMemoryStore
, credentialsMatcher = require('security-middleware/lib/security.js').sha256CredentialsMatcher 
, encryptedPassword = credentialsMatcher.encrypt('changeit');

inMemoryStore.storeRole({
    name : 'user', // must be unique
    privileges : [] // may be empty or null
});

inMemoryStore.storeRole({
    name : 'admin',
    privileges : [ 'admin:*' ]
});

inMemoryStore.storeAccount({
    username : 'user', // must be unique
    password : encryptedPassword, // must be encrypted using the same encryption algorithm which will be used by the security middleware
    roles : ['user'], // set of roles granted to the user
    privileges : [ 'products:company_1:list', 'products:company_1:show:*' ] // set of privileges granted to the user
});

inMemoryStore.storeAccount({
    username : 'admin',
    password : encryptedPassword,
    roles : [ 'user', 'admin' ],
    privileges : []
});
```

### Define a custom Store

A custom Store must conform to the interface below :

```javascript
/**
 * Returns the user mapped to this username or null
 * 
 * If exists, the returned object should include the user's password
 * 
 * @param username
 * @returns the user mapped to this username or null
 */
Store.prototype.lookup = function(username) {
    ...
};

/**
 * Returns the roles granted to the user mapped to this username as a set of strings
 * 
 * @param username
 * @returns the roles granted to the user mapped to this username as a set of strings
 */
Store.prototype.loadUserRoles = function(username) {
    ...
};

/**
 * Returns the privileges granted to the user mapped to this username as a set of strings
 * 
 * @param username
 * @returns the privileges granted to the user mapped to this username as a set of strings
 */
Store.prototype.loadUserPrivileges = function(username) {
    ...
};

/**
 * Returns the privileges granted to the role mapped to this role name as a set of strings
 * 
 * @param username
 * @returns the privileges granted to the role mapped to this role name as a set of strings
 */
Store.prototype.loadRolePrivileges = function(roleName) {
    ...
};


```


### Define an Access Control rule

### Subject api
