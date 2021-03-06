/*!
 * security
 *
 */

var utils = require('./utils.js')
, crypto = require('crypto')
, url = require('url');

/**
 * Class CredentialsMatcher
 */
var CredentialsMatcher = function(algorithm){
    this.encrypt = function(str){
        if(utils.isDefined(algorithm) 
            && utils.isDefined(str) 
            && typeof str === 'string'){
            return crypto
            .createHash(algorithm)
            .update(str)
            .digest('hex');
        }
        return str;
    };

};

/**
 * Returns true if the provided token credentials match the stored account 
 * credentials, false otherwise.
 */
CredentialsMatcher.prototype.doCredentialsMatch = function(token, account){
    if(utils.isDefined(token) 
        && utils.isDefined(token.getCredentials) 
        && utils.isDefined(account) 
        && utils.isDefined(account.credentials)){
        return utils.isEqual(
            utils.stringToBytes(account.credentials), 
            utils.stringToBytes(this.encrypt(token.getCredentials())));
    }
    return false;
};
exports.CredentialsMatcher = CredentialsMatcher;

exports.simpleCredentialsMatcher = new CredentialsMatcher();

exports.md5CredentialsMatcher = new CredentialsMatcher('md5');

exports.sha1CredentialsMatcher = new CredentialsMatcher('sha1');

exports.sha256CredentialsMatcher = new CredentialsMatcher('sha256');

exports.sha512CredentialsMatcher = new CredentialsMatcher('sha512');

/**
 * Class UsernamePasswordToken
 */
var UsernamePasswordToken = function(username, password, rememberMe){
    this.getUsername = function(){
        return username;
    };
    var _password = utils.toCharArray(password);
    this.getPassword = function(){
        return _password;
    };
    this.rememberMe = rememberMe || false;
};
/**
 * Returns the account identity submitted during the authentication process.
 *
 * @return the account identity submitted during the authentication process.
 */
UsernamePasswordToken.prototype.getPrincipal = function(){
    return this.getUsername();
};
/**
 * Returns the credentials submitted by the user during the authentication process that verifies
 * the submitted {@link #getPrincipal() account identity}.
 *
 * @return the credential submitted by the user during the authentication process.
 */
UsernamePasswordToken.prototype.getCredentials = function(){
    var p = this.getPassword();
    return utils.isDefined(p) ? p.join('') : null;
};
/**
 * Returns true if the submitting user wishes their identity (principal(s)) to be remembered
 * across sessions, false otherwise.
 *
 * @return true if the submitting user wishes their identity (principal(s)) to be remembered
 *         across sessions, false otherwise.
 */
UsernamePasswordToken.prototype.isRememberMe = function(){
    return this.rememberMe;
};

exports.UsernamePasswordToken = UsernamePasswordToken;

/**
 * Class SimpleAccount
 */
/**
 * Constructs a SimpleAccount instance for the specified realm with the given principal and credentials, with
 * the assigned roles and permissions.
 *
 * @param principal the princial identifying the account.
 * @param credentials the credentials that verify identity for the account
 * @param realmName the name of the realm that accesses this account data
 * @param roleNames the names of the roles assigned to this account.
 * @param permissions the permissions assigned to this account directly.
 */
var SimpleAccount = function(principal, credentials, realmName, roleNames, permissions){
    this.principal = principal;
    this.credentials = credentials;
    this.realmName = realmName;
    this.roleNames = roleNames || [];
    this.permissions = permissions || [];
};

//exports.SimpleAccount = SimpleAccount;

var makeCallback = function(callback){
    if(utils.isUndefined(callback) || ('function' !== typeof callback)){
        callback = function(){};
    }
    return callback;
};

/**
 * Class InMemoryStore
 */
var InMemoryStore = function(accounts, roles){
    this.accounts = accounts || [];  
    this.roles = roles || [];
};

InMemoryStore.prototype.storeAccount = function(account) {
    if(utils.isDefined(account) && utils.isDefined(account.username)){
        this.accounts[account.username] = account;
    }
};

InMemoryStore.prototype.storeRole = function(role) {
    if(utils.isDefined(role) && utils.isDefined(role.name)){
        this.roles[role.name] = role;
    }
};

/**
 * Returns the user mapped to this username or null
 * 
 * If exists, the returned object should include the user's password
 * 
 * @param username
 * @returns the user mapped to this username or null within the provided callback
 * @throws any error within the provided callback
 */
InMemoryStore.prototype.lookup = function(username, callback) {
    callback = makeCallback(callback);
    var user = this.accounts[username];
    callback(null, user);
};

/**
 * Returns the roles granted to the user mapped to this username as an array of string
 * 
 * @param username
 * @returns the roles granted to the user mapped to this username as an array of string within the provided callback
 * @throws any error within the provided callback
 */
InMemoryStore.prototype.loadUserRoles = function(username, callback) {
    callback = makeCallback(callback);
    this.lookup(username, function(err, user){
        callback(null, user ? user.roles : []);
    });
};

/**
 * Returns the privileges granted to the user mapped to this username as an array of string
 * 
 * @param username
 * @returns the privileges granted to the user mapped to this username as an array of string within the provided callback
 * @throws any error within the provided callback
 */
InMemoryStore.prototype.loadUserPrivileges = function(username, callback) {
    callback = makeCallback(callback);
    this.lookup(username, function(err, user){
        callback(null, user ? user.privileges : []);
    });
};

/**
 * Returns the privileges granted to the role mapped to this role name as an array of string
 * 
 * @param roleName
 * @returns the privileges granted to the role mapped to this role name as an array of string within the provided callback
 * @throws any error within the provided callback
 */
InMemoryStore.prototype.loadRolePrivileges = function(roleName, callback) {
    callback = makeCallback(callback);
    var role = this.roles[roleName];
    callback(null, role ? role.privileges : []);
};

InMemoryStore.prototype.contains = function(username) {
    return Object.prototype.hasOwnProperty.call(this.accounts, username)
    && Object.prototype.propertyIsEnumerable.call(this.accounts,
        username);
};

var inMemoryStore = new InMemoryStore();

exports.inMemoryStore = inMemoryStore;

/**
 * Class Realm
 */
var Realm = function(options){
    options = options || {};
    this.store = options.store || inMemoryStore;
    this.name = options.realmName || 'Authorization Required';
    var credentialsMatcher = options.credentialsMatcher || exports.simpleCredentialsMatcher;
    if(credentialsMatcher instanceof CredentialsMatcher){
        this.credentialsMatcher = credentialsMatcher;
    }
    else if(typeof credentialsMatcher === 'string'){
        switch(credentialsMatcher.trim().toLowerCase()){
            case 'md5' :
                this.credentialsMatcher = exports.md5CredentialsMatcher;
                break;
            case 'sha1' :
                this.credentialsMatcher = exports.sha1CredentialsMatcher;
                break;
            case 'sha256' :
                this.credentialsMatcher = exports.sha256CredentialsMatcher;
                break;
            case 'sha512' :
                this.credentialsMatcher = exports.sha512CredentialsMatcher;
                break;
            default :
                this.credentialsMatcher = new CredentialsMatcher(credentialsMatcher);
        }
    }
    else{
        throw new Error('wrong credentials matcher');
    }
};

/**
 * Authenticates a user via the given authentication token. 
 */
Realm.prototype.authenticate = function(token, callback){
    callback = makeCallback(callback);
    if(utils.isUndefined(token) 
        || utils.isUndefined(token.getPrincipal) 
        || utils.isUndefined(token.getCredentials)){
        callback(new Error('wrong token'));
    }
    var principal = token.getPrincipal();
    // Null principal is invalid
    if(utils.isUndefined(principal)){
        callback(new Error('Null principals are not allowed by this realm.'));
    }
    // Get the user with the given principal. If the user is not
    // found, then he doesn't have an account and we throw an
    // exception.
    var self = this;
    this.store.lookup(principal, function(err, user){
        if(utils.isDefined(err)){
            callback(err);
        }
        else if(utils.isUndefined(user)){
            callback(new Error('No account found for user ' + principal));
        }
        else{
            // Now check the user's password against the hashed value stored
            // in the store.
            var account = new SimpleAccount(principal, user.password, self.name);
            if(!self.credentialsMatcher.doCredentialsMatch(token, account)){
                callback(new Error('Invalid password for ' + principal));
            }
            else{
                callback(null, account);
            }
        }
    });
};

/**
 * Determines whether a user has a particular role or not. It
 * should return {{true}} if the user has the role, or {{false}}
 * otherwise. {{principal}} is the principal returned by the
 * {{authenticate()}} method, while {{roleName}} is simply a
 * string.
 */
Realm.prototype.hasRole = function(principal, roleName, callback) {
    callback = makeCallback(callback);
    if(utils.isUndefined(principal) || utils.isUndefined(roleName)){
        callback(new Error('principal and roleName are mandatory arguments'));
    }
    else{
        this.store.loadUserRoles(principal, function(err, roles){
            if(err){
                callback(err);
            }
            else{
                callback(null, utils.isDefined(roles)&& utils.some(roles, function(role){
                        return utils.isEqual(role, roleName);
                    }));
            }
        });
    }
};

/**
 * Determines whether a user has a set of particular roles or not. It
 * should return {{true}} if the user has been granted the roles, or {{false}}
 * otherwise. {{principal}} is the principal returned by the
 * {{authenticate()}} method, while {{roles}} is simply an array of
 * string.
 */
Realm.prototype.hasAllRoles = function(principal, roles, callback) {
    callback = makeCallback(callback);
    if(utils.isUndefined(principal) || utils.isUndefined(roles)){
        callback(new Error('principal and roles are mandatory arguments'));
    }
    else{
        this.store.loadUserRoles(principal, function(err, userRoles){
            if(err){
                callback(err);
            }
            else{
                callback(null, utils.isDefined(userRoles) && utils.every(roles, function(roleName){
                    return utils.some(userRoles, function(role){
                        return utils.isEqual(role, roleName);
                    });
                }));
            }
        });
    }
};

/**
 * Returns true if the user is permitted to perform an action or access a 
 * resource summarized by the specified permission string.
 */
Realm.prototype.isPermitted = function(principal, requiredPermission, callback) {
    callback = makeCallback(callback);
    if(utils.isUndefined(principal) || utils.isUndefined(requiredPermission)){
        callback (new Error('principal and requiredPermission are mandatory arguments'));
    }
    else{
        var match = function(privileges, search){
            return utils.some(privileges, function(it){
                var ret = utils.isEqual(search, it);
                return ret;
            });
        };
        var existsRequiredPermission = function(privileges){
            var parts = requiredPermission.split(':');
            var search = parts.join(':');
            var found = match(privileges, search) || match(privileges, search + ':*');
            if(!found){
                while(parts.length > 0){
                    parts.pop();
                    search = parts.join(':') + (parts.length > 0 ? ':' : '') + '*';
                    if(match(privileges, search)){
                        found = true;
                        break;
                    }
                }
            }
            return found;
        };
        var self = this;
        // check within user privileges
        this.store.loadUserPrivileges(principal, function(err, userPrivileges){
            if(err){
                callback(err);
            }
            else if(utils.isDefined(userPrivileges) 
                && existsRequiredPermission(userPrivileges)){
                callback(null, true);
            }
            else{
                // check within user roles privileges
                self.store.loadUserRoles(principal, function(err, userRoles){
                    if(err){
                        callback(err);
                    }
                    else{
                        if(utils.isUndefined(userRoles)){
                            callback(null, false);
                        }
                        else{
                            utils.someAsync(userRoles, function(next, role){
                                self.store.loadRolePrivileges(role, function(err, rolePrivileges){
                                    if(err){
                                        next(false);
                                    }
                                    else if(utils.isDefined(rolePrivileges) 
                                        && existsRequiredPermission(rolePrivileges)){
                                        next(true);
                                    }
                                    else{
                                        next(false);
                                    }
                                });
                            }, function(value){
                                callback(null, value);
                            });
                        }
                    }
                });
            }
        });
    }
};

/**
 * Returns true if the user implies all of the specified permission strings.
 */
Realm.prototype.isPermittedAll = function(principal, permissions, callback) {
    if(utils.isUndefined(callback) || ('function' !== typeof callback)){
        callback = function(){};
    }
    if(utils.isUndefined(principal) || utils.isUndefined(permissions)){
        calback(new Error('principal and permissions are mandatory arguments'));
    }
    else{
        var self = this;
        // TODO
        return utils.every(permissions, function(permission){
            return self.isPermitted(principal, permission);
        });
    }
};

exports.Realm = Realm;

/**
 * Class Subject
 */
var Subject = function(realm, req, res, secure){
    if(utils.isUndefined(realm) || utils.isUndefined(req)){
        throw new Error('realm and req are mandatory');
    }
    this.realm = realm;
    this.secure = secure || false;
    this.authenticated = false;
    this.session = req.session || {};
    this.res = res || {cookie : function(){}, clearCookie : function(){}};
    var account = this.session.account;
    if(utils.isUndefined(account)){
        account = this.secure ? req.signedCookies.account : req.cookies.account;
        if(utils.isDefined(account) && utils.isEqual(realm.name, account.realmName)){
            this.account = new SimpleAccount(account.principal, null, realm.name);
            console.log(
                'retrieve account ' + account.principal 
                + ' for ' + account.realmName 
                + ' from cookie');
        }
    }
    else if(utils.isEqual(realm.name, account.realmName)){
        this.account = new SimpleAccount(account.principal, null, account.realmName);
        this.authenticated = true;
        console.log(
            'retrieve account ' + account.principal 
            + ' for ' + account.realmName 
            + ' from session');
    }
};
/**
 * Returns this Subject's uniquely-identifying principal, or null 
 * if this Subject doesn't yet have account data associated with it
 */
Subject.prototype.getPrincipal = function(){
    return utils.isDefined(this.account) ? this.account.principal : null;
};
/**
 * Returns within the provided callback true if this Subject has the specified role, false otherwise.
 */
Subject.prototype.hasRole = function(roleName, callback){
    if(utils.isUndefined(callback) || ('function' !== typeof callback)){
        callback = function(){};
    }
    this.realm.hasRole(this.getPrincipal(), roleName, function(err, value){
        if(err){
            callback(err);
        }
        else{
            callback(null, value);
        }
    });
};
/**
 * Returns within the provided callback true if this Subject has all of the specified roles, false otherwise.
 */
Subject.prototype.hasAllRoles = function(roles, callback){
    if(utils.isUndefined(callback) || ('function' !== typeof callback)){
        callback = function(){};
    }
    this.realm.hasAllRoles(this.getPrincipal(), roles, function(err, value){
        if(err){
            callback(err);
        }
        else{
            callback(null, value);
        }
    });
};
/**
 * Returns within the provided callback true if the Subject is permitted to perform an action or access a 
 * resource summarized by the specified permission string.
 */
Subject.prototype.isPermitted = function(permission, callback) {
    if(utils.isUndefined(callback) || ('function' !== typeof callback)){
        callback = function(){};
    }
    this.realm.isPermitted(this.getPrincipal(), permission, function(err, value){
        if(err){
            callback(err);
        }
        else{
            callback(null, value);
        }
    });
};
/**
 * Returns within the provided callback true if the Subject implies all of the specified permission strings.
 */
Subject.prototype.isPermittedAll = function(permissions, callback) {
    if(utils.isUndefined(callback) || ('function' !== typeof callback)){
        callback = function(){};
    }
    this.realm.isPermittedAll(this.getPrincipal(), permissions, function(err, value){
        if(err){
            callback(err);
        }
        else{
            callback(null, value);
        }
    });
};
/**
 * Returns true if this Subject/user has proven their identity during their current session
 * by providing valid credentials matching those known to the system, false otherwise.
 */
Subject.prototype.isAuthenticated = function(){
    return this.authenticated;
};
/**
 * Performs a login attempt for this Subject/user. If unsuccessful, an error is thrown within the provided callback.
 * If successful, the account data associated with the submitted principals/credentials 
 * will be associated with this Subject and the method will return quietly.
 * 
 * Upon returninq quietly, this Subject instance can be considered authenticated 
 * and getPrincipal() will be non-null and isAuthenticated() will return true.
 */
Subject.prototype.login = function(token, callback){
    callback = makeCallback(callback);
    var self = this;
    this.realm.authenticate(token, function(err, account){
        if(err){
            callback(err);
        }
        else{
            self.account = account;
            self.authenticated = true;
            self.session.account = {
                principal : self.getPrincipal(),
                realmName : self.realm.name
            };
            if(token.isRememberMe()){
                self.res.cookie('account', {
                    principal : self.getPrincipal(),
                    realmName : self.realm.name
                }, {
                    signed: self.secure
                });
            }
            callback();
        }
    });
};
/**
 * Logs out this Subject and invalidates and/or removes any associated entities 
 * and authorization data.
 */
Subject.prototype.logout = function(){
    this.account = null;
    this.authenticated = false;
    this.session.account = null;
    this.res.clearCookie('account');
};

exports.Subject = Subject;

/**
 * Class AccessControl
 */
var AccessControl = function(options){
    options = options || {};
    this.url = options.url || '/*';
    var methods = options.methods || ['*'];  // GET, POST, DELETE, PUT, *
    if('string' === typeof methods){
        this.methods = methods.split(',');
    }
    else if(methods instanceof Array){
        this.methods = methods;
    }
    this.authentication = options.authentication || 'ANONYMOUS'; // authentication method to use
    var rules = options.rules;
    if(utils.isDefined(rules)){
        this.rules = new AccessControlRules(rules);
    }
};

AccessControl.prototype.isApplicable = function(method, url){
    return utils.some(this.methods, function(it){
        return utils.isEqual(it.trim(), '*') || utils.isEqual(it.trim(), method);
    }) && utils.isEqual(this.url, url);
};

AccessControl.prototype.check = function(req, callback){
    callback = makeCallback(callback);
    if(utils.isEqual(this.authentication, 'ANONYMOUS')){
        callback(null, true);
    }
    else if(utils.isUndefined(this.rules)){
        callback(null, true);
    }
    else{
        var subject = req.subject;
        if(utils.isUndefined(subject) || !(subject instanceof Subject)){
            callback(null, false);
        }
        else{
            var principal = subject.getPrincipal();
            if(utils.isUndefined(principal)){
                callback(null, false);
            }
            else{
                // check rules
                this.rules.check(req, callback);
            }
        }
    }
};

/**
 * Class AccessControlList
 */
var AccessControlList = function(accessControls){
    this.accessControls = accessControls || [];
};

AccessControlList.prototype.store = function(accessControl){
    if(accessControl instanceof AccessControl){
        this.accessControls.push(accessControl);
    }
    else if('object' === typeof accessControl){
        this.accessControls.push(new AccessControl(accessControl));
    }
};

AccessControlList.prototype.lookup = function(req){
    var accessControl = null;
    var parts = url.parse(req.url).pathname.split('/');
    var search = parts.join('/');
    do {
        if(utils.some(this.accessControls, function(it){
            if(it.isApplicable(req.method, search)){
                accessControl = it;
                return true;
            }
            return false;
        })){
            break;
        }
        parts.pop();
        search = parts.join('/') + '/*';
    }while(!accessControl && parts.length > 0); 
    return accessControl;
};

exports.AccessControlList = AccessControlList;

/**
 * Class AccessControlRules
 */
var AccessControlRules = function(rules){
    if(utils.isUndefined(rules) 
        || utils.isNotEqual('string', typeof rules)){
        throw new Error('wrong rules');
    }

    var self = this;

    var splitRules = function(text) {

        text = text.trim();

        function indexOrEnd(character) {
            var index = text.indexOf(character);
            return index == -1 ? text.length : index;
        }

        function takeNormal() {
            var end = utils.reduce(Math.min, text.length,
                utils.map(indexOrEnd, [ '(', '[' ]));
            var part = text.slice(0, end);
            text = text.slice(end);
            return part.trim();
        }

        function takeUpTo(character, last) {
            var end = last ? text.lastIndexOf(character) : text.indexOf(character, 1);
            if (end == -1){
                throw new Error("Missing closing '" + character + "'");
            }
            var part = text.slice(1, end);
            text = text.slice(end + 1);
            return part.trim();
        }

        var parts = [];

        while (text != '') {
            if (text.charAt(0) == '(') {
                parts.push(new AccessControlRules(takeUpTo(')', true)));
            } else if(text.charAt(0) == '['){
                parts.push(new AccessControlRule(takeUpTo(']')));
            } else {
                var content = takeNormal();
                if(utils.isEqual('&&', content)){
                    self.type = 'every';
                }
                else if(utils.isEqual('||', content)){
                    self.type = 'some';
                }
            /*
                parts.push({
                    type : 'operator',
                    content : content
                });
                */
            }
        }
        return parts;
    };    

    this.type = 'every';
    this.rules = splitRules(rules);
};

AccessControlRules.prototype.check = function(req, callback){
    callback = makeCallback(callback);
    switch(this.type.toLowerCase()){
        case('some') :
            utils.someAsync(this.rules, function(next, rule){
                rule.check(req, function(err, value){
                    if(err){
                        next(false);
                    }
                    else{
                        next(value);
                    }
                });
            }, function(value){
                callback(null, value);
            });
            break;
        default :
            utils.everyAsync(this.rules, function(next, rule){
                rule.check(req, function(err, value){
                    if(err){
                        next(false);
                    }
                    else{
                        next(value);
                    }
                });
            }, function(value){
                callback(null, value);
            });
    }
};

/**
 * Class AccessControlRule
 */
var AccessControlRule = function(rule){
    if(utils.isUndefined(rule) 
        || utils.isNotEqual('string', typeof rule)){
        throw new Error('wrong rule');
    }

    var parts = rule.split('=');
                
    if(parts.length == 2){
        this.type = parts[0];
        var value = parts[1];
        switch(this.type.toLowerCase()){
            case('permission') :
                this.permission = new Permission(value);
                break;
            default :
                this.role = value;
                break;
        }
    }
    else{
        throw new Error('wrong rule');
    }
};

AccessControlRule.prototype.check = function(req, callback){
    callback = makeCallback(callback);
    switch(this.type.toLowerCase()){
        case('permission') :
            if(utils.isUndefined(this.permission)){
                callback(null, true);
            }
            this.permission.check(req, callback);
            break;
        default :
            var subject = req.subject;
            if(utils.isUndefined(subject) 
                || !(subject instanceof Subject) 
                || utils.isUndefined(this.role)){
                callback(null, false);
            }
            else{
                subject.hasRole(this.role, callback);
            }
    }
};

/**
 * Class Permission
 */
var Permission = function(permission){

    if(utils.isUndefined(permission) 
        || utils.isNotEqual('string', typeof permission)){
        throw new Error('wrong permission');
    }

    var splitText = function(text) {
        function indexOrEnd(character) {
            var index = text.indexOf(character);
            return index == -1 ? text.length : index;
        }

        function takeNormal() {
            var end = utils.reduce(Math.min, text.length,
                utils.map(indexOrEnd, [ '{' ]));
            var part = text.slice(0, end);
            text = text.slice(end);
            return part.trim();
        }

        function takeUpTo(character) {
            var end = text.indexOf(character, 1);
            if (end == -1)
                throw new Error("Missing closing '" + character + "'");
            var part = text.slice(1, end);
            text = text.slice(end + 1);
            return part.trim();
        }

        var parts = [];

        while (text != '') {
            if (text.charAt(0) == '{') {
                parts.push({
                    type : 'param',
                    content : takeUpTo('}')
                });
            } else {
                parts.push({
                    type : 'text',
                    content : takeNormal()
                });
            }
        }
        return parts;
    };

    this.parts = splitText(permission);
};

Permission.prototype.check = function(req, callback){
    callback = makeCallback(callback);
    var subject = req.subject;
    if(utils.isUndefined(subject) 
        || !(subject instanceof Subject)){
        callback(null, false);
    }
    else{
        var query = utils.parseQuery(req);
        var permission = '';
        utils.forEach(this.parts, function(part){
            switch(part.type.toLowerCase()){
                case('param'):
                    var value = query[part.content];
                    if(utils.isDefined(value)){
                        permission += value;
                    }
                    break;
                default :
                    permission += part.content;
                    break;
            }
        });
        subject.isPermitted(permission, callback);
    }
};