/*!
 * security - middleware
 *
 */

var utils = require('./utils.js')
, security = require('./security.js')
, url = require('url')
, http = require('http')
, connectUtils = require('connect/lib/utils');

/**
 * Return Connect middleware with the given `options`.
 *
 * Options:
 *
 *  `rememberMe` - whether a cookie will be set after authentication or not - default value : false
 *
 *  `secure` - whether to use secured cookies or not
 *  
 *  `loginUrl` - url used by the application to sign in - default value : /login 
 *
 *  `usernameParam` - name of the username parameter which will be used during form authentication  - default value : username 
 *
 *  `passwordParam` - name of the password parameter which will be used during form authentication - default value : password 
 *
 *  `logoutUrl` - url used by the application to sign out - default value : /logout
 *
 *  `store` - store which will be used to retrieve user information
 *
 *  `realm` - name of the realm
 *
 *  `acl` - access control list - array of access controls to apply per url
 *
 * Examples:
 *
 *
 * @param {Object} options
 * @return {Function}
 * @api public
 */
module.exports = security.middleware = function(options){

    options = options || {};

    var debug = options.debug || false;

    var secure = options.secure || false;

    var rememberMe = options.rememberMe || false;

    var loginUrl = options.loginUrl || '/login';
    var usernameParam = options.usernameParam || 'username';
    var passwordParam = options.passwordParam || 'password';
    var logoutUrl = options.logoutUrl || '/logout';

    var realm = new security.Realm({
        store : options.store || security.inMemoryStore,
        realmName : options.realmName || 'Authorization Required',
        credentialsMatcher : options.credentialsMatcher || security.simpleCredentialsMatcher
    });

    if(debug){
        console.log(realm);
    }

    var acl = new security.AccessControlList();
    if(utils.isDefined(options.acl) && options.acl instanceof Array){
        utils.forEach(options.acl, function(accessControl){
            acl.store(accessControl);
        });
    }

    if(debug){
        console.log(acl);
    }

    var retrieveSubject = function(req){
        var subject = req.subject || new security.Subject(realm, req, secure);
        req.subject = subject;
        return subject;
    };

    // Middleware
    return function(req, res, next) {

        var pathname = url.parse(req.url).pathname;

        var query = utils.parseQuery(req);

        if(utils.isEqual(pathname, loginUrl)){
            var subject = retrieveSubject(req);
            var username = query[usernameParam]
            , password = query[passwordParam]
            , redirect = query['redirect'];
            if(utils.isDefined(username) && utils.isDefined(password)){
                try{
                    subject.login(new security.UsernamePasswordToken(username, password, rememberMe));
                    if(rememberMe){
                        res.cookie('account', {
                            principal:subject.getPrincipal(),
                            realm : realm.name
                        }, {
                            signed: secure
                        });
                    }
                    if(utils.isDefined(redirect)){
                        return res.redirect(redirect);
                    }
                    else{
                        return next();
                    }
                }
                catch(e){
                    console.error(e);
                    redirect = redirect || '';
                    return res.redirect(loginUrl 
                        + "?redirect="+encodeURIComponent(redirect)
                        + "&" + usernameParam + "=" + username);
                }
            }
            else{
                return next();
            }
        }
        else if(utils.isEqual(pathname, logoutUrl)){
            retrieveSubject(req).logout();
            res.clearCookie('account');
            var redirect = query['redirect'] || '/';
            res.redirect(redirect);
        }
        else{
            var accessControl = acl.lookup(req);

            if(utils.isUndefined(accessControl)){
                return next();
            }
            else{
                var subject = retrieveSubject(req);
            
                var authenticated = utils.isDefined(subject.getPrincipal());

                var authentication = accessControl.authentication.toLowerCase();

                if(!authenticated){
                    // user not authenticated yet => perform authentication
                    switch(authentication){
                        case 'anonymous' :
                            authenticated = true;
                            break;
                        case 'basic':
                            var authorization = req.headers.authorization;
                            if (utils.isUndefined(authorization)) {
                                return connectUtils.unauthorized(res, realm.name);
                            }
                            else{
                                var parts = authorization.split(' ')
                                , scheme = parts[0]
                                , credentials = new Buffer(parts[1], 'base64').toString().split(':')
                                , username = credentials[0]
                                , password = credentials[1];
                                if ('Basic' != scheme) {
                                    return next(connectUtils.error(400));
                                }
                                try{
                                    subject.login(new security.UsernamePasswordToken(username, password));
                                    if(rememberMe){
                                        res.cookie('account', {
                                            principal:subject.getPrincipal(),
                                            realm : realm.name
                                        }, {
                                            signed: secure
                                        });
                                    }
                                    authenticated = true;
                                }
                                catch(e){
                                    console.error(e);
                                    return connectUtils.unauthorized(res, realm.name);
                                }
                            }
                            break;
                        case 'form' :
                            break;
                        default :
                            break;
                    }
                }

                // user authenticated => check access control
                if(authenticated && accessControl.check(req)){
                    if(debug){
                        console.log('user authenticated and authorized to access this ressource');
                    }
                    return next();
                }
                else{
                    if(debug){
                        console.log(
                            authenticated ? 'user authenticated but not authorized to access this ressource' 
                            : 'user not authenticated');
                    }
                    switch(authentication){
                        case 'basic' :
                            return connectUtils.unauthorized(res, realm.name);
                        case 'form' :
                            var username = query[usernameParam] || '';
                            var _url = loginUrl + '?' 
                            + usernameParam + "=" + username;
                            var redirect = pathname + '?';
                            var first = true;
                            utils.forEach(query, function(name, value){
                                redirect += (!first ? '&' : '') + name + "=" + value;
                                first = false;
                            });
                            return res.redirect(_url + '&redirect=' + encodeURIComponent(redirect));
                        default :
                            return next(connectUtils.error(400));
                    }
                }
            }
        }


    };
};
