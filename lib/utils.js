/* 
 * utils functions.
 */

var url = require('url')
, qs = require('querystring');

var asArray = function(args, start) {
    var result = [];
    for ( var i = (start || 0); i < args.length; i++){
        result.push(args[i]);
    }
    return result;
}

exports.asArray = asArray;

/**
 * forEach executes the provided function (callback) once for each element 
 * present in the array or each property present in the object until it finds 
 * one where callback returns a false value.
 */
var forEach = function(obj, callback) {
    var fixedArgs = asArray(arguments, 2);
    if(obj instanceof Array){
        var copy = [].concat(obj);
        for ( var i = 0; i < obj.length; i++) {
            if(callback.apply(null, [ obj[i], i, copy ].concat(fixedArgs)) === false){
                break;
            }
        }
    }
    else if (typeof obj === 'object'){
        for ( var property in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, property)
                && Object.prototype.propertyIsEnumerable.call(obj,
                    property))
                if(callback.apply(null, [ property, obj[property] ]
                    .concat(fixedArgs)) === false){
                    break;
                }
        }
    }
};

exports.forEach = forEach;

/**
 * every executes the provided callback function once for each element present 
 * in the array or each property present in the object until it finds one where 
 * callback returns a false value. 
 * If such an element is found, the every method immediately returns false. 
 * Otherwise, if callback returned a true value for all elements, every will return true. 
 */
var every = function(obj, callback) {
    var fixedArgs = asArray(arguments, 2);
    if(obj instanceof Array){
        var copy = [].concat(obj);
        for ( var i = 0; i < obj.length; i++) {
            if(callback.apply(null, [ obj[i], i, copy ].concat(fixedArgs)) === false){
                return false;
            }
        }
    }
    else if (typeof obj === 'object'){
        for ( var property in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, property)
                && Object.prototype.propertyIsEnumerable.call(obj,
                    property))
                if(callback.apply(null, [ property, obj[property] ]
                    .concat(fixedArgs)) === false){
                    return false;
                }
        }
    }
    return true;
}

exports.every = every;

/**
 * some executes the callback function once for each element present in the 
 * array or each property present in the object until it finds one where 
 * callback returns a true value. 
 * If such an element is found, some immediately returns true. 
 * Otherwise, some returns false. 
 */
var some = function(obj, callback){
    var fixedArgs = asArray(arguments, 2);
    if(obj instanceof Array){
        var copy = [].concat(obj);
        for ( var i = 0; i < obj.length; i++) {
            if(callback.apply(null, [ obj[i], i, copy ].concat(fixedArgs)) === true){
                return true;
            }
        }
    }
    else if (typeof obj === 'object'){
        for ( var property in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, property)
                && Object.prototype.propertyIsEnumerable.call(obj,
                    property))
                if(callback.apply(null, [ property, obj[property] ]
                    .concat(fixedArgs)) === true){
                    return true;
                }
        }
    }
    return false;    
};

exports.some = some;

var reduce = function(func, base, array) {
    forEach(array, function(element) {
        base = func(base, element);
    });
    return base;
};

exports.reduce = reduce;

var map = function(func, array) {
    var result = [];
    forEach(array, function(element) {
        result.push(func(element));
    });
    return result;
};

exports.map = map;

var copy = function(target, source) {
    forEach(source, function(name, value) {
        target[name] = value;
    });
    return target;
}

exports.copy = copy;

var partial = function(func) {
    var fixedArgs = asArray(arguments, 1);
    return function() {
        return func.apply(null, fixedArgs.concat(asArray(arguments)));
    };
}

exports.partial = partial;

var compose = function(func1, func2) {
    return function() {
        return func1(func2.apply(null, arguments));
    };
}

exports.compose = compose;

var op = {
    '===' : function(a, b) {
        if(isUndefined(a) || isUndefined(b)){
            return false;
        }
        if(a === b) {
            return true;
        }
        if(a.constructor !== b.constructor) {
            return false;
        }
        if(a instanceof Array){
            if(a.length !== b.length) {
                return false;
            }
            return every(a, function(element, i){
                if(typeof element === 'object' 
                    && typeof b[i] === 'object'){
                    if(isNotEqual(element, b[i])) {
                        return false;
                    }
                }
                else if(element !== b[i]) {
                    return false;
                }
                return true;
            });
        }
        else if (typeof a === 'object'){
            var objListCounter = 0;
            if(!every(a, function(property, value){
                objListCounter++;
                if(isUndefined(b[property])){
                    return false;
                }
                if(isNotEqual(value, b[property])) {
                    return false;
                }
                return true;
            })) {
                return false;
            }
            var refListCounter = 0;
            forEach(b, function(){
                refListCounter++;
            });
            if(objListCounter !== refListCounter) {
                return false;
            }
        }
        else{
            // console.log(typeof a);
            return false;
        }
        return true; //Every object and array is equal
    },
    '==' : function(a, b) {
        return a == b;
    },
    '!' : function(a) {
        return !a;
    }
};

var sum = function(a){
    var ret = 0;
    forEach(a, function(e){
        ret += e;
    });
    return ret;
}

exports.sum = sum;

var isNumber = compose(op["!"], isNaN);

exports.isNumber = isNumber;

var isUndefined = partial(op["=="], undefined);

exports.isUndefined = isUndefined;

var isDefined = compose(op["!"], isUndefined);

exports.isDefined = isDefined;

var isEqual = partial(op['===']);

exports.isEqual = isEqual;

var isNotEqual = compose(op["!"], isEqual);

exports.isNotEqual = isNotEqual;

var toCharArray = function(s){
    var ret = null;
    if(isDefined(s) && typeof s === 'string'){
        ret = s.split('');
    }
    return ret;
};

exports.toCharArray = toCharArray;

var stringToBytes = function ( str ) {
    var ch, st, re = [];
    for (var i = 0; i < str.length; i++ ) {
        ch = str.charCodeAt(i);  // get char 
        st = [];                 // set up "stack"
        do {
            st.push( ch & 0xFF );  // push byte to stack
            ch = ch >> 8;          // shift value down by 1 byte
        }  
        while ( ch );
        // add stack contents to result
        // done because chars have "wrong" endianness
        re = re.concat( st.reverse() );
    }
    // return an array of bytes
    return re;
};

exports.stringToBytes = stringToBytes;

var parseQuery = function(req){
    var query = {};
    if(req.method == 'POST'){
        if(isDefined(req.body)){
            query = req.body;
        }
        else{
            var body = '';
            req.on('data', function (data) {
                body += data;
                if (body.length > 1e6) {
                    // FLOOD ATTACK OR FAULTY CLIENT, NUKE REQUEST
                    req.connection.destroy();
                }
            });
            req.on('end', function () {
                query = qs.parse(body);
            });
        }
    }
    else{
        query = url.parse(req.url, true).query;
    }
    return query;
};

exports.parseQuery = parseQuery;

/***
 * return true if the object obj implements the interface i
 */
var implementsInterface = function(obj, i)
{ 
    return every(i, function(property, value){
        return isdefined(obj[property]) && typeof obj[property] === value;
    });
};

// exports.implementsInterface = implementsInterface;