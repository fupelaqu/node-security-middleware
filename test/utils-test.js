/* 
 * unit tests for utils library
 */

var utils = require('../lib/utils.js');

exports['test utils#isUndefined'] = function(beforeExit, assert) {
    var s = undefined;
    assert.equal(true, utils.isUndefined(s));
};

exports['test utils#isDefined'] = function(beforeExit, assert) {
    var s = 'string';
    assert.equal(true, utils.isDefined(s));
};

exports['test utils#isEqual'] = function(beforeExit, assert) {
    assert.equal(true, utils.isEqual('string', 'string'));
    assert.equal(true, utils.isEqual(utils.sum([ 1, 2, 3, 4 ]), 10));
    assert.equal(true, utils.isEqual([ 1, 2, 3, 4, 5 ], [ 1, 2, 3, 4, 5 ]));
    assert.equal(true, utils.isEqual({
        p1 : 'value1',
        p2 : 'value2'
    }, {
        p1 : 'value1',
        p2 : 'value2'
    }));
    assert.equal(true, utils.isEqual({
        p1 : 'value1',
        p2 : 'value2',
        p3 : [ 1, 2, 3, 4, 5 ]
    }, {
        p1 : 'value1',
        p2 : 'value2',
        p3 : [ 1, 2, 3, 4, 5 ]
    }));
};

exports['test utils#isNotEqual'] = function(beforeExit, assert) {
    assert.equal(true, utils.isNotEqual('string', 'test'));

    assert.equal(true, utils.isNotEqual('a', 'b'));

    assert.equal(true, utils
            .isNotEqual([ 1, 2, 3, 4, 5 ], [ 1, 2, 3, 4, 5, 6 ]));

    assert
            .equal(true, utils.isNotEqual([ 1, 2, 3, 4, 5 ],
                    [ 1, 2, 3, 4, '5' ]));

    assert.equal(true, utils.isNotEqual({
        p1 : 'value1',
        p2 : 'value2'
    }, {
        p1 : 'value1',
        p2 : 'value2',
        p3 : 3
    }));

    assert.equal(true, utils.isNotEqual({
        p1 : 'value1',
        p2 : 'value2',
        p3 : [ 1, 2, 3, 4, 5 ]
    }, {
        p1 : 'value1',
        p2 : 'value2',
        p3 : [ 1, 2, 3, 4, 5, 6 ]
    }));
};

exports['test utils#isNumber'] = function(beforeExit, assert) {
    assert.equal(true, utils.isNumber(2));
    assert.equal(true, utils.isNumber('2'));
    assert.equal(false, utils.isNumber('b'));
};

exports['test utils#forEach'] = function(beforeExit, assert) {
    var a = [1, 2, 3, 4, 5];
    var b = null;
    utils.forEach(a, function(e){
        b = e;
        if(utils.isEqual(3, e)){
            return false;
        }
    });
    assert.equal(3, b);
    utils.forEach({
        p1 : 'value1',
        p2 : 'value2',
        p3 : [ 1, 2, 3, 4, 5 ]
    }, function(name, value){
        b = value;
        if(utils.isEqual(name, 'p3')){
            utils.forEach(value, function(e){
                b = e;
                if(utils.isEqual(4, e)){
                    return false;
                }
            });
        }
    });
    assert.equal(4, b);
};

exports['test utils#some'] = function(beforeExit, assert) {
    var a = [1, 2, 3, 4, 5];
    assert.equal(true, utils.some(a, function(e){
        if(utils.isEqual(3, e)){
            return true;
        }
        return false;
    }));
};

exports['test utils#every'] = function(beforeExit, assert) {
    assert.equal(true, utils.every([1, 2, 3, 4, 5], function(e){
        if(utils.isNumber(e)){
            return true;
        }
        return false;
    }));
    assert.equal(true, utils.every([1, '2', 3, 4, 5], function(e){
        if(utils.isNumber(e)){
            return true;
        }
        return false;
    }));
    assert.equal(false, utils.every([1, 'b', 3, 4, 5], function(e){
        if(utils.isNumber(e)){
            return true;
        }
        return false;
    }));
};

exports['test utils#forEachAsync'] = function(beforeExit, assert) {
    utils.forEachAsync([ '1', '2', '3', '4', '5', '6' ], function(next, arg) {
        var delay = Math.floor(Math.random() * 5 + 1) * 100; // random ms
        console.log('forEachAsync1 with \''+arg+'\', return in ' + delay + 'ms');
        var ret = utils.isEqual('5', arg) ? false : arg;
        setTimeout(function() {
            next(ret);
        }, delay);
    }, function(value) {
        assert.equal(false, value);
    });
    utils.forEachAsync([ '1', '2', '3', '4', '5', '6' ], function(next, arg) {
        var delay = Math.floor(Math.random() * 5 + 1) * 100; // random ms
        console.log('forEachAsync2 with \''+arg+'\', return in ' + delay + 'ms');
        setTimeout(function() {
            next(arg);
        }, delay);
    }, function(value) {
        assert.equal('6', value);
    });
};

exports['test utils#everyAsync'] = function(beforeExit, assert) {
    utils.everyAsync([ '1', '2', '3', '4', '5', '6' ], function(next, arg) {
        var delay = Math.floor(Math.random() * 5 + 1) * 100; // random ms
        console.log('everyAsync1 with \''+arg+'\', return in ' + delay + 'ms');
        var ret = utils.isEqual('5', arg) ? false : true;
        setTimeout(function() {
            next(ret);
        }, delay);
    }, function(value) {
        assert.equal(false, value);
    });
    utils.everyAsync([ '1', '2', '3', '4', '5', '6' ], function(next, arg) {
        var delay = Math.floor(Math.random() * 5 + 1) * 100; // random ms
        console.log('everyAsync2 with \''+arg+'\', return in ' + delay + 'ms');
        setTimeout(function() {
            next(true);
        }, delay);
    }, function(value) {
        assert.equal(true, value);
    });
};

exports['test utils#someAsync'] = function(beforeExit, assert) {
    utils.someAsync([ '1', '2', '3', '4', '5', '6' ], function(next, arg) {
        var delay = Math.floor(Math.random() * 5 + 1) * 100; // random ms
        console.log('someAsync1 with \''+arg+'\', return in ' + delay + 'ms');
        var ret = utils.isEqual('a', arg);
        setTimeout(function() {
            next(ret);
        }, delay);
    }, function(value) {
        assert.equal(false, value);
    });
    utils.someAsync([ '1', '2', '3', '4', '5', '6' ], function(next, arg) {
        var delay = Math.floor(Math.random() * 5 + 1) * 100; // random ms
        console.log('someAsync2 with \''+arg+'\', return in ' + delay + 'ms');
        var ret = utils.isEqual('5', arg);
        setTimeout(function() {
            next(ret);
        }, delay);
    }, function(value) {
        assert.equal(true, value);
    });
};
