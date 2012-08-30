/* 
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


var assert = require('assert')
, utils = require('../lib/utils.js');

assert.ok(utils.isUndefined(s));

var s = 'string';

assert.ok(utils.isDefined(s));
assert.ok(utils.isEqual(s, 'string'));
assert.ok(utils.isNotEqual(s, 'test'));

assert.ok(utils.isEqual(utils.sum([1, 2, 3, 4]), 10));

assert.ok(utils.isNotEqual('a', 'b'));

assert.ok(utils.isEqual([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]));

assert.ok(utils.isNotEqual([1, 2, 3, 4, 5], [1, 2, 3, 4, 5, 6]));

assert.ok(utils.isNotEqual([1, 2, 3, 4, 5], [1, 2, 3, 4, '5']));

assert.ok(utils.isEqual(
{
    p1:'value1', 
    p2:'value2'
}, 
{
    p1:'value1', 
    p2:'value2'
}));

assert.ok(utils.isNotEqual(
{
    p1:'value1', 
    p2:'value2'
}, 
{
    p1:'value1', 
    p2:'value2',
    p3:3
}));

assert.ok(utils.isEqual(
{
    p1:'value1', 
    p2:'value2', 
    p3:[1, 2, 3, 4, 5]
}, 
{
    p1:'value1', 
    p2:'value2',
    p3:[1, 2, 3, 4, 5]
}));

assert.ok(utils.isNotEqual(
{
    p1:'value1', 
    p2:'value2', 
    p3:[1, 2, 3, 4, 5]
}, 
{
    p1:'value1', 
    p2:'value2',
    p3:[1, 2, 3, 4, 5, 6]
}));

