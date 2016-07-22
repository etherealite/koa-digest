'use strict';
import test from 'ava';

import {parse} from './_helpers.js';

import {buildResponse} from './_helpers.js';

import crypto from 'crypto';


const validation = { 
    username: 'garloth', password: 'swingsword',
    realm: 'dungeon'
};


// Client has not provided authorization field in request headers

test.beforeEach( async t => {
    const response = t.context.response = await buildResponse(null);
    const authString = t.context.authString = response.header['www-authenticate'];
    t.context.authObject = parse(authString);
});


test('Responds with status code 401', t => {
    const response = t.context.response;
    t.is(response.status, 401);
});

test('Prevents execution of downstream middleware', t => {
    const header = t.context.response.header;
    t.false(header.hasOwnProperty('fromdownstream'));
});

test('Provides an authenticate field in the response headers', t => {
    const response = t.context.response;
    t.true(response.header.hasOwnProperty('www-authenticate'));
});

test('First word of the authenticate field string is "Digest"', t => {
    t.is(t.context.authString.split(/[\s,]/)[0], 'Digest');
});

test('authenticate field\'s qop value is "auth"', t => {
   t.is(t.context.authObject.qop, 'auth'); 
});

test('authenticate field\'s realm value matches the validation realm', t => {
    const authObject = t.context.authObject;
    t.is(authObject.realm, validation.realm);
});

test('authenticate field\'s opaque is equal to the md5 sig of the realm', t => {
    const authObject = t.context.authObject;
    const realm = authObject.realm;
    const testOpaque = crypto.createHash('md5').update(realm).digest('hex');
    t.is(authObject.opaque, testOpaque);
});

test('authenticate field\'s nonce is a 32 char string', t => {
    const nonce = t.context.authObject.nonce;
    t.is(typeof nonce, 'string');
    t.is(nonce.length, 32);
});

test('Athenticate field\'s nonce value is unique to each call', async t => {
    const nonce = t.context.authObject.nonce;
    const testResponse = await buildResponse(null);
    const testAuthString = testResponse.header['www-authenticate'];
    const testAuthObject = parse(testAuthString);
    const testNonce = testAuthObject.nonce;
    t.not(nonce, testNonce);
});