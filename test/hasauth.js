'use strict';

import test from 'ava';

import {buildResponse, credentialsDefault} from './_helpers';



// With valid credentials
test('valid credentials allow execution of downstream middleware', async t => {
    const response = await buildResponse();
    const header = response.header;
    t.true(header.hasOwnProperty('fromdownstream'));
});

test('valid credentials do not effect status code', async t => {
    const sets302 = async (ctx, next) => {
        ctx.status = 302;
        await next();
    };
    const credentials = credentialsDefault;
    
    const response = await buildResponse(credentials, {middleware: sets302});
    t.is(response.status, 302);
});

test('valid credentials authenticate POST requests', async t => {
    const response = await buildResponse(credentialsDefault, {method: 'POST'});
    t.is(response.status, 200);
});

test('valid credentials authenticate PUT requests', async t => {
    const response = await buildResponse(credentialsDefault, {method: 'PUT'});
    t.is(response.status, 200);
});

test('valid credentials authenticate DELETE requests', async t => {
    const response = await buildResponse(credentialsDefault, {method: 'DELETE'});
    t.is(response.status, 200);
});

test('valid credentials authenticate requests with query params', async t => {
    // A bit of a cheat since query params are removed
    const response = await buildResponse(credentialsDefault, {
        path: '/IHaveSomeParams?yes=with&more=params'
    });
    t.is(response.status, 200);
});


// With invalid credentials

const invalidUser = Object
    .assign({}, credentialsDefault, {username: 'notgarloth'});

test('Username invalid stops down stream middleware execution', async t => {
    const response = await buildResponse(invalidUser);
    t.false(response.header.hasOwnProperty('fromdownstream'));
});

test('Username invalid results in 401 status', async t => {
    const response = await buildResponse(invalidUser);
    t.is(response.status, 401);
});


const invalidPass = Object
    .assign({}, credentialsDefault, {password: 'swingwut?'});

test('Password invalid stops down stream middleware execution', async t => {
    const response = await buildResponse(invalidPass);
    t.false(response.header.hasOwnProperty('fromdownstream'));
});

test('Password invalid results in 401 status', async t => {
    const response = await buildResponse(invalidPass);
    t.is(response.status, 401);
});

const invalidRealm = Object
    .assign({}, credentialsDefault, {realm: 'isnotvalid'});

test('Realm invalid stops down stream middlewaree execution', async t => {
    const response = await buildResponse(invalidRealm);
    t.false(response.header.hasOwnProperty('fromdownstream'));
});

test('Realm invalid results in 401 status', async t => {
    const response = await buildResponse(invalidRealm);
    t.is(response.status, 401);
});


// Superagent is probably cleaning input to it's set headers function.
// Can't test permutations of quotes where cleansing is happening

test('escaped quotes can be in credentials', async t => {
    // single quotes are auto backslash escaped by Superagent
    const newCredentials = Object
        .assign({}, credentialsDefault, {username: "I_likes\'s the ring\'"});
    const newValidation = Object.assign({}, newCredentials);

    const ops = { validation: newValidation };
    const response = await buildResponse(newCredentials, ops);
    t.is(response.status, 200);
});

test('double quotes can be in credentials', async t => {
    // all backslashes added here will be escaped by Superagent
    const newCredentials = Object
        .assign({}, credentialsDefault, {username: 'air""quotes"'});
    const newValidation = Object.assign({}, newCredentials);

    const ops = { validation: newValidation };
    const response = await buildResponse(newCredentials, ops);
    t.is(response.status, 200);
});

test('commas can be in credentials', async t => {
    const newCredentials = Object
        .assign({}, credentialsDefault, {username: ',more, commas, plux,'});
    const newValidation = Object.assign({}, newCredentials);

    const ops = { validation: newValidation };
    const response = await buildResponse(newCredentials, ops);
    t.is(response.status, 200);
});