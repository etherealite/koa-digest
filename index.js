'use strict';

module.exports = exports = middleware;

const crypto = require('crypto');
const IO = require('fantasy-io');


function hashfunc(msg) {
    return crypto.createHash('md5').update(msg).digest('hex');
}


const random16B = IO(() => crypto.randomBytes(16).toString('hex') );


function parse(authbody){

//console.log(authbody);
    let a = authbody;
    let authObj = {};
    let pat = /([^=,\s]*)\s*=\s*["'\s]?([^,"]+)["'\s]?/gi;

    a.replace(pat, (match, key, value) => { authObj[key] = value; });
    return authObj;

}


// seriously need to refactor closures into a compositional approach

const challenge = (credentials) => {
   const nonce = crypto.randomBytes(16).toString('hex');
   const realm = credentials.realm;
   const opaque = hashfunc(realm);
   return `Digest realm="${realm}",qop="auth",nonce=` +
        `"${nonce}",opaque="${opaque}"`;
};


const compute = ( arr => {
    return hashfunc(arr.join(':'));
});


function solve(challenge) {
    const c = challenge;
    const ha1 = compute([c.username, c.realm, c.password]);
    const ha2 = compute([c.method, c.uri]);
    const response = compute([
        ha1,
        c.nonce, c.nc, c.cnonce, c.qop,
        ha2
        ]);

    return response;
}


function verify(clientAuth, criteria) {
    if(!clientAuth) {
        return false;
    }

    const client = parse(clientAuth);

    const server = Object.assign({}, client, criteria);

    server.response = '';
    server.response = solve(server);

    return client.response === server.response;
}


function middleware(credentials) {
    return async (ctx, next)  => {
        const request = ctx.request;
        const response = ctx.response;

        const clientAuth = request.headers.authorization;

        const criteria = Object.assign({}, credentials);
        criteria.method = request.method;
        criteria.uri = request.url;

        const authorized = verify(clientAuth, criteria);

        if(authorized) {
            await next();
        }
        else {
            response.set('www-authenticate', challenge(credentials));
            response.status = 401;
        }
    };
}