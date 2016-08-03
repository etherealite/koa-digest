'use strict';

export default middleware;

const crypto = require('crypto');
const IO = require('fantasy-io');
import R from 'ramda';
import Maybe from 'data.maybe'
import {compose} from 'ramda';
//import {compose} from 'fantasy-combinators';


function MD5(msg) {
    return crypto.createHash('md5').update(msg).digest('hex');
}


//const random16B = IO(() => crypto.randomBytes(16).toString('hex') );




const challenge = (credentials) => {
   const nonce = crypto.randomBytes(16).toString('hex');
   const realm = credentials.realm;
   const opaque = MD5(realm);
   return `Digest realm="${realm}",qop="auth",nonce=` +
        `"${nonce}",opaque="${opaque}"`;
};




// function verify(clientAuth, criteria) {
//     if(!clientAuth) {
//         return false;
//     }

//     const fromClient = parse(clientAuth);

//     const fromServer = Object.assign({}, fromClient, criteria);

//     const serverSig = solve(fromServer);
//     const clientSig = fromClient.response;

//     return clientSig === serverSig;
// }



const tap = x => {console.log(x); return x};

const pairFromMW = (clientHead, criteria) => IO(() => [clientHead, criteria]);

const doClient = f => pair => [f(pair[0]), pair[1]];
const doServer = f => pair => [pair[0], f(pair[1])];

const authParse = (authbody) => {

    let a = authbody;
    const authObj = {};
    const pat = /([^=,\s]*)\s*=\s*["'\s]?([^,"]+)["'\s]?/gi;

    a.replace(pat, (match, key, value) => { authObj[key] = value; });
    return authObj;

};


const solveChallenge = hashfunc => challenge => {
    const compute = arr => {
        return hashfunc(arr.join(':'));
    };
    const c = challenge;
    const ha1 = compute([c.username, c.realm, c.password]);
    const ha2 = compute([c.method, c.uri]);
    const response = compute([
        ha1,
        c.nonce, c.nc, c.cnonce, c.qop,
        ha2
        ]);

    return response;
};

const cheatOffClient = pair => {
    const client = pair[0];
    const criteria = pair[1];
    const serverChallenge = {
        username: criteria.username,
        realm: criteria.realm,
        password: criteria.password,
        method: criteria.method,
        uri: criteria.uri,
        nonce: client.nonce,
        nc: client.nc,
        cnonce: client.cnonce,
        qop: client.qop
    };

    return [client, serverChallenge];
};


const solverMD5 = solveChallenge(MD5);

const signaturesEqual = signatures => signatures[0] === signatures[1];


const verifyPair = compose(signaturesEqual,
    doServer(solverMD5), cheatOffClient, doClient(authParse));


function verify(clientHead, criteria) {
    return pairFromMW(clientHead, criteria).map(verifyPair).unsafePerform();
}



function middleware(credentials) {
    return async (ctx, next)  => {
        const request = ctx.request;
        const response = ctx.response;

        const clientHead = request.headers.authorization;

        const criteria = Object.assign({}, credentials);
        criteria.method = request.method;
        criteria.uri = request.url;

        const authorized = verify(clientHead, criteria);

        if(authorized) {
            await next();
        }
        else {
            response.set('www-authenticate', challenge(credentials));
            response.status = 401;
        }
    };
}