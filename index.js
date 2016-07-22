'use strict';

module.exports = exports = middleWare;

const crypto = require('crypto');
const url = require('url');


function md5(msg) {
    return crypto.createHash('md5').update(msg).digest('hex');
}


function parse(authbody){
    
    let a = authbody; 
    let authObj = {};
    let pat = /([^=,\s]*)\s*=\s*["'\s]?([^,"]+)["'\s]?/gi;
    
    if(!authbody) return;
    
    a.replace(pat, (match, key, value) => { authObj[key] = value; });
    return authObj;

}


function middleWare(validation) {
    
    // seriously need to refactor these closures into a compositional approach
    
    
    const challenge = (function(hashfunc, validateby) {
       let realm = validateby.realm;
       return async function() {
           let opaque = hashfunc(realm);
           const random = await (crypto.randomBytes(16).toString('hex'));
           return `Digest realm="${realm}",qop="auth",nonce=`+
           `"${random}",opaque="${opaque}"`;
           
       };
    })(md5, validation);


    const digest = (function (hashfunc, validateby) {
        return function (auth, request) {
            let valid = validateby, ha1, ha2, response;
            
            request.pathname = url.parse(request.url).pathname;
            const compute = ( arr => {
                return hashfunc(arr.join(':'));
            });

            ha1 = compute([valid.username, valid.realm, valid.password]);
            ha2 = compute([request.method, request.pathname]);
            response = compute([
                ha1,
                auth.nonce, auth.nc, auth.cnonce, auth.qop, 
                ha2
                ]);
    
            return { ha1, ha2, response };
        };
    })(md5, validation);
    

    return async (ctx, next)  => {
          
        let response = ctx.response;
        let request = ctx.request;
        let authorization = parse(request.header.authorization);
        let authorized, server, client;

        if (authorization) {
            server = digest(authorization, request).response;
            client = authorization.response;
            authorized = ( client === server );
        }
        
        if (authorized) {
            await next();
        }
        else {
    
            response.set('WWW-Authenticate', await challenge());
            ctx.status = 401;
        }
    
    };
}

