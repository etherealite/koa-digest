
import url from 'url';

import crypto from 'crypto';


function md5(msg) {
    return crypto.createHash('md5').update(msg).digest('hex');
}


// Cruft for now, going to need this when the feature of following 401 a 
// issued challenge is implemented
const parse = (authbody) => {
    
    let a = authbody; 
    let authObj = {};
    let pat = /([^=,\s]*)\s*=\s*["'\s]?([^,"]+)["'\s]?/gi;
    
    if(!authbody) return;
    
    a.replace(pat, (match, key, value) => { authObj[key] = value; });
    return authObj;
    
};


const clientDigest = (auth) => {
    
    const compute = ( arr => {
        return md5(arr.join(':'));
    });

    const ha1 = compute([auth.username, auth.realm, auth.password]);
    const ha2 = compute([auth.method, auth.uri]);

    const response = compute([
        ha1,
        auth.nonce, auth.nc, auth.cnonce, auth.qop, 
        ha2
    ]);

    return response;
};


const clientAuthBody = (clientAuth) => {
  const a = clientAuth; 
  return `Digest username="${a.username}", realm="${a.realm}",`+
  `nonce="${a.nonce}", uri="${a.uri}", qop=${a.qop}, nc=${a.nc}, `+
  `cnonce="${a.cnonce}", response="${a.response}"`;
};


// HTTP-Digest 'plugin' for Superagent
function agentDigest(authorization) {

    const clientAuth = {
        username: authorization.username,
        password: authorization.password,
        realm: authorization.realm,
        nonce: 'xxx',
        cnonce: 'xxx',
        nc: '1',
        uri: '',
        method: '',
        qop: 'auth',
        response: ''
            
    };
    
    return function(request) {
        clientAuth.uri = url.parse(request.url).pathname;
        clientAuth.method = request.method.toUpperCase();
        clientAuth.response = clientDigest(clientAuth);
        const authBody = clientAuthBody(clientAuth);
        request.set('authorization', authBody);
        return request;
    };
}

export default agentDigest;