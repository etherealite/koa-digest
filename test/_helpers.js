
import koa from 'koa';

import koaDigest from '../index.js';

import request from 'supertest-as-promised';

import agentDigest from './_agent.js';


const parse = (authbody) => {
    
    let a = authbody; 
    let authObj = {};
    let pat = /([^=,\s]*)\s*=\s*["'\s]?([^,"]+)["'\s]?/gi;
    
    if(!authbody) return;
    
    a.replace(pat, (match, key, value) => { authObj[key] = value; });
    return authObj;
};


// server side authentication records
const validationDefault = { 
    username: 'garloth', password: 'swingsword',
    realm: 'dungeon'
};
// client side authentication credentials
const credentialsDefault = Object.assign({}, validationDefault);

// Default down stream middleware
const downstream = async (ctx, next) => {
    ctx.response
    .set('fromdownstream', 'This was set by downstream middleware');
    
    ctx.body = 'Hi from downstream middlware';
    await next();
};

const buildResponse = (creds=credentialsDefault, kargs={}) => {
    const {middleware: middleware=downstream} = kargs;
    const {validation: validateby=validationDefault} = kargs;
    const {path: path='/'} = kargs;
    const {method: method='GET'} = kargs;
    
    const app = new koa();
    app.use(koaDigest(validateby));
    app.use(middleware);
    
    const req = request(app.listen())[method.toLowerCase()](path); //.get(uri)
    
    return creds ? req.use(agentDigest(creds)) : req;
};


export { 
    parse,
    buildResponse,
    validationDefault,
    credentialsDefault
};