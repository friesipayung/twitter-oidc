import * as config from './config.json'
import {Hono} from 'hono'
import * as jose from 'jose'
import '@worker-tools/location-polyfill';

const passport = require('passport');
const TwitterStrategy = require('passport-twitter').Strategy;

const algorithm = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: 'SHA-256'},
}

const importAlgo = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: {name: 'SHA-256'},
}

async function loadOrGenerateKeyPair(KV) {
    let keyPair = {}
    let keyKV = config.kvKey || 'keys'
    let keyPairJson = await KV.get(keyKV, {type: 'json'})

    if (keyPairJson !== null) {
        keyPair.publicKey = await crypto.subtle.importKey('jwk', keyPairJson.publicKey, importAlgo, true, ['verify'])
        keyPair.privateKey = await crypto.subtle.importKey('jwk', keyPairJson.privateKey, importAlgo, true, ['sign'])

        return keyPair
    } else {
        keyPair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])

        await KV.put(keyKV, JSON.stringify({
            privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
            publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey)
        }))

        return keyPair
    }

}

passport.use('twitter', new TwitterStrategy({
    consumerKey: config.consumerKey,
    consumerSecret: config.consumerSecret,
    callbackURL: config.callbackURL,
}, ((accessToken, tokenSecret, profile, done) => {
    // Compose auths.
    const {id, username} = profile;
    const auths = {
        'name': username,
        'type': 'twitter',
        'ext_social_id': id,
        'ext_auths': [{
            'ext_type': 'TWITTER_OAUTH',
            'content': {
                'access_token': accessToken,
                'access_token_secret': tokenSecret,
            }
        }],
    };

    const data = {
        auths,
    };

    return done(null, data);
})));


function configureRedirect(req) {
    req.session.redirect = req.query.redirect;
}

function authenticate(strategy, options) {
    return (req, res, next) => {
        configureRedirect(req);
        const authenticator = passport.authenticate(strategy, options);

        authenticator(req, res, next);
    };
}

const app = new Hono()

app.get('/authorize/:scopemode', async (c) => {
    // todo
    authenticate('twitter', {
        failureRedirect: '/',
    })

    return c.json({error: 'not implemented'})
})

app.post('/token', async (c) => {
    // todo
    return c.json({error: 'not implemented'})

})

app.get('/userinfo', async (c) => {
    // todo
    return c.json({error: 'not implemented'})

})

app.get('/jwks.json', async (c) => {
    let publicKey = (await loadOrGenerateKeyPair(c.env.KV)).publicKey
    return c.json({
        keys: [{
            alg: 'RS256',
            kid: 'jwtRS256',
            ...(await crypto.subtle.exportKey('jwk', publicKey))
        }]
    })
})

app.get('/.well-known/openid-configuration', async (c) => {
    return c.json({
        "issuer": config.issuerURL,
        "authorization_endpoint": config.issuerURL + "/authorize/guilds",
        "token_endpoint": config.issuerURL + "/token",
        "userinfo_endpoint": config.issuerURL + "/userinfo",
        "jwks_uri": config.issuerURL + "/jwks.json",
        "response_types_supported": [
            "code",
            "code id_token",
            "id_token",
            "token id_token"
        ],
        "subject_types_supported": [
            "public"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256"
        ],
        "userinfo_signing_alg_values_supported": [
            "none"
        ],
        "request_object_signing_alg_values_supported": [
            "none"
        ],
        "scopes_supported": [
            "identify",
            "email",
            "guilds"
        ],
        "token_endpoint_auth_methods_supported": [
            'client_secret_basic',
            'private_key_jwt'
        ],
        "token_endpoint_auth_signing_alg_values_supported": ['RS256'],
        "claims_supported": [
            "id",
            "email",
            "username",
            "guilds",
            "preferred_username",
            "avatar",
            "iss",
            "aud",
            "sub",
            "iat"
        ],
        "code_challenge_methods_supported": [
            "plain",
            "S256"
        ],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
        ],
        "display_values_supported": [
            "page",
            "popup"
        ]
    })
})

export default app