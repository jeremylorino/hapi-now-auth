"use strict";

/**
 * Reference for Hapi Docs - hapijs.com/api#authentication-scheme
 */

const JWT = require("jsonwebtoken");
const Boom = require("boom");
const Hoek = require("hoek");
const Joi = require("joi");

function verifyJWT(settings, token) {
    if (settings.verifyJWT && settings.keychain.length === 0) {
        throw settings.unauthorized(null, settings.tokenType);
    }

    if (settings.verifyJWT && token.split(".").length !== 3) {
        throw settings.unauthorized(null, settings.tokenType);
    }

    let decodedJWT = null,
        keysTried = 0;

    settings.keychain.some((k) => {

        try {
            ++keysTried;
            decodedJWT = JWT.verify(token, k, settings.verifyOptions);
            return true;
        } catch (error) {
            if (keysTried >= settings.keychain.length) {
                throw settings.unauthorized(null, settings.tokenType);
            }
            return false;
        }
    });

    return decodedJWT ? { decodedJWT, token } : token;
}

function getAuthorization(settings, request) {
    const d = new RegExp(settings.tokenType + "\\s+([^;$]+)", "i");
    let b = request.raw.req.headers.authorization;
    b || (settings.allowCookieToken && request.state[settings.accessTokenName] &&
        (b = settings.tokenType + " " + request.state[settings.accessTokenName]), settings.allowQueryToken && request.query[settings.accessTokenName] && (b = settings.tokenType + " " + request.query[settings.accessTokenName]));
    settings.allowMultipleHeaders && null !== b.match(d) && (b = b.match(d)[0]);

    if (!b) {
        throw settings.unauthorized(null, settings.tokenType);
    }
    return b;
}

function validateToken(settings, authorization) {
    const [tokenType, token] = authorization.split(/\s+/);

    if (!token || tokenType.toLowerCase() !== settings.tokenType.toLowerCase()) {
        throw settings.unauthorized(null, settings.tokenType);
    }

    // return [tokenType, token];
    return token;
}

const internals = {};

internals.defaults = {
    accessTokenName: "access_token",
    allowQueryToken: false,
    allowCookieToken: false,
    allowMultipleHeaders: false,
    allowChaining: false,
    tokenType: "Bearer",
    verifyJWT: false,
    keychain: [],
    verifyOptions: {
        algorithms: ["HS256"],
        ignoreExpiration: false
    },
    unauthorized: Boom.unauthorized
};

internals.schema = Joi.object().keys({
    accessTokenName: Joi.string().required(),
    allowQueryToken: Joi.boolean(),
    allowCookieToken: Joi.boolean(),
    allowMultipleHeaders: Joi.boolean(),
    allowChaining: Joi.boolean(),
    tokenType: Joi.string().required(),
    verifyJWT: Joi.boolean(),
    keychain: Joi.array().optional(),
    verifyOptions: Joi.object().keys({
        algorithms: Joi.array().optional(),
        audience: Joi.array().optional(),
        issuer: Joi.array().optional(),
        ignoreExpiration: Joi.boolean().optional(),
        ignoreNotBefore: Joi.boolean().optional(),
        subject: Joi.string().optional(),
        clockTolerance: Joi.number().optional(),
        maxAge: Joi.string().optional(),
        clockTimestamp: Joi.date().timestamp().optional()
    }).optional(),
    validate: Joi.func().required(),
    unauthorized: Joi.func()
});

internals.implementation = (server, options) => {

    Hoek.assert(options, "Missing bearer auth options");

    const settings = Hoek.applyToDefaults(internals.defaults, options);
    Joi.assert(settings, internals.schema);

    const scheme = {
        authenticate: async(request, h) => {
            const authorization = getAuthorization(settings, request);
            const token = validateToken(settings, authorization);
            const decodedJWT = verifyJWT(settings, token);
            const { isValid, credentials, artifacts } = await settings.validate(request, decodedJWT, h);

            if (!credentials || typeof credentials !== "object") {
                throw h.unauthorized(Boom.badImplementation("Bad token received from auth validation"), { credentials, artifacts });
            }

            if(isValid) {
                return h.authenticated({ credentials, artifacts });
            }

            const message = (settings.allowChaining && request.route.settings.auth.strategies.length > 1) ? null : "Bad token";
            return h.unauthenticated(settings.unauthorized(message, settings.tokenType), { credentials, artifacts });
        }
    };

    return scheme;
};

exports.plugin = {
    pkg: require("../package.json"),
    register: (server, options) => server.auth.scheme("hapi-now-auth", internals.implementation)
};
