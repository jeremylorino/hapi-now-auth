"use strict";

/**
 * Reference for Hapi Docs - hapijs.com/api#authentication-scheme
 */

const JWT = require("jsonwebtoken");
const Boom = require("boom");
const Hoek = require("hoek");
const Joi = require("joi");

function verifyJWT(settings, token) {
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

    return decodedJWT;
}

/*function getAuthorization(settings, request) {
    const headerRegExp = new RegExp(settings.tokenType + "\\s+([^;$]+)", "i");
    let authorization = request.raw.req.headers.authorization;

    if (!authorization) {

        if (settings.allowCookieToken && request.state[settings.accessTokenName]) {
            authorization = `${settings.tokenType} ${request.state[settings.accessTokenName]}`;
        }

        if (settings.allowQueryToken && request.query[settings.accessTokenName]) {

            authorization = `${settings.tokenType} ${request.query[settings.accessTokenName]}`;
        }
    }

    if (settings.allowMultipleHeaders && authorization.match(headerRegExp) !== null) {
        authorization = authorization.match(headerRegExp)[0];
    }

    return authorization;
}*/
function getAuthorization(a, c) {
    const d = new RegExp(a.tokenType + "\\s+([^;$]+)", "i");
    let b = c.raw.req.headers.authorization;
    b || (a.allowCookieToken && c.state[a.accessTokenName] &&
        (b = a.tokenType + " " + c.state[a.accessTokenName]), a.allowQueryToken && c.query[a.accessTokenName] && (b = a.tokenType + " " + c.query[a.accessTokenName]));
    a.allowMultipleHeaders && null !== b.match(d) && (b = b.match(d)[0]);
    return b;
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

            let authorization = getAuthorization(settings, request);

            if (!authorization) {
                return settings.unauthorized(null, settings.tokenType);
            }

            const [tokenType, token] = authorization.split(/\s+/);

            if (!token || tokenType.toLowerCase() !== settings.tokenType.toLowerCase()) {
                throw settings.unauthorized(null, settings.tokenType);
            }

            let decodedJWT;
            if (settings.verifyJWT) {
                if (settings.keychain.length === 0) {
                    return settings.unauthorized(null, settings.tokenType);
                }

                if (token.split(".").length !== 3) {
                    return settings.unauthorized(null, settings.tokenType);
                }

                decodedJWT = verifyJWT(settings, token);
            }

            const { isValid, credentials, artifacts } = await settings.validate(request, decodedJWT ? { decodedJWT, token } : token, h);

            if (!isValid) {
                const message = (settings.allowChaining && request.route.settings.auth.strategies.length > 1) ? null : "Bad token";
                return h.unauthenticated(settings.unauthorized(message, settings.tokenType), { credentials, artifacts });
            }

            if (!credentials || typeof credentials !== "object") {
                throw h.unauthorized(Boom.badImplementation("Bad token received from auth validation"), { credentials, artifacts });
            }

            return h.authenticated({ credentials, artifacts });
        }
    };

    return scheme;
};

exports.plugin = {
    pkg: require("../package.json"),
    register: (server, options) => server.auth.scheme("hapi-now-auth", internals.implementation)
};
