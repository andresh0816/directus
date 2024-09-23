import { useEnv } from '@directus/env';
import { ErrorCode, InvalidCredentialsError, InvalidPayloadError, isDirectusError } from '@directus/errors';
import type { Accountability } from '@directus/types';
import type { Request } from 'express';
import { Router } from 'express';
import {
	createLDAPAuthRouter,
	createLocalAuthRouter,
	createOAuth2AuthRouter,
	createOpenIDAuthRouter,
	createSAMLAuthRouter,
} from '../auth/drivers/index.js';
import { DEFAULT_AUTH_PROVIDER, REFRESH_COOKIE_OPTIONS, SESSION_COOKIE_OPTIONS } from '../constants.js';
import { useLogger } from '../logger/index.js';
import { respond } from '../middleware/respond.js';
import { createDefaultAccountability } from '../permissions/utils/create-default-accountability.js';
import { AuthenticationService } from '../services/authentication.js';
import { UsersService } from '../services/users.js';
import type { AuthenticationMode } from '../types/auth.js';
import asyncHandler from '../utils/async-handler.js';
import { getAuthProviders } from '../utils/get-auth-providers.js';
import { getIPFromReq } from '../utils/get-ip-from-req.js';
import { getSecret } from '../utils/get-secret.js';
import isDirectusJWT from '../utils/is-directus-jwt.js';
import { verifyAccessJWT } from '../utils/jwt.js';
import { toArray } from '@directus/utils';
import jwt from 'jsonwebtoken';

const router = Router();
const env = useEnv();
const logger = useLogger();

const authProviders = getAuthProviders();

for (const authProvider of authProviders) {
	let authRouter: Router | undefined;

	switch (authProvider.driver) {
		case 'local':
			authRouter = createLocalAuthRouter(authProvider.name);
			break;

		case 'oauth2':
			authRouter = createOAuth2AuthRouter(authProvider.name);
			break;

		case 'openid':
			authRouter = createOpenIDAuthRouter(authProvider.name);
			break;

		case 'ldap':
			authRouter = createLDAPAuthRouter(authProvider.name);
			break;

		case 'saml':
			authRouter = createSAMLAuthRouter(authProvider.name);
			break;
	}

	if (!authRouter) {
		logger.warn(`Couldn't create login router for auth provider "${authProvider.name}"`);
		continue;
	}

	router.use(`/login/${authProvider.name}`, authRouter);
}

if (!env['AUTH_DISABLE_DEFAULT']) {
	router.use('/login', createLocalAuthRouter(DEFAULT_AUTH_PROVIDER));
}

function getCurrentMode(req: Request): AuthenticationMode {
	if (req.body.mode) {
		return req.body.mode as AuthenticationMode;
	}

	if (req.body.refresh_token) {
		return 'json';
	}

	return 'cookie';
}

function getCurrentRefreshToken(req: Request, mode: AuthenticationMode): string | undefined {
	if (mode === 'json') {
		return req.body.refresh_token;
	}

	if (mode === 'cookie') {
		return req.cookies[env['REFRESH_TOKEN_COOKIE_NAME'] as string];
	}

	if (mode === 'session') {
		const token = req.cookies[env['SESSION_COOKIE_NAME'] as string];

		if (isDirectusJWT(token)) {
			const payload = verifyAccessJWT(token, getSecret());
			return payload.session;
		}
	}

	return undefined;
}

router.post(
	'/refresh',
	asyncHandler(async (req, res, next) => {
		const accountability: Accountability = createDefaultAccountability({ ip: getIPFromReq(req) });

		const userAgent = req.get('user-agent')?.substring(0, 1024);
		if (userAgent) accountability.userAgent = userAgent;

		const origin = req.get('origin');
		if (origin) accountability.origin = origin;

		const authenticationService = new AuthenticationService({
			accountability: accountability,
			schema: req.schema,
		});

		const mode = getCurrentMode(req);
		const currentRefreshToken = getCurrentRefreshToken(req, mode);

		if (!currentRefreshToken) {
			throw new InvalidPayloadError({
				reason: `The refresh token is required in either the payload or cookie`,
			});
		}

		const { accessToken, refreshToken, expires } = await authenticationService.refresh(currentRefreshToken, {
			session: mode === 'session',
		});

		const payload = { expires } as { expires: number; access_token?: string; refresh_token?: string };

		if (mode === 'json') {
			payload.refresh_token = refreshToken;
			payload.access_token = accessToken;
		}

		if (mode === 'cookie') {
			res.cookie(env['REFRESH_TOKEN_COOKIE_NAME'] as string, refreshToken, REFRESH_COOKIE_OPTIONS);
			payload.access_token = accessToken;
		}

		if (mode === 'session') {
			res.cookie(env['SESSION_COOKIE_NAME'] as string, accessToken, SESSION_COOKIE_OPTIONS);
		}

		res.locals['payload'] = { data: payload };
		return next();
	}),
	respond,
);

router.post(
	'/logout',
	asyncHandler(async (req, res, next) => {
		const accountability: Accountability = createDefaultAccountability({ ip: getIPFromReq(req) });

		const userAgent = req.get('user-agent')?.substring(0, 1024);
		if (userAgent) accountability.userAgent = userAgent;

		const origin = req.get('origin');
		if (origin) accountability.origin = origin;

		const authenticationService = new AuthenticationService({
			accountability: accountability,
			schema: req.schema,
		});

		const mode = getCurrentMode(req);
		const currentRefreshToken = getCurrentRefreshToken(req, mode);

		if (!currentRefreshToken) {
			throw new InvalidPayloadError({
				reason: `The refresh token is required in either the payload or cookie`,
			});
		}

		await authenticationService.logout(currentRefreshToken);

		if (req.cookies[env['REFRESH_TOKEN_COOKIE_NAME'] as string]) {
			res.clearCookie(env['REFRESH_TOKEN_COOKIE_NAME'] as string, REFRESH_COOKIE_OPTIONS);
		}

		if (req.cookies[env['SESSION_COOKIE_NAME'] as string]) {
			res.clearCookie(env['SESSION_COOKIE_NAME'] as string, SESSION_COOKIE_OPTIONS);
		}

		return next();
	}),
	respond,
);

router.post(
	'/password/request',
	asyncHandler(async (req, _res, next) => {
		if (typeof req.body.email !== 'string') {
			throw new InvalidPayloadError({ reason: `"email" field is required` });
		}

		const accountability: Accountability = createDefaultAccountability({ ip: getIPFromReq(req) });

		const userAgent = req.get('user-agent')?.substring(0, 1024);
		if (userAgent) accountability.userAgent = userAgent;

		const origin = req.get('origin');
		if (origin) accountability.origin = origin;

		const service = new UsersService({ accountability, schema: req.schema });

		try {
			await service.requestPasswordReset(req.body.email, req.body.reset_url || null);
			return next();
		} catch (err: any) {
			if (isDirectusError(err, ErrorCode.InvalidPayload)) {
				throw err;
			} else {
				logger.warn(err, `[email] ${err}`);
				return next();
			}
		}
	}),
	respond,
);

router.post(
	'/password/reset',
	asyncHandler(async (req, _res, next) => {
		if (typeof req.body.token !== 'string') {
			throw new InvalidPayloadError({ reason: `"token" field is required` });
		}

		if (typeof req.body.password !== 'string') {
			throw new InvalidPayloadError({ reason: `"password" field is required` });
		}

		const accountability: Accountability = createDefaultAccountability({ ip: getIPFromReq(req) });

		const userAgent = req.get('user-agent')?.substring(0, 1024);
		if (userAgent) accountability.userAgent = userAgent;

		const origin = req.get('origin');
		if (origin) accountability.origin = origin;

		const service = new UsersService({ accountability, schema: req.schema });
		await service.resetPassword(req.body.token, req.body.password);
		return next();
	}),
	respond,
);

router.get(
	'/',
	asyncHandler(async (req, res, next) => {
		const sessionOnly =
			'sessionOnly' in req.query && (req.query['sessionOnly'] === '' || Boolean(req.query['sessionOnly']));

		res.locals['payload'] = {
			data: getAuthProviders({ sessionOnly }),
			disableDefault: env['AUTH_DISABLE_DEFAULT'],
		};

		return next();
	}),
	respond,
);

router.get(
	'/oauth2/authorize',
	asyncHandler(async (req, res) => {
		const { client_id, response_type, redirect_uri, state } = req.query;
		const allowedClientList = toArray(env['OAUTH2_ALLOWED_CLIENTS'] as string);

		if (!client_id || !response_type || !redirect_uri || !state) {
			throw new InvalidPayloadError({ reason: "Invalid OAuth2 request" });
		}

		if (!allowedClientList.includes(client_id as string)) {
			res.send("Invalid client_id");
			return;
		}

		const encodedUri = encodeURIComponent(redirect_uri as string);
		const payload = `/admin/login?oauth=true&client_id=${client_id}&response_type=${response_type}&redirect_uri=${encodedUri}&state=${state}`;
		res.redirect(payload);
	}),
	respond
)

router.post(
	'/oauth2/authorize',
	asyncHandler(async (req, res, next) => {
		const { email, password, client_id, redirect_uri, state, response_type, access_token } = req.body
		const accountability: Accountability = createDefaultAccountability({ ip: getIPFromReq(req) })
		const authenticationService = new AuthenticationService({ accountability: accountability, schema: req.schema })
		const decodedUri = decodeURIComponent(redirect_uri)

		if(!client_id || !redirect_uri || !state || !response_type) {
			throw new InvalidPayloadError({ reason: "Error on the OAuth2 payload from authorization client" })
		}

		if(access_token) {

			if(!access_token) {
				throw new InvalidPayloadError({ reason: "No access token provided" })
			}

			const payload = {
				access_token: access_token
			}

			const code = jwt.sign(payload, env['SECRET'] as string, { issuer: 'Directus OAuth2' })
			res.redirect(decodedUri + `?code=${code}&state=${state}`)
			return;
		}

		if(!email || !password) {
			throw new InvalidPayloadError({ reason: "Email and Password is required" })
		}

		const auth = await authenticationService.login("local", { email, password }, { session: false })

		if (!auth) {
			throw new InvalidCredentialsError()
		}

		const payload = {
			email: email,
			...auth
		}

		const code = jwt.sign(payload, env['SECRET'] as string, { issuer: 'Directus OAuth2' })

		res.redirect(decodedUri + `?code=${code}&state=${state}`)

		return next()
	}),
	respond
)

router.post(
	'oauth2/token',
	asyncHandler(async (req, res, next) => {
		const { grant_type, code, client_id, redirect_uri } = req.body;
		const allowedClientList = toArray(env['OAUTH2_ALLOWED_CLIENTS'] as string)

		if (!client_id || !redirect_uri || !code) {
			throw new InvalidPayloadError({ reason: "Invalid OAuth2 request"});
		}

		if (!allowedClientList.includes(client_id)) {
			res.send("Invalid client_id")
			throw new InvalidCredentialsError()
		}

		if (grant_type !== 'authorization_code') {
			return res.status(400).json({ error: 'Unsupported grant type' });
		}

		let decodedMessage;

		try {
			decodedMessage = JSON.parse(jwt.verify(code, env['SECRET'] as string) as string);
		} catch (error) {
			throw new InvalidPayloadError({ reason: "Invalid oauth2 code" });
		}

		res.status(200).send({ acess_token: decodedMessage.access_token })

		return next()
	}),
	respond
)

router.get(
	'/token',
	asyncHandler(async (req, res) => {
		const cookie = req.cookies[env['SESSION_COOKIE_NAME'] as string]

		if (!cookie) {
			res.status(401).send({ error: "No authenticated"})
		}

		res.status(200).send({ access_token: cookie })
	}),
	respond
)


export default router;
