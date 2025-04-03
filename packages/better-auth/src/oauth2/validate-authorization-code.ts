import { betterFetch } from "@better-fetch/fetch";
import type { ProviderOptions } from "./types";
import { getOAuth2Tokens } from "./utils";
import { jwtVerify } from "jose";

export async function validateAuthorizationCode({
	code,
	codeVerifier,
	redirectURI,
	options,
	tokenEndpoint,
	authentication,
	deviceId,
}: {
	code: string;
	redirectURI: string;
	options: ProviderOptions;
	codeVerifier?: string;
	deviceId?: string;
	tokenEndpoint: string;
	authentication?: "basic" | "post";
}) {
	const body = new URLSearchParams();
	const headers: Record<string, any> = {
		"content-type": "application/x-www-form-urlencoded",
		accept: "application/json",
		"user-agent": "better-auth",
	};
	body.set("grant_type", "authorization_code");
	body.set("code", code);
	codeVerifier && body.set("code_verifier", codeVerifier);
	options.clientKey && body.set("client_key", options.clientKey);
	deviceId && body.set("device_id", deviceId);
	body.set("redirect_uri", options.redirectURI || redirectURI);
	if (authentication === "basic") {
		const encodedCredentials = btoa(
			`${options.clientId}:${options.clientSecret}`,
		);
		headers["authorization"] = `Basic ${encodedCredentials}`;
	} else {
		body.set("client_id", options.clientId);
		body.set("client_secret", options.clientSecret);
	}
	const { data, error } = await betterFetch<object>(tokenEndpoint, {
		method: "POST",
		body: body,
		headers,
	});

	if (error) {
		throw error;
	}
	const tokens = getOAuth2Tokens(data);
	const responseHeaders = new Headers({
		'Content-Type': 'application/json',
		'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
		'Pragma': 'no-cache',
		'Expires': '0'
	});

	return new Response(JSON.stringify(tokens), {
		status: 200,
		headers: responseHeaders,
	});
}

export async function validateToken(token: string, jwksEndpoint: string) {
	const { data, error } = await betterFetch<{
		keys: {
			kid: string;
			kty: string;
			use: string;
			n: string;
			e: string;
			x5c: string[];
		}[];
	}>(jwksEndpoint, {
		method: "GET",
		headers: {
			accept: "application/json",
			"user-agent": "better-auth",
		},
	});
	if (error) {
		throw error;
	}
	const keys = data["keys"];
	const header = JSON.parse(atob(token.split(".")[0]));
	const key = keys.find((key) => key.kid === header.kid);
	if (!key) {
		throw new Error("Key not found");
	}
	const verified = await jwtVerify(token, key);
	return verified;
}
