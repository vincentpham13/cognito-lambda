const axios = require('axios');
const jsonwebtoken = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');

const cognitoPoolId = 'us-east-1_HC0P4th3o';
if (!cognitoPoolId) {
  throw new Error('env var required for cognito pool');
}

const cognitoIssuer = `https://cognito-idp.us-east-1.amazonaws.com/${cognitoPoolId}`;

let cachedKeys = null;
const getPublicKeys = async () => {
  if (!cachedKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const publicKeys = await axios.default.get(url);
    console.log("🚀 ~ file: decode-verifry-jwt.js ~ line 17 ~ getPublicKeys ~ publicKeys", publicKeys)

    cachedKeys = publicKeys.data.keys.reduce((agg, current) => {
      const pem = jwkToPem(current);
      agg[current.kid] = { instance: current, pem };

      return agg;
    });

    return cachedKeys;
  } else {
    return cachedKeys;
  }
}

const verifyToken = async (token) => {
  let responseClaims = {};
  try {
    const keys = await getPublicKeys();
    const tokenSections = (token || '').split('.');

    const headerJSON = Buffer.from(tokenSections[1], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON);

    if (tokenSections.length < 2) {
      throw new Error('Token is invalid');
    }

    // get key from header and compare with key in the fetched key-pairs cognito
    const key = keys[header.kid];

    if (!key) {
      throw new Error("No matching key found");
    }

    if (token) {
      const claims = jsonwebtoken.verify(token, key.pem);
      console.log("🚀 ~ file: decode-verifry-jwt.js ~ line 53 ~ verifyToken ~ claims", claims);
      responseClaims = claims;
    }
  } catch (error) {
    console.log("🚀 ~ file: decode-verifry-jwt.js ~ line 59 ~ verifyToken ~ error", error)
  }

  return responseClaims;
}

module.exports = {
  getPublicKeys,
  verifyToken,
}