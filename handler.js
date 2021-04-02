'use strict';

const { verifyToken } = require('./decode-verifry-jwt')

const interceptorFn = async (event) => {
  const claims = verifyToken(token);
  console.log("🚀 ~ file: handler.js ~ line 7 ~ interceptorFn ~ claims", claims)
  
  const responsePolicy = {
    "principalId": "abcdef", // The principal user identification associated with the token sent by the client.
    "policyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Deny",
          "Action": "execute-api:Invoke",
          "Resource": "arn:aws:execute-api:us-east-1:653332051596:amled9b5v0/*/GET/trigger"
        }
      ]
    },
    "context": {
      "exampleKey": "exampleValue"
    }
  };

  const { authorizationToken } = event;

  if (!authorizationToken) {
    return responsePolicy;
  }

  responsePolicy.policyDocument.Statement[0].Effect = "Allow";

  return responsePolicy;
}

const foobarFn = async (event) => {
  console.log('Involked by...', event);
  return {
    "isBase64Encoded": false,
    "statusCode": 200,
    "body": "Hello from Lambda!",
    "headers": {
      "content-type": "application/json"
    }
  };
}

const preSignUpCheck = async (event) => {
  console.log('response', event.response);

  // set the user autoConfirmUser flag after validating the email domain
  event.response.autoConfirmUser = false;

  // split the email adrr to compare domains
  console.log(event.request.userAttributes);
  const address = event.request.userAttributes.email.split('@');

  // this example uses a custom attribute "custom:domain"
  const preferredUsn = 'preferred_username';
  if (event.request.userAttributes.hasOwnProperty(preferredUsn)) {
    if (event.request.userAttributes[preferredUsn] === address[1]) {
      event.response.autoConfirmUser = true;
      await Promise.resolve(setTimeout(() => { console.log('verified email') }, 3000));
    }
  }

  return event;
};

module.exports = {
  foobarFn,
  interceptorFn,
  preSignUpCheck,
}
