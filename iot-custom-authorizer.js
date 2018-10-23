// A simple authorizer Lambda function demonstrating
// how to parse auth token and generate response
var jwt = require('jsonwebtoken');

exports.handler = function(event, context, callback) {
    var encoded_token = event.token;
    var permission = "deny";
    var key_secret = process.env.key_secret;
    console.log("Token is : " + encoded_token);
    console.log("--------------");
    var decoded_token;
    try {
      decoded_token = jwt.verify(encoded_token, key_secret);
      permission = "allow";
    } catch(err) {
      console.log(err.message);
    }
    if (typeof decoded_token !== "undefined") {
      console.log(decoded_token.sub);
    }
    switch (permission) {
        case 'allow':
            callback(null, generateAuthResponse(decoded_token, 'Allow'));
        case 'deny':
            callback(null, generateAuthResponse(decoded_token, 'Deny'));
        default:
            callback("Error: Invalid token");
    }
};

// Helper function to generate authorization response
var generateAuthResponse = function(token, effect) {
    // Invoke your preferred identity provider
    // to get the authN and authZ response.
    // Following is just for simplicity sake

    var authResponse = {};
    authResponse.isAuthenticated = true;
    if (typeof token !== "undefined") {
      authResponse.principalId = token.sub;
    } else {
      authResponse.principalId = 'invalid_user';
    }
    var policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    var statement = {};
    statement.Action = 'iot:Publish';
    statement.Effect = effect;
    statement.Resource = "arn:aws:iot:us-east-1:033518387927:topic/customauthtesting";
    policyDocument.Statement[0] = statement;
    authResponse.policyDocuments = [policyDocument];
    authResponse.disconnectAfterInSeconds = 3600;
    authResponse.refreshAfterInSeconds = 600;

    return authResponse;
}
