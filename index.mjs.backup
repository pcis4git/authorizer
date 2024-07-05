import axios from 'axios';
import jwt from 'jsonwebtoken';

let OIDC_URL = "https://login.pst.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaaspstoidc/.well-known/openid-configuration";
let jwks ;

export const handler = async (event, context ) => {

    var signerKey = null; 
    var principalId  = "user";
    var authRequest  = JSON.stringify(event, null, 0 );
    console.warn("Auth Request: " + authRequest );
    
    var methodArn  = event.methodArn;
    var oAuthtoken = event.authorizationToken;
    var effect     = "Deny"
    var ctxMessage = "";

    try {
        
        if( oAuthtoken == null ) {
            console.error("missing authorization header!");
            throw new Error("Bad request, missing authorization header");            
        }
      
        if( ! oAuthtoken.startsWith('Bearer ')) {
            console.error("Invalid authorization header, not starting with Bearer !");
            throw new Error("Bad request, Invalid authorization token");
        }

        oAuthtoken = oAuthtoken.split(' ')[1];
        var decodedToken = null;
        try {
            decodedToken = jwt.decode(oAuthtoken, { complete: true });
        }
        catch(error) {
            console.error("failed to decode authorization token: " + error.message );
            throw new Error("Bad request, Invalid JWT token: " + error.message);
        }

        if( decodedToken == null ) {
            console.error("failed to decode authorization token!");
            throw new Error("Bad request, Invalid JWT token");
        }

        var algorithm = decodedToken?.header?.alg; 
        var kid = decodedToken?.header?.kid; 
        console.info(`token alg is '${algorithm}'', kid is '${kid}'`) ;        
        
        //find jwks and then find the proper key for token verification
        //the jwks can be set to global variable to work as cache
        if( jwks == null ) {
            jwks = await downloadJWKS(OIDC_URL);      
        }
        else {
            console.info("Get JWKS data from default Cache !!")
        }
        
        var keys = jwks.keys;
        signerKey = findKeyFromJWKS(keys, kid, algorithm );

        var verifyResult = null;
        try {
            // temporary disable check
           //verifyResult = jwt.verify(oAuthtoken, signerKey, { algorithms: [algorithm] });
        }
        catch(error) {
            console.error(`failed to verify JWT token: ${error.message}`);
            //throw new Error("Invalid JWT token: " + error.message );
        }

        //var azp = verifyResult.azp;        
        //console.warn(`token verify success for: '${azp}'`);

        effect = "Allow";
        ctxMessage = "Access Permitted";
    }
    catch(error) {
        effect = "Deny";
        ctxMessage = error.message;
    }


    var returnPolicy =  generatePolicy(principalId, effect, methodArn, ctxMessage);
    var policyResult = JSON.stringify( returnPolicy, null, 0 );
    console.warn("Auth Result: " + policyResult );
    
    return returnPolicy;
    
};




const downloadJWKS = async (oidcEndpoint) => {
    try {
        console.warn("start calling OIDC endpoint " + oidcEndpoint );
        const response = await axios.get(oidcEndpoint);
        console.warn("stop calling OIDC endpoint");
        
        const jwks_uri = response.data.jwks_uri;
        console.warn("start calling jwks endpoint " + jwks_uri );
        const jwksResponse = await axios.get(jwks_uri);
        console.warn("start calling jwks endpoint" );
        
        console.warn("total number of Keys in JWKS is " + jwksResponse.data.keys.length);
        return jwksResponse.data;
    } 
    catch (error) {
        console.error('Error fetching JWKS:', error);
        throw new Error('Internal Server Error');
    }
};

function findKeyFromJWKS(keys, kid, alg ) {
    
    var key = null;
    key = keys.find( k=> k.kid == kid && k.alg == alg );
    if( key == null ) {
       console.error(`Unable to find a signing key that matches '${kid}' and algorithm '${alg}'`);
       throw new Error("Invalid KID in JWT token");
    }
    
    if (key.x5c && key.x5c.length) {
      const cert = key.x5c[0];
      const pem = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
      return pem;
    } 
    else {
      console.error("Unable to find x5c from key entry");  
      throw new Error("Invalid JWKS key entry");
    }    
    
}


function generatePolicy(principalId, effect, resource, ctxMessage) {
    return {
        principalId,
        policyDocument: {
            Version: "2012-10-17",
            Statement: [
                {
                    Action: "execute-api:Invoke",
                    Effect: effect,
                    Resource: resource
                }
            ] 
        },
        context: {
            message: ctxMessage
        },

        //usageIdentifierKey: "key1234567key1234567key1234567"
        usageIdentifierKey: "PR9Y3bQYuJ7uGByPVLvZxnqKWoAlRSf34IoJuq0f"
    };
}
