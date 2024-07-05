import axios from 'axios';
import jwt from 'jsonwebtoken';

let OIDC_URL="https://login.pst.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaaspstoidc/.well-known/openid-configuration";
let jwks = null;
let lastJWKSFetchTime = 0;
const jwks_ttl = 1000 * 60 * 60 * 12; // 12 hours


//entry point for authorizer lambda
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
        
        await downloadJWKS(OIDC_URL);      
        
        var keys = jwks.keys;
        signerKey = findKeyFromJWKS(keys, kid, algorithm );

        var verifyResult = null;
        try {
            // temporary disable check
          verifyResult = jwt.verify(oAuthtoken, signerKey, { algorithms: [algorithm] });
        }
        catch(error) {
            console.error(`failed to verify JWT token: ${error.message}`);
            throw new Error("Invalid JWT token: " + error.message );
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

//check if JWKS cache is expired
function isJWKSExpired()  {
    var currentTime = new Date().getTime();
    var diff = currentTime - lastJWKSFetchTime;
    return diff > jwks_ttl;
}

//locate the key from JWKS
function findKeyFromJWKS(keys, kid, alg ) {
    
    var key = null;
    key = keys.find( k=> k.kid == kid && k.alg == alg );
    if( key == null ) {
       console.error(`Unable to find a signing key that matches '${kid}' and algorithm '${alg}'`);
       throw new Error("Invalid KID in JWT token");
    }
    
    if( key.x5c == null || key.x5c == undefined ) {
        console.error("Unable to find x5c from key entry");  
        throw new Error("Invalid JWKS key entry");
    }
    else {
        if( Array.isArray(key.x5c) && key.x5c.length > 0 ) {
            if( key.x5c.length > 1) {
                console.warn("found multiple x5c entries, using the first one");
            }
            const cert = key.x5c[0];
            const pem = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
            return pem;            
        }
        else if (typeof key.x5c === 'string') {
            const cert = key.x5c;
            const pem = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
            return pem;
        }
        else {
            console.error("Unable to find x5c from key entry");  
            throw new Error("Invalid JWKS key entry");
        }
    }
}

async function downloadJWKS() {

    if( jwks == null || jwks.keys == null || jwks.keys.length == 0 || isJWKSExpired()) {
        try {
            let oidcEndpoint = process.env.OIDC_URL;
            console.info("start calling OIDC endpoint " + oidcEndpoint );
            const response = await axios.get(oidcEndpoint);
            console.info("stop calling OIDC endpoint");
            
            const jwks_uri = response.data.jwks_uri;
            console.info("start calling jwks endpoint " + jwks_uri );
            const jwksResponse = await axios.get(jwks_uri);
            console.info("stop calling jwks endpoint" );
    
            jwks = jwksResponse.data;
            lastJWKSFetchTime = new Date().getTime();
            console.info("total number of Keys in JWKS is " + jwks.keys.length);
        } 
        catch (error) {
            console.error('lambda termigated due to fatal error, cannot fetching JWKS:', error);
            if( lastJWKSFetchTime == 0 ) {
                process.exit(1);
            }
            else {
                throw new Error('Internal Server Error, cannot fetching JWKS');
            }
        }
    }
    else {
        console.info("JWKS cache is still valid, no need to refresh");    
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

        usageIdentifierKey: "PR9Y3bQYuJ7uGByPVLvZxnqKWoAlRSf34IoJuq0f"
    };
}

await downloadJWKS();

const event = {
    methodArn: "arn:aws:execute-api:us-east-1:123456789012:apiId/stage/GET/resource",
    authorizationToken: "Bearer eyJ0eXAiOiJKV1QiLCJraWQiOiJpa1ZKeEJkcDVQRmxXdzIwWGtRYW1CWVorZEU9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJvYWdfaGVhbHRoY2hlY2tfY2xpZW50IiwiY3RzIjoiT0FVVEgyX1NUQVRFTEVTU19HUkFOVCIsImF1ZGl0VHJhY2tpbmdJZCI6IjQ4ZDRmMTcxLTk3ZWQtNDAyNS05MmE0LTBhMGMxYzBkY2E5ZS04NDA4ODI1IiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5wc3Qub25laWRmZWRlcmF0aW9uLmVoZWFsdGhvbnRhcmlvLmNhL3Nzby9vYXV0aDIvcmVhbG1zL3Jvb3QvcmVhbG1zL2lkYWFzcHN0b2lkYyIsInRva2VuTmFtZSI6ImFjY2Vzc190b2tlbiIsInRva2VuX3R5cGUiOiJCZWFyZXIiLCJhdXRoR3JhbnRJZCI6IkVIdWZuaW0tSTZ2SjNhdTcyUnJBN0hsTWdNTSIsImF1ZCI6WyJvYWdfaGVhbHRoY2hlY2tfY2xpZW50IiwiaHR0cHM6Ly9wcm92aWRlci5laGVhbHRob250YXJpby5jYSJdLCJuYmYiOjE3MTc0NDc5MzMsImdyYW50X3R5cGUiOiJjbGllbnRfY3JlZGVudGlhbHMiLCJzY29wZSI6WyJzeXN0ZW0vQnVuZGxlLndyaXRlIl0sImF1dGhfdGltZSI6MTcxNzQ0NzkzMywicmVhbG0iOiIvaWRhYXNwc3RvaWRjIiwiZXhwIjoxNzE3NDUxNTMzLCJpYXQiOjE3MTc0NDc5MzMsImV4cGlyZXNfaW4iOjM2MDAsImp0aSI6InBrWG5tcnhFQ3NDcDR4bGw5Y0NiN0Y3aEJXSSIsInVhbyI6IjIuMTYuODQwLjEuMTEzODgzLjMuMjM5Ljk6MTAzNjk4MDg5NDI0IiwidWFvVHlwZSI6Ik9yZ2FuaXphdGlvbiIsInVhb05hbWUiOiJTaW5haSBIZWFsdGggU3lzdGVtIiwiYXpwIjoib2FnX2hlYWx0aGNoZWNrX2NsaWVudCIsImFwaV9rZXlzIjpbIm1VVmk3R3BvNWtGT25scEtocVYxRXFDUUF4S3JxdnJWTFpheW11Uy9WdW89IiwiIEpQSm8zL2t0aHRZWGRpdUs3Zm1Tc05SVHpYVjc3azBxcWlVd1k4dWVPWWs9IiwiIDNZM2xTV3QycUdTY21tM1NocVQrRmdGRXVjUGRSb0dlUE5mM0xQbWhIZEE9IiwiIEVvWHFzTCsyNUpaRlQ1UHFiQk5pSVlpN0pnS2NJSDE4cWdCVnJOOWRmcm89IiwiIExkUnZ3RUEzUklwZUdjUUp3aGhTZ1VXcm82QUpXcjZsa3BBRWd6ekFvTVk9IiwiIFFEYS9LVGNXc28yY216b0JaZXN5UGpZRHBGcFIwWlU5bXJLb2tMUzV1ZFk9IiwiIHNjcWxZcngzMUhQVStMRDFDNGJUaTF0VGhZbGF6Y1IwNVYwNTRxVG5KTE09Il0sIkROIjoiQ049T0FQR0hDLlBTVCxPVT1QQ0lTLE89T05UQVJJT0hFQUxUSCxMPVRPUk9OVE8sUz1PTixDPUNBIiwidmVyc2lvbiI6IjEuMCIsIl9wcm9maWxlIjpbImh0dHA6Ly9laGVhbHRob250YXJpby5jYS9maGlyL1N0cnVjdHVyZURlZmluaXRpb24vY2Etb24tSFJNLXByb2ZpbGUtQnVuZGxlIl19.GPWVAl7ozkjLCPCvfujt-uM6andjTjRxTwAr-BD-TVD44mlZE99ghxw8juEjDfLOYA5r5eJoIDLzi9DTpjay0rqXl2uX3p9X2s05chsc5aGrC7EmyaRFHxOVi8wJqriUsrc6TJcQvCSMzG2XqDzfakDyz_cR9zrBvE2jc6MMwT1_wyrDNZ1f5fA5BX9iPBCAlniJOq4BD2RnTtYzu8mbPBJhzFxOohEHm0TYkwpYq4edfTRIUNz6laA3a-GrGmCRpIpfM2lLaB-O1MjuMxgWq7iInvor6MLcQvKuuzJc2GTUfxr4K3ud7pwk0U24Y5iL-Xyba1fJBIaLrTBHQ8e9Og"
}
handler(event, null);


