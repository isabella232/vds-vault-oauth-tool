from datetime import datetime
from jose import jwt
from jose.utils import base64url_decode
from jose.exceptions import JWTError
from vds_vault_oauth.utilities import OAuthContainer


class Token():
    def __init__(self, token_value, token_type, logger):
        self.token_value = token_value
        self.token_type = token_type
        self.token_claims = dict()
        self.logger = logger

    def decodeTokens(self):
        # key is equal to the key set that returns from the JWKS endpoint
        # key = {"kty":"RSA","alg":"RS256","kid":"UpnQvBsxTg7xlg2wblrMxHchWN2AfEOZIGpPnP-MAt0","use":"sig","e":"AQAB","n":"ipjtfQQPWAvLMvFpW_H3GtLLGCRwWpoJN93dPztEwo-CwapveR4_piioMFKFmtiB5G2C8EhW51lU_4uC_fTDNCd44qC89f1Yvsmw46yDUChjmkJTtkyF-GwZGwoXaUQ6uLTgiBOQy2B2YpJKLLt2KaLAo4Pnb0MytPe0KQqEMokC1MlDjxMsNT6Yhm7oDwEmenEatbcmpurRk827oo8NOHhhQA4L8Dpd8ozpvrGEar6v06as-vSmYMoEUP8AtKmhL-szZDhpMmRvXtr2WgBSC7nPB5KLK9WrsFtHYAr340moaXN4C8F61aRjLQC9oukoEipn3kNfmcnbELBGxrkUww"}
        # claims_ver = jwt.decode(payload,key,algorithms='RS256',options={'verify_aud' : False, 'verify_at_hash' : False})
        
        if (self.token_value != None and self.token_type != "refresh_token"):
            try:
                claims = jwt.get_unverified_claims(self.token_value)
                headers = jwt.get_unverified_headers(self.token_value)
                self.token_claims.update(headers)
                self.token_claims.update(claims)
            except JWTError as e:
                import sys
                self.logger.log(("\t%s: %s\n" % (str(sys.exc_info()[0]), str(e))))        
                self.logger.log(("\t%s: %s\n\n" % ("Error", "Non-JWT token detected. Verifying against introspection endpoint.")))
                       
                return False

        return True

    def verifyTokenClaims(self):

        self.logger.log(("\n\t" + '{s:{c}^{n}}'.format(s=" Verifying '" + self.token_type + "' Claims ",n=65,c='-') + "\n\n"))
        if ('sub' in self.token_claims):
            self.logger.log(("\t%s: %s\n" % ("The 'sub' claim exists", self.token_claims['sub'])))
        else:
            self.logger.log(("\n\tINVALID: The 'sub' claim does not exist. This is required.\n"), "ERROR") 

        if ('aud' in self.token_claims):
            self.logger.log(("\t%s: %s\n" % ("The 'aud' claim exists", self.token_claims['aud'])))
        else:
            self.logger.log(("\n\tINVALID: The 'aud' claim does not exist. This is optionally required.\n"), "ERROR") 
        
        if ('exp' in self.token_claims):
            expiry = datetime.utcfromtimestamp(int(self.token_claims['exp'])).strftime('%Y-%m-%d %H:%M:%S')
            self.logger.log(("\t%s: %s\n" % ("The 'exp' claim exists", str(self.token_claims['exp']) + " (" + str(expiry) + " UTC)")))
        else:
            self.logger.log(("\n\tINVALID: The 'exp' claim does not exist.\n"), "ERROR") 

        if self.token_type == "access_token":
            if ('cid' in self.token_claims):
                self.logger.log(("\t%s: %s\n" % ("The 'cid' claim exists", self.token_claims['cid'])))
            elif ('appid' in self.token_claims):
                self.logger.log(("\t%s: %s\n" % ("The 'appid' claim exists", self.token_claims['appid'])))
            else:
                self.logger.log(("\n\tINVALID: The 'cid' or 'appid' claim does not exist.\n"), "ERROR") 

        self.logger.log(("\n\n")) 

    def logTokenClaims(self):
        for key, value in self.token_claims.items():
            self.logger.log(("\t%s: %s\n" % (key, value)))
        self.logger.log(("\n\t" + '{s:{c}^{n}}'.format(s='',n=65,c='-') + "\n\n"))
        self.logger.log(("\n"))