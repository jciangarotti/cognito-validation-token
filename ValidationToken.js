const jwt       = require('jsonwebtoken');
const jwkToPem  = require('jwk-to-pem');
const axios     = require('axios');


class ValidationToken {

    constructor(token, iss) { 
        console.log("INGRESANDO AL CONSTRUCTOR DE LA CLASE VALIDATION TOKEN");
        this.token  =   token;
        this.iss    =   iss;
    }

    /** 
     * Función para poder validar que:
     * - La estructura del token concuerda con la de Jwt.
     * - Validar en el caso de que el token no petenece al User Pool correspondiente.
     * - El jwt es de tipo Access Token
    */
    async validateToken() {

        const token     = this.token;
        const iss       = this.iss;
        const decodeJwt = jwt.decode(token, {complete: true});
        // En caso de que el Token no sea válido
        if(!decodeJwt) {
            console.log(`Error en decode al validar el token`);
            console.log(token);
            throw "El JWT No es válido";
            return;
        } else {
            console.log(`El Token es válido`);
            console.log(decodeJwt);
        }

        // En caso de que no sea un token del User Pool.
        if (decodeJwt.payload.iss != iss) {
            console.log(`Error al comparar el User Pool el payload ${decodeJwt.payload.iss} con el definido en la app${iss}`);
            throw "Usuario NO Autorizado";
            return;
        } else {
            console.log(`El Token corresponde al del user pool ${iss}`);
        }

        if(decodeJwt.payload.token_use != 'access'){
            console.log(`Error, el token no es de tipo Access.`);
            throw "Usuario NO Autorizado";
            return;
        } else {
            console.log("El Token es de tipo Access Token");
        }

        var pems          = {};
        try {
            const jwkUrl    = `${iss}/.well-known/jwks.json`;
            pems      = await this.createPems(jwkUrl);
            console.log(`Se obtuvo correctamente el JWK`);
        }catch(err) {
            console.log(`Error al obtener el JWK`)
            console.log(err);
            throw "Problemas en el servidor";
            return;
        }

        const kid   = decodeJwt.header.kid;
        const pem   = pems[kid];
        if(!pem) {
            console.log(`Error con El Access Token al obtener el pem con el kid`);
            throw "Usuario No Autorizado";
        }

        jwt.verify(token, pem, { algorithms: ['RS256'] }, function(err, decodedToken) {
            if(!err){
                console.log(`El usuario es correcto`);
                return;
           }else{
               console.log(`Error al verificar el token: ${decodedToken}`);
               console.log(err);
               throw "Usuario No Autorizado";
               return;
           }
           
   
       });
        
    }

    /**
     *  Función para recorrer el JWK y formar un arreglo de PEMs
     * */
    async createPems (jwkUrl){
        try {
            var pems    = {};
            var jwk   = await getData(jwkUrl);
            const keys  = jwk['keys'];

            for(var i = 0; i < keys.length; i++) {
                //Convert each key to PEM
                var key_id = keys[i].kid;
                var modulus = keys[i].n;
                var exponent = keys[i].e;
                var key_type = keys[i].kty;
                var jwk = { kty: key_type, n: modulus, e: exponent};
                var pem = jwkToPem(jwk);
                pems[key_id] = pem;
            }

            return pems;

        } catch (err) {
            console.log("Error al momento de la creación del Pems");
            console.log(err);
            return;
        }
    }



}

const getData   =   async url => {
    try {
        const response  = await axios.get(url);
        const data      = response.data;
        return data;
        // console.log(data);
    } catch (err) {
        console.log(err);
    }
}



module.exports = ValidationToken;