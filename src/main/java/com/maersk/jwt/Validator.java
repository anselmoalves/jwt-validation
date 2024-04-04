package com.maersk.jwt;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;

public class Validator {

  public static void main(String[] args) throws JwkException, MalformedURLException {
    String token = args[0];
    DecodedJWT jwt = JWT.decode(token);
    JwkProvider provider = new UrlJwkProvider(new URL(
        "https://login.microsoftonline.com/common/discovery/keys"));
    Jwk jwk = provider.get(jwt.getKeyId());
    Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
    algorithm.verify(jwt);

    // Check expiration
    if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
      throw new RuntimeException("Expired token!");
    }
  }
}
