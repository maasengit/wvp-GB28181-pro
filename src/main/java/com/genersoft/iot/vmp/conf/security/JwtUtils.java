package com.genersoft.iot.vmp.conf.security;

import com.genersoft.iot.vmp.conf.security.dto.JwtUser;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private static final String HEADER = "access-token";
    private static final String AUDIENCE = "Audience";

    private static final long EXPIRED_THRESHOLD = 10 * 60;

    private static String privateKeyStr;
    private static String publicKeyStr;

    static {
        try (BufferedReader reader = new BufferedReader(new FileReader("privateKey.json"));
             BufferedReader reader2 = new BufferedReader(new FileReader("publicKey.json"))) {
            privateKeyStr = reader.readLine();
            publicKeyStr = reader2.readLine();
        } catch (IOException e) {
            logger.error("必须提供有效的公钥和私钥", e);
        }
    }
    /**
     * token过期时间(分钟, 24小时)
     */
    public static final long expirationTime = 1440;

    public static String createToken(String username, String password, Integer roleId) {
        try {
            /**
             * “iss” (issuer)  发行人
             *
             * “sub” (subject)  主题
             *
             * “aud” (audience) 接收方 用户
             *
             * “exp” (expiration time) 到期时间
             *
             * “nbf” (not before)  在此之前不可用
             *
             * “iat” (issued at)  jwt的签发时间
             */
            //Payload
            JwtClaims claims = new JwtClaims();
            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            // 令牌将过期的时间 分钟
            claims.setExpirationTimeMinutesInTheFuture(expirationTime);
            claims.setNotBeforeMinutesInThePast(0);
            claims.setSubject("login");
            claims.setAudience(AUDIENCE);
            //添加自定义参数,必须是字符串类型
            claims.setClaim("username", username);
            // claims.setClaim("password", password);
            claims.setClaim("roleId", roleId);

            //jws
            JsonWebSignature jws = new JsonWebSignature();
            //签名算法RS256
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
            jws.setPayload(claims.toJson());
            RsaJsonWebKey jsonWebKey = new RsaJsonWebKey(JsonUtil.parseJson(privateKeyStr));
            PrivateKey privateKey = jsonWebKey.getPrivateKey();
            jws.setKey(privateKey);
            jws.setKeyIdHeaderValue(jsonWebKey.getKeyId());
            //get token
            String idToken = jws.getCompactSerialization();
            return idToken;
        } catch (JoseException e) {
            logger.error("[Token生成失败]： {}", e.getMessage());
        }

        return null;
    }

    public static String getHeader() {
        return HEADER;
    }


    public static JwtUser verifyToken(String token) {

        JwtUser jwtUser = new JwtUser();

        try {
            JwtConsumer consumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime()
                    .setMaxFutureValidityInMinutes(5256000)
                    .setAllowedClockSkewInSeconds(30)
                    .setRequireSubject()
                    //.setExpectedIssuer("")
                    .setExpectedAudience(AUDIENCE)
                    .setVerificationKey(new RsaJsonWebKey(JsonUtil.parseJson(publicKeyStr)).getPublicKey())
                    .build();

            JwtClaims claims = consumer.processToClaims(token);
            NumericDate expirationTime = claims.getExpirationTime();
            // 判断是否即将过期, 默认剩余时间小于5分钟未即将过期
            // 剩余时间 （秒）
            long timeRemaining = LocalDateTime.now().toEpochSecond(ZoneOffset.ofHours(8)) - expirationTime.getValue();
            if (timeRemaining < 5 * 60) {
                jwtUser.setStatus(JwtUser.TokenStatus.EXPIRING_SOON);
            }else {
                jwtUser.setStatus(JwtUser.TokenStatus.NORMAL);
            }

            String username = (String) claims.getClaimValue("username");
            // String password = (String) claims.getClaimValue("password");
            Long roleId = (Long) claims.getClaimValue("roleId");
            jwtUser.setUserName(username);
//            jwtUser.setPassword(password);
            jwtUser.setRoleId(roleId.intValue());

            return jwtUser;
        } catch (InvalidJwtException e) {
            if (e.hasErrorCode(ErrorCodes.EXPIRED)) {
                jwtUser.setStatus(JwtUser.TokenStatus.EXPIRED);
            }else {
                jwtUser.setStatus(JwtUser.TokenStatus.EXCEPTION);
            }
            return jwtUser;
        }catch (Exception e) {
            logger.error("[Token解析失败]： {}", e.getMessage());
            jwtUser.setStatus(JwtUser.TokenStatus.EXPIRED);
            return jwtUser;
        }
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RsaJsonWebKey jsonWebKey = new RsaJsonWebKey(publicKey);
        jsonWebKey.setKeyId("574146a4eeb5f559420c959378ee21b4");
        jsonWebKey.setPrivateKey(privateKey);

        System.out.println("Public JWK: " + jsonWebKey.toJson());
        System.out.println("Private JWK: " + jsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        String token = createToken("user", "", 2);
        verifyToken(token);
    }
}
