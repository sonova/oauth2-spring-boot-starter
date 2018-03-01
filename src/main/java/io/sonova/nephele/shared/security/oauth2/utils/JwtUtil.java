package io.sonova.nephele.shared.security.oauth2.utils;

import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;


import java.nio.CharBuffer;
import java.util.Map;

import static org.springframework.security.jwt.codec.Codecs.b64UrlDecode;
import static org.springframework.security.jwt.codec.Codecs.utf8Decode;

/**
 * Util class for JWT handling.
 */
public class JwtUtil {

    private static JsonParser objectMapper = JsonParserFactory.create();

    public static Map<String,Object> getJwtHeaderParams(String token){

        int firstPeriod = token.indexOf('.');
        int lastPeriod = token.lastIndexOf('.');

        if (firstPeriod <= 0 || lastPeriod <= firstPeriod) {
            throw new IllegalArgumentException("JWT must have 3 tokens");
        }

        CharBuffer buffer = CharBuffer.wrap(token, 0, firstPeriod);
        byte[] bytes = b64UrlDecode(buffer);
        String headerString = utf8Decode(bytes);

        Map<String,Object> headerParams = objectMapper.parseMap(headerString);
        return headerParams;
    }



}
