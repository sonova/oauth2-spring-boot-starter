package io.sonova.nephele.shared.security.oauth2.utils;

import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

public class JwtUtilTest {

    final static String JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjdkOWZmNDczLWUyZjgtNDcyNS1iY2I0LThmYjVlMTg3OTU4ZSIsIng1dCI6IkpWUXBFSmU2Mk5GRm9BSXZOUTNtWEF6VndESSJ9.eyJjbGllbnRfaWQiOiJkNmQxMzE0Ny0yZDBlLTRjNzUtYjI4ZC0zYmQwNzYyMDJlZWYiLCJleHAiOjE0Nzg3OTA2MTksInNjb3BlIjpbInBob25ha19iMmNfdXNlcm1nbXQiLCJwaG9uYWtfYjJjX3VzZXJtZ210LmlkcCJdLCJpc3MiOiJodHRwczovL2ludC1zaWdub24ucGhvbmFrLmNvbSIsImF1ZCI6Imh0dHBzOi8vYXBwaWQuc29ub3ZhLmNvbS9hcGkvaW50In0.XqSFJusG4oO7MyYMqLUNI02z325ontbZsgqNr7TtoPflR8TIcgE70vQr7xaU3zsxqUbMwwkgcowH-BWmfhOhjquB1MCDknVH6kxLYKtVenlluhgKgtA0b7VSRNMQWdaYenQfEEU7_J_3AQd3oH9n7t_8KJfyTbNdEQDaBEsYOGsop223rDt9l5w8OhSva6uUaJbfe_5UXEaawwOowpf2HAZRsTlJRtvOHrMY9efVlut3j0VaAgatp-KbAENNHBsdvEWzObWsjnN0_ftmCK2Nlt78UUYCReRHlvYCPexSwPMA2AKD6NjQWirvaXvI0mBQPefLJCjfZHPHnYhdVNetgw";
    final static String X5T_FIELDNAME = "x5t";
    final static String X5T_VALUE = "JVQpEJe62NFFoAIvNQ3mXAzVwDI";

    @Test
    public void testHeaderExtraction() throws Exception {
        Map<String,Object> header = JwtUtil.getJwtHeaderParams(JWT_TOKEN);
        Assert.assertEquals(X5T_VALUE, header.get(X5T_FIELDNAME));
    }
    @Test(expected=IllegalArgumentException.class)
    public void testIllegalToken() throws Exception {
        Map<String,Object> header = JwtUtil.getJwtHeaderParams("asdf");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalTokenContent() throws Exception {
        Map<String,Object> header = JwtUtil.getJwtHeaderParams("OWZmNDczLWUyZjgt.asdf.ddfd");
    }

}

