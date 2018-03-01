package io.sonova.nephele.shared.security.oauth2.provider.token;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;


public class SonovaUserAuthenticationConverterTest {


    private SonovaUserAuthenticationConverter converter = new SonovaUserAuthenticationConverter();

    @Test
    public void shouldExtractAuthenticationWhenAuthoritiesIsCollection() throws Exception {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(SonovaUserAuthenticationConverter.SUB, "test_user_sub");
        ArrayList<String> lists = new ArrayList<String>();
        lists.add("a1");
        lists.add("a2");
        map.put(UserAuthenticationConverter.AUTHORITIES, lists);

        Authentication authentication = converter.extractAuthentication(map);

        assertEquals(2, authentication.getAuthorities().size());
    }

    @Test
    public void shouldExtractAuthenticationWhenAuthoritiesIsString() throws Exception {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(SonovaUserAuthenticationConverter.SUB, "test_user_sub");
        map.put(UserAuthenticationConverter.AUTHORITIES, "a1,a2");

        Authentication authentication = converter.extractAuthentication(map);

        assertEquals(2, authentication.getAuthorities().size());
    }

    @Test
    public void shouldExtractAuthenticationWhenUserDetailsProvided() throws Exception {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(SonovaUserAuthenticationConverter.SUB, "test_user_sub");

        UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetailsService.loadUserByUsername("test_user_sub")).thenReturn(
                new User("foo", "bar", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_SPAM")));
        converter.setUserDetailsService(userDetailsService);
        Authentication authentication = converter.extractAuthentication(map);

        assertEquals("ROLE_SPAM", authentication.getAuthorities().iterator().next().toString());
    }

    @Test
    public void useSubClaimInsteadOfUsername() throws Exception {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");
        map.put(SonovaUserAuthenticationConverter.SUB, "test_user_sub");
        Authentication authentication = converter.extractAuthentication(map);

        assertEquals("test_user_sub", (String)authentication.getPrincipal());
    }

}