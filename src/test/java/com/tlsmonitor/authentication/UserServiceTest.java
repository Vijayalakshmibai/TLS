package com.tlsmonitor.authentication;

import com.tlsmonitor.authentication.entity.User;
import com.tlsmonitor.authentication.repository.UserRepository;
import com.tlsmonitor.authentication.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;
    private UserService userService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        userService = new UserService(userRepository, passwordEncoder);
    }

    @Test
    void testRegisterUserEncodesPasswordWithBCrypt() {
        when(userRepository.existsByUsername("securityadmin")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User user = userService.registerUser("securityadmin", "SecretPassword123!", "ADMIN");

        assertNotNull(user);
        assertEquals("securityadmin", user.getUsername());
        assertNotEquals("SecretPassword123!", user.getPassword());
        assertTrue(passwordEncoder.matches("SecretPassword123!", user.getPassword()));
        assertEquals("ADMIN", user.getRole());
        assertTrue(user.isEnabled());
    }

    @Test
    void testDuplicateUsernameThrowsException() {
        when(userRepository.existsByUsername("admin")).thenReturn(true);

        assertThrows(IllegalArgumentException.class, () ->
                userService.registerUser("admin", "anyPass", "ADMIN")
        );
        verify(userRepository, never()).save(any());
    }

    @Test
    void testLoadUserByUsernameReturnsUserDetails() {
        User user = new User("admin", passwordEncoder.encode("admin123"), "ADMIN");
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));

        UserDetails userDetails = userService.loadUserByUsername("admin");

        assertNotNull(userDetails);
        assertEquals("admin", userDetails.getUsername());
        assertTrue(userDetails.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void testLoadUnknownUserThrowsUsernameNotFoundException() {
        when(userRepository.findByUsername("unknown")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () ->
                userService.loadUserByUsername("unknown")
        );
    }
}
