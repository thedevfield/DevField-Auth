package dev.devfield.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
class AuthApplicationTest {
    @Autowired
    JdbcTemplate jdbc;

    @Test
    void connectsToAuthSchema() {
        assertEquals("auth", jdbc.queryForObject("select current_schema()", String.class));
    }
}
