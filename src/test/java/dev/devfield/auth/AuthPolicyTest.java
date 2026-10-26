package dev.devfield.auth;

import static org.junit.jupiter.api.Assertions.*;

import dev.devfield.auth.account.AuthAccounts;
import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.util.Secrets;
import org.junit.jupiter.api.Test;

class AuthPolicyTest {
    @Test void emailNormalizationIsConservative() {
        assertEquals("person+tag@example.test", AuthAccounts.normalize(" Person+Tag@Example.Test "));
        assertEquals("first.last@example.test", AuthAccounts.normalize("First.Last@Example.Test"));
        assertNotEquals(AuthAccounts.normalize("first.last@example.test"), AuthAccounts.normalize("firstlast@example.test"));
        assertThrows(ApiError.class, () -> AuthAccounts.normalize("invalid-address"));
    }

    @Test void randomProofsAreUniqueAndHaveStableHashes() {
        String first = Secrets.randomToken();
        String second = Secrets.randomToken();
        assertEquals(43, first.length());
        assertNotEquals(first, second);
        assertEquals(64, Secrets.sha256(first).length());
        assertTrue(Secrets.equalHex(Secrets.sha256(first), Secrets.sha256(first)));
        assertFalse(Secrets.equalHex(Secrets.sha256(first), Secrets.sha256(second)));
    }
}
