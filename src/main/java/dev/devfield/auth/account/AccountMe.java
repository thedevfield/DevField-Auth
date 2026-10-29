package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.session.AuthSessions;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountMe {
    public record Profile(UUID userId, String displayName, String email, boolean emailLoginEnabled, boolean emailLoginPending, boolean emailOwnershipVerified,
                          List<String> socialProviders, Instant createdAt, String deletionStatus) {}

    private record AccountRow(UUID userId, String displayName, String email, boolean emailPending, Instant createdAt,
                              String state, String providers) {}

    private final JdbcTemplate db;
    private final AuthSessions sessions;

    public AccountMe(JdbcTemplate db, AuthSessions sessions) {
        this.db = db;
        this.sessions = sessions;
    }

    @Transactional(readOnly = true)
    public Profile get(String handle) {
        AuthSessions.State session = sessions.byHandle(handle);
        if (!session.active()) throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");

        // Recheck the session in the account query so a revocation between the two reads fails closed.
        List<AccountRow> rows = db.query("SELECT u.id,u.display_name,c.normalized_email,c.id IS NOT NULL,u.created_at,u.state," +
                        "COALESCE((SELECT string_agg(si.provider, ',' ORDER BY si.provider) " +
                        "FROM auth.social_identity si WHERE si.user_id=u.id),'') " +
                        "FROM auth.auth_session s JOIN auth.devfield_user u ON u.id=s.user_id " +
                        "LEFT JOIN auth.email_credential c ON c.user_id=u.id " +
                        "WHERE s.id=? AND s.user_id=? AND s.revoked_at IS NULL AND s.expires_at>now()",
                (rs, i) -> new AccountRow(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getBoolean(4),
                        rs.getTimestamp(5).toInstant(), rs.getString(6), rs.getString(7)), session.id(), session.userId());
        if (rows.isEmpty()) throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
        AccountRow account = rows.getFirst();
        if ("DELETED".equals(account.state())) throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
        if (!"ACTIVE".equals(account.state()) && !"DELETING".equals(account.state()))
            throw new ApiError(HttpStatus.FORBIDDEN, "account_unavailable");

        List<String> providers = account.providers().isEmpty() ? List.of() :
                java.util.Arrays.stream(account.providers().split(",")).map(value -> value.toUpperCase(Locale.ROOT)).toList();
        boolean enabled = db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=? AND verified_at IS NOT NULL AND password_hash IS NOT NULL", Integer.class, account.userId()) > 0;
        boolean verified = db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=? AND verified_at IS NOT NULL", Integer.class, account.userId()) > 0;
        return new Profile(account.userId(), account.displayName(), account.email(), enabled, account.emailPending() && !enabled, verified,
                providers, account.createdAt(), "DELETING".equals(account.state()) ? "DELETING" : "NONE");
    }
}
