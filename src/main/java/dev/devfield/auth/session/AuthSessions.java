package dev.devfield.auth.session;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.util.Secrets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthSessions {
    public record State(UUID id, UUID userId, String userState, boolean active) {}
    private final JdbcTemplate db;
    public AuthSessions(JdbcTemplate db) { this.db = db; }

    public State byHandle(String handle) {
        if (handle == null || !handle.matches("[A-Za-z0-9_-]{43}"))
            throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
        List<State> rows = db.query("SELECT s.id,s.user_id,u.state,s.revoked_at IS NULL AND s.expires_at>now() " +
                        "FROM auth.auth_session s JOIN auth.devfield_user u ON u.id=s.user_id WHERE s.session_handle_hash=?",
                (rs, i) -> new State(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3), rs.getBoolean(4)),
                Secrets.sha256(handle));
        if (rows.isEmpty()) throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
        return rows.getFirst();
    }

    public State byId(UUID id, UUID userId) {
        List<State> rows = db.query("SELECT s.id,s.user_id,u.state,s.revoked_at IS NULL AND s.expires_at>now() " +
                        "FROM auth.auth_session s JOIN auth.devfield_user u ON u.id=s.user_id WHERE s.id=? AND s.user_id=?",
                (rs, i) -> new State(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3), rs.getBoolean(4)), id, userId);
        if (rows.isEmpty()) throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
        return rows.getFirst();
    }

    @Transactional
    public void logout(String handle) {
        State session = byHandle(handle);
        if (!session.active()) {
            Integer exists = db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE id=? AND revoked_at IS NOT NULL AND expires_at>now()",
                    Integer.class, session.id());
            if (exists != null && exists == 1) return;
            throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
        }
        db.update("UPDATE auth.auth_session SET revoked_at=? WHERE id=? AND revoked_at IS NULL", java.sql.Timestamp.from(Instant.now()), session.id());
    }

    public void requireActive(State state) {
        if (!state.active()) throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
        if (!"ACTIVE".equals(state.userState())) throw new ApiError(HttpStatus.FORBIDDEN, "account_unavailable");
    }
}
