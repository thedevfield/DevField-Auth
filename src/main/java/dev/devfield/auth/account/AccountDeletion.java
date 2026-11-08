package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.oauth.OAuthDeletionFence;
import dev.devfield.auth.session.AuthSessions;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class AccountDeletion {
    private static final Logger log = LoggerFactory.getLogger(AccountDeletion.class);
    private record Claim(UUID job, boolean projectDone, boolean interviewDone) {}

    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final AuthSessions sessions;
    private final AccountChanges changes;
    private final AccountDeletionClient client;

    AccountDeletion(JdbcTemplate db, TransactionTemplate tx, AuthSessions sessions,
                    AccountChanges changes, AccountDeletionClient client) {
        this.db = db;
        this.tx = tx;
        this.sessions = sessions;
        this.changes = changes;
        this.client = client;
    }

    public boolean request(String handle, String proof) {
        UUID user = tx.execute(status -> {
            var session = sessions.byHandle(handle);
            UUID owner = session.userId();
            sessions.lockUser(owner);
            session = sessions.byHandle(handle);
            if (!session.active()) throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_session");
            if ("DELETING".equals(session.userState())) return owner;
            sessions.requireActive(session);
            if (!client.configured()) throw new ApiError(HttpStatus.SERVICE_UNAVAILABLE, "deletion_unavailable");
            changes.consumeProof(proof, session);
            db.update("UPDATE auth.devfield_user SET state='DELETING',updated_at=now() WHERE id=?", owner);
            db.update("INSERT INTO auth.account_deletion(user_id,job_id) VALUES (?,?)", owner, UUID.randomUUID());
            return owner;
        });
        if (client.configured()) process(user);
        return Boolean.TRUE.equals(db.queryForObject(
                "SELECT completed_at IS NOT NULL FROM auth.account_deletion WHERE user_id=?", Boolean.class, user));
    }

    @Scheduled(fixedDelayString = "${devfield.auth.deletion.poll-ms:5000}",
            initialDelayString = "${devfield.auth.deletion.poll-ms:5000}")
    public void poll() {
        if (!client.configured()) return;
        var due = db.query("""
                SELECT user_id FROM auth.account_deletion WHERE completed_at IS NULL AND next_attempt_at<=clock_timestamp()
                ORDER BY next_attempt_at,user_id LIMIT 1
                """, (rs, row) -> rs.getObject(1, UUID.class));
        if (!due.isEmpty()) process(due.getFirst());
    }

    private void process(UUID user) {
        UUID attempt = UUID.randomUUID();
        var claimed = db.query("""
                UPDATE auth.account_deletion SET claim_id=?,next_attempt_at=clock_timestamp()+interval '1 minute'
                WHERE user_id=? AND completed_at IS NULL AND next_attempt_at<=clock_timestamp()
                RETURNING job_id,project_completed_at IS NOT NULL,interview_completed_at IS NOT NULL
                """, (rs, row) -> new Claim(rs.getObject(1, UUID.class), rs.getBoolean(2), rs.getBoolean(3)),
                attempt, user);
        if (claimed.isEmpty()) return;
        Claim claim = claimed.getFirst();
        try {
            boolean projectDone = claim.projectDone() || deliver(true, user, claim.job(), attempt);
            boolean interviewDone = claim.interviewDone() || deliver(false, user, claim.job(), attempt);
            if (projectDone && interviewDone) tx.executeWithoutResult(status -> finish(user, attempt));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            db.update("""
                    UPDATE auth.account_deletion SET claim_id=NULL,next_attempt_at=clock_timestamp()+interval '30 seconds'
                    WHERE user_id=? AND claim_id=? AND completed_at IS NULL
                    """, user, attempt);
        }
    }

    private boolean deliver(boolean project, UUID user, UUID job, UUID attempt) throws InterruptedException {
        int status = client.delete(project, user, job);
        if (status != 204) {
            log.warn("Account deletion job {}: {} returned {}", job, project ? "X-03" : "X-04", status);
            return false;
        }
        String sql = project
                ? "UPDATE auth.account_deletion SET project_completed_at=clock_timestamp() WHERE user_id=? AND claim_id=?"
                : "UPDATE auth.account_deletion SET interview_completed_at=clock_timestamp() WHERE user_id=? AND claim_id=?";
        return db.update(sql, user, attempt) == 1;
    }

    private void finish(UUID user, UUID attempt) {
        OAuthDeletionFence.lock(db);
        if (!"DELETING".equals(sessions.lockUser(user))) return;
        var ready = db.query("""
                SELECT job_id FROM auth.account_deletion WHERE user_id=? AND claim_id=? AND completed_at IS NULL
                AND project_completed_at IS NOT NULL AND interview_completed_at IS NOT NULL FOR UPDATE
                """, (rs, row) -> rs.getObject(1, UUID.class), user, attempt);
        if (ready.isEmpty()) return;
        db.update("DELETE FROM auth.action_token WHERE user_id=? AND parent_intent_id IS NOT NULL", user);
        db.update("""
                DELETE FROM auth.action_token WHERE user_id=? OR email_credential_id IN
                (SELECT id FROM auth.email_credential WHERE user_id=?)
                """, user, user);
        db.update("DELETE FROM auth.auth_session WHERE user_id=?", user);
        OAuthDeletionFence.invalidate(db, user);
        db.update("DELETE FROM auth.social_identity WHERE user_id=?", user);
        db.update("DELETE FROM auth.email_credential WHERE user_id=?", user);
        db.update("UPDATE auth.devfield_user SET state='DELETED',display_name=NULL,updated_at=now() WHERE id=?", user);
        db.update("UPDATE auth.account_deletion SET completed_at=clock_timestamp(),claim_id=NULL WHERE user_id=?", user);
    }
}
