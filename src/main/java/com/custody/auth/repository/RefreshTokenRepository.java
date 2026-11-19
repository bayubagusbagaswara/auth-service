package com.custody.auth.repository;

import com.custody.auth.entity.RefreshTokenEntity;
import jakarta.persistence.LockModeType;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<@NonNull RefreshTokenEntity, @NonNull Long> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT r
            FROM RefreshTokenEntity r
            WHERE r.tokenHash = :tokenHash
            """)
    Optional<RefreshTokenEntity> findByTokenHashForUpdate(
            @Param("tokenHash") String tokenHash
    );

    List<RefreshTokenEntity> findByUsernameAndRevokedAtIsNull(String username);


    List<RefreshTokenEntity> findByTokenFamilyId(String tokenFamilyId);


    boolean existsByTokenHash(String tokenHash);

}
