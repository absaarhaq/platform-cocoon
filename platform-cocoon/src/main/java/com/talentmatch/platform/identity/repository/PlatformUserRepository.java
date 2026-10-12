package com.talentmatch.platform.identity.repository;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.talentmatch.platform.identity.entity.PlatformUserEntity;

public interface PlatformUserRepository extends JpaRepository<PlatformUserEntity, Long> {
	
	Optional<PlatformUserEntity> findByUsername(String username);

    Optional<PlatformUserEntity> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

}
