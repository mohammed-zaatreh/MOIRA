package com.ttu_elite.moira.Repositories;

import com.ttu_elite.moira.Entities.MoiraAnalysisEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MoiraRepository extends JpaRepository<MoiraAnalysisEntity, Long> {
    Optional<MoiraAnalysisEntity> findByContentHash(String contentHash);
}