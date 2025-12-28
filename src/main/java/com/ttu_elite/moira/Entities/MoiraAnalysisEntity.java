package com.ttu_elite.moira.Entities;


import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "moira_analysis")
@Data
public class MoiraAnalysisEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "content_hash", unique = true)
    private String contentHash;

    @Column(name = "input_json", columnDefinition = "TEXT")
    private String inputJson;

    @Column(name = "result_json", columnDefinition = "TEXT")
    private String resultJson;

    @Column(name = "analyzed_at")
    private LocalDateTime analyzedAt;
}
