package com.ttu_elite.moira.Services;


import com.ttu_elite.moira.Entities.MoiraAnalysisEntity;
import com.ttu_elite.moira.Repositories.MoiraRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class MoiraService {
    private final MoiraRepository repository;
    private final ObjectMapper mapper = new ObjectMapper();

    private String calculateHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encoded = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(encoded);
    }

    public String processGraph(String rawJson) {
        try {
            String hash = calculateHash(rawJson);

            // Check DB cache
            var existing = repository.findByContentHash(hash);
            if (existing.isPresent()) {
                System.out.println("Returning cached result from DB.");
                return existing.get().getResultJson();
            }

            // Parse and Analyze
            JsonNode root = mapper.readTree(rawJson);
            Map<String, Object> result = runMoiraLogic(root);
            String resultString = mapper.writeValueAsString(result);

            // Save to DB
            MoiraAnalysisEntity analysis = new MoiraAnalysisEntity();
            analysis.setContentHash(hash);
            analysis.setInputJson(rawJson);
            analysis.setResultJson(resultString);
            analysis.setAnalyzedAt(LocalDateTime.now());
            repository.save(analysis);

            return resultString;

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"error\": \"ERR_PROCESSING_FAILED\", \"details\": \"" + e.getMessage() + "\"}";
        }
    }
    private Map<String, Object> runMoiraLogic(JsonNode root) {
        // 1. Parse Graph
        Map<String, JsonNode> nodeMap = new HashMap<>();
        Map<String, List<String>> adjList = new HashMap<>();

        JsonNode nodes = root.get("nodes");
        JsonNode edges = root.get("edges");

        if (nodes != null) {
            for (JsonNode n : nodes) {
                nodeMap.put(n.get("id").asText(), n);
            }
        }

        if (edges != null) {
            for (JsonNode e : edges) {
                String from = e.get("from").asText();
                String to = e.get("to").asText();
                adjList.computeIfAbsent(from, k -> new ArrayList<>()).add(to);
            }
        }

        // 2. Global Exhaustive Simulation
        List<Map<String, Object>> allScenarios = new ArrayList<>();
        double maxGlobalImpact = -1.0;
        Map<String, Object> bestScenario = null;

        for (String startId : nodeMap.keySet()) {
            // Find the absolute best path starting from this node by exploring ALL directions
            PathResult result = findMaxPathRecursive(startId, new LinkedHashSet<>(), adjList, nodeMap);

            Map<String, Object> scenario = new HashMap<>();
            scenario.put("start_node", startId);
            scenario.put("total_impact", result.totalImpact);
            scenario.put("path_length", result.path.size());
            scenario.put("attack_path", result.path);

            allScenarios.add(scenario);

            if (result.totalImpact > maxGlobalImpact) {
                maxGlobalImpact = result.totalImpact;
                bestScenario = scenario;
            }
        }

        // 3. Sort by Impact
        allScenarios.sort((a, b) -> Double.compare((Double) b.get("total_impact"), (Double) a.get("total_impact")));

        // 4. Response
        Map<String, Object> finalResponse = new LinkedHashMap<>();
        finalResponse.put("most_critical_start_node", bestScenario != null ? bestScenario.get("start_node") : "none");
        finalResponse.put("max_impact", maxGlobalImpact);
        finalResponse.put("winner_details", bestScenario);
        finalResponse.put("all_scenarios", allScenarios);

        return finalResponse;
    }

    /**
     * This is the O(2^n) engine. It explores every possible unique path
     * from the current node and returns the one with the highest weight.
     */
    private PathResult findMaxPathRecursive(String current, LinkedHashSet<String> visited,
                                            Map<String, List<String>> adjList,
                                            Map<String, JsonNode> nodeMap) {
        // Mark node as visited in this specific path branch
        visited.add(current);

        double myImpact = nodeMap.get(current).has("impact") ? nodeMap.get(current).get("impact").asDouble() : 0.0;

        double bestDownstreamImpact = 0;
        List<String> bestDownstreamPath = new ArrayList<>();

        // Explore EVERY neighbor
        List<String> neighbors = adjList.getOrDefault(current, Collections.emptyList());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                // RECURSION: This "branches" the simulation into a new universe
                // We pass a copy of 'visited' (LinkedHashSet) to keep path history local to this branch
                PathResult res = findMaxPathRecursive(neighbor, new LinkedHashSet<>(visited), adjList, nodeMap);

                if (res.totalImpact > bestDownstreamImpact) {
                    bestDownstreamImpact = res.totalImpact;
                    bestDownstreamPath = res.path;
                }
            }
        }

        // Build result for this node
        List<String> finalPath = new ArrayList<>();
        finalPath.add(current);
        finalPath.addAll(bestDownstreamPath);

        return new PathResult(myImpact + bestDownstreamImpact, finalPath);
    }

    // Static helper class for path results
    private static class PathResult {
        double totalImpact;
        List<String> path;

        PathResult(double totalImpact, List<String> path) {
            this.totalImpact = totalImpact;
            this.path = path;
        }
    }
}
