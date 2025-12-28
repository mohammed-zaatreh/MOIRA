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

        // 2. Run Simulation for EVERY Node
        List<Map<String, Object>> allScenarios = new ArrayList<>();

        // Variables to track the winner
        Map<String, Object> bestScenario = null;
        double maxGlobalImpact = -1.0;

        for (String startId : nodeMap.keySet()) {
            List<String> currentPath = new ArrayList<>();
            Set<String> visited = new HashSet<>();
            double currentTotalImpact = 0;
            String curr = startId;

            // The Greedy Traversal Loop
            while (curr != null) {
                visited.add(curr);
                currentPath.add(curr);

                // Add impact (default to 0 if missing)
                double nodeImpact = nodeMap.get(curr).has("impact")
                        ? nodeMap.get(curr).get("impact").asDouble()
                        : 0.0;

                currentTotalImpact += nodeImpact;

                // Find best neighbor
                List<String> neighbors = adjList.getOrDefault(curr, Collections.emptyList());
                String nextNode = null;
                double maxNeighborImpact = -1;

                for (String neighbor : neighbors) {
                    if (!visited.contains(neighbor)) {
                        double imp = nodeMap.get(neighbor).has("impact")
                                ? nodeMap.get(neighbor).get("impact").asDouble()
                                : 0.0;

                        if (imp > maxNeighborImpact) {
                            maxNeighborImpact = imp;
                            nextNode = neighbor;
                        }
                    }
                }
                curr = nextNode;
            }

            // Store this specific scenario
            Map<String, Object> scenario = new HashMap<>();
            scenario.put("start_node", startId);
            scenario.put("total_impact", currentTotalImpact);
            scenario.put("path_length", currentPath.size());
            scenario.put("attack_path", currentPath);

            allScenarios.add(scenario);

            // Update Global Winner
            if (currentTotalImpact > maxGlobalImpact) {
                maxGlobalImpact = currentTotalImpact;
                bestScenario = scenario;
            }
        }

        // 3. Sort all scenarios by impact (Highest First) for easier reading
        allScenarios.sort((a, b) -> Double.compare(
                (Double) b.get("total_impact"),
                (Double) a.get("total_impact")
        ));

        // 4. Construct Final Response
        Map<String, Object> finalResponse = new LinkedHashMap<>();
        finalResponse.put("most_critical_start_node", bestScenario != null ? bestScenario.get("start_node") : "none");
        finalResponse.put("max_impact", maxGlobalImpact);
        finalResponse.put("winner_details", bestScenario);
        finalResponse.put("all_scenarios", allScenarios); // <--- The list you asked for

        return finalResponse;
    }

    private String calculateHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encoded = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(encoded);
    }
}
