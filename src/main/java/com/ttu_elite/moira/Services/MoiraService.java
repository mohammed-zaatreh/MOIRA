package com.ttu_elite.moira.Services;

import com.ttu_elite.moira.Entities.MoiraAnalysisEntity;
import com.ttu_elite.moira.Repositories.MoiraRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Service
@RequiredArgsConstructor
public class MoiraService {
    private final MoiraRepository repository;
    private final ObjectMapper mapper = new ObjectMapper();

    // دالة حساب الهاش لضمان الكاش في الداتابيز
    private String calculateHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encoded = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(encoded);
    }

    /**
     * المعالجة الأساسية (الفردية): تستخدم للطلبات العادية ولتوفير الكاش
     */
    public String processGraph(String rawJson) {
        try {
            String hash = calculateHash(rawJson);

            // التحقق من وجود نتيجة سابقة في الداتابيز
            var existing = repository.findByContentHash(hash);
            if (existing.isPresent()) {
                return existing.get().getResultJson();
            }

            // تنفيذ اللوجيك إذا لم تكن مخزنة
            JsonNode root = mapper.readTree(rawJson);
            Map<String, Object> result = runMoiraLogic(root);
            String resultString = mapper.writeValueAsString(result);

            // حفظ النتيجة الجديدة
            MoiraAnalysisEntity analysis = new MoiraAnalysisEntity();
            analysis.setContentHash(hash);
            analysis.setInputJson(rawJson);
            analysis.setResultJson(resultString);
            analysis.setAnalyzedAt(LocalDateTime.now());
            repository.save(analysis);

            return resultString;

        } catch (Exception e) {
            return "{\"error\": \"ERR_PROCESSING_FAILED\", \"details\": \"" + e.getMessage() + "\"}";
        }
    }

    /**
     * تشغيل 100 محاكاة وتصدير النتائج كـ CSV مباشرة لـ Apidog
     */
    public String runBatchAnalysis(String baseRawJson) throws Exception {
        JsonNode baseRoot = mapper.readTree(baseRawJson);
        StringBuilder csvBuilder = new StringBuilder();

        // ترويسة ملف الـ CSV
        csvBuilder.append("Run_ID,Critical_Start_Node,Max_Impact,Winner_Start,Winner_Total_Impact,Path_Length,Attack_Path\n");

        for (int i = 1; i <= 100; i++) {
            // 1. توليد نسخة معدلة (Mutation) بناءً على رقم الدورة
            String mutatedJson = mutateJsonDeterministically(baseRoot, i);

            // 2. معالجة النسخة (تلقائياً سيتم استخدام الكاش أو الحفظ في DB)
            String resultJsonStr = processGraph(mutatedJson);
            JsonNode resultNode = mapper.readTree(resultJsonStr);

            // 3. إضافة النتيجة كسطر في التقرير
            csvBuilder.append(formatResultAsCsvRow(i, resultNode));
        }

        // 4. حفظ نسخة احتياطية على القرص
        String fileName = "moira_batch_results_" + System.currentTimeMillis() + ".csv";
        try (PrintWriter writer = new PrintWriter(new FileWriter(fileName))) {
            writer.print(csvBuilder.toString());
        }

        // 5. العودة بالنص الكامل لـ Apidog لعرض النتائج فوراً
        return csvBuilder.toString();
    }

    private String mutateJsonDeterministically(JsonNode baseRoot, int seed) {
        // الـ Casting الصحيح لحل مشكلة النوع (Type Mismatch)
        ObjectNode mutatedRoot = (ObjectNode) baseRoot.deepCopy();
        Random rng = new Random(seed);

        if (mutatedRoot.has("nodes")) {
            ArrayNode nodes = (ArrayNode) mutatedRoot.get("nodes");
            for (JsonNode node : nodes) {
                ObjectNode nodeObj = (ObjectNode) node;

                // تعديل القيم الرقمية بنسبة +/- 10%
                applyMutation(nodeObj, "impact", rng);
                applyMutation(nodeObj, "pivot", rng);
                applyMutation(nodeObj, "defense", rng);
            }
        }
        return mutatedRoot.toString();
    }

    private void applyMutation(ObjectNode node, String field, Random rng) {
        if (node.has(field)) {
            double currentVal = node.get(field).asDouble();
            double delta = (rng.nextDouble() * 0.6) - 0.3;
            double newVal = Math.max(0.0, Math.min(1.0, currentVal + delta));
            node.put(field, newVal);
        }
    }

    private String formatResultAsCsvRow(int runId, JsonNode res) {
        JsonNode winner = res.get("winner_details");

        // تحويل مصفوفة المسار لنص مفصول بـ | لتجنب مشاكل أعمدة الإكسل
        String path = StreamSupport.stream(winner.get("attack_path").spliterator(), false)
                .map(JsonNode::asText)
                .collect(Collectors.joining("|"));

        return String.format("%d,%s,%.4f,%s,%.4f,%d,%s\n",
                runId,
                res.get("most_critical_start_node").asText(),
                res.get("max_impact").asDouble(),
                winner.get("start_node").asText(),
                winner.get("total_impact").asDouble(),
                winner.get("path_length").asInt(),
                path
        );
    }

    // --- محرك المحاكاة الأصلي (Recursive Engine) ---
    private Map<String, Object> runMoiraLogic(JsonNode root) {
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

        List<Map<String, Object>> allScenarios = new ArrayList<>();
        double maxGlobalImpact = -1.0;
        Map<String, Object> bestScenario = null;

        for (String startId : nodeMap.keySet()) {
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

        allScenarios.sort((a, b) -> Double.compare((Double) b.get("total_impact"), (Double) a.get("total_impact")));

        Map<String, Object> finalResponse = new LinkedHashMap<>();
        finalResponse.put("most_critical_start_node", bestScenario != null ? bestScenario.get("start_node") : "none");
        finalResponse.put("max_impact", maxGlobalImpact);
        finalResponse.put("winner_details", bestScenario);
        finalResponse.put("all_scenarios", allScenarios);

        return finalResponse;
    }

    private PathResult findMaxPathRecursive(String current, LinkedHashSet<String> visited,
                                            Map<String, List<String>> adjList,
                                            Map<String, JsonNode> nodeMap) {
        visited.add(current);
        double myImpact = nodeMap.get(current).has("impact") ? nodeMap.get(current).get("impact").asDouble() : 0.0;

        double bestDownstreamImpact = 0;
        List<String> bestDownstreamPath = new ArrayList<>();

        List<String> neighbors = adjList.getOrDefault(current, Collections.emptyList());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                PathResult res = findMaxPathRecursive(neighbor, new LinkedHashSet<>(visited), adjList, nodeMap);
                if (res.totalImpact > bestDownstreamImpact) {
                    bestDownstreamImpact = res.totalImpact;
                    bestDownstreamPath = res.path;
                }
            }
        }

        List<String> finalPath = new ArrayList<>();
        finalPath.add(current);
        finalPath.addAll(bestDownstreamPath);

        return new PathResult(myImpact + bestDownstreamImpact, finalPath);
    }

    private static class PathResult {
        double totalImpact;
        List<String> path;

        PathResult(double totalImpact, List<String> path) {
            this.totalImpact = totalImpact;
            this.path = path;
        }
    }
}