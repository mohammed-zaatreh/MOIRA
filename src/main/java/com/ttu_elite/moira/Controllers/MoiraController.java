package com.ttu_elite.moira.Controllers;

import com.ttu_elite.moira.Services.MoiraService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/moira") // هاد هو المسار الأساسي
@RequiredArgsConstructor
public class MoiraController {

    private final MoiraService moiraService;

    // الميثود القديمة للتحليل الفردي
    @PostMapping("/analyze")
    public String analyze(@RequestBody String json) {
        return moiraService.processGraph(json);
    }

    // الميثود الجديدة اللي لازم تضيفها للـ 100 تجربة
    @PostMapping("/batch")
    public String batchAnalyze(@RequestBody String json) throws Exception {
        // بنادي ميثود الـ 100 محاكاة وبنرجع الـ CSV لـ Apidog
        return moiraService.runBatchAnalysis(json);
    }
}