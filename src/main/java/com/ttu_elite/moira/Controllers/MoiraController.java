package com.ttu_elite.moira.Controllers;


import com.ttu_elite.moira.Services.MoiraService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/moira")
@RequiredArgsConstructor
public class MoiraController {


    private final MoiraService service;

    @PostMapping("/analyze")
    public ResponseEntity<String> analyze(@RequestBody String jsonGraph) {
        // Direct pass-through to service
        String response = service.processGraph(jsonGraph);

        if (response.contains("ERR_PROCESSING_FAILED")) {
            return ResponseEntity.internalServerError().body(response);
        }

        return ResponseEntity.ok(response);
    }
}
