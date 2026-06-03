package com.nyaysetu.backend.controller;

import com.nyaysetu.backend.service.DigitalSignatureService;
import com.nyaysetu.backend.service.DigitalSignatureService.SignatureMetadata;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/signatures")
@RequiredArgsConstructor
public class DigitalSignatureController {

    private final DigitalSignatureService digitalSignatureService;

    @PostMapping("/sign")
    @PreAuthorize("hasAnyRole('LAWYER', 'LITIGANT')")
    public ResponseEntity<SignatureMetadata> signDocument(
            @RequestParam String documentId,
            @RequestParam String signerName) {
        SignatureMetadata metadata = digitalSignatureService.signDocument(documentId, signerName);
        return ResponseEntity.ok(metadata);
    }

    @GetMapping("/verify/{signatureHash}")
    public ResponseEntity<Boolean> verifySignature(@PathVariable String signatureHash) {
        boolean isValid = digitalSignatureService.verifySignature(signatureHash);
        return ResponseEntity.ok(isValid);
    }
}
