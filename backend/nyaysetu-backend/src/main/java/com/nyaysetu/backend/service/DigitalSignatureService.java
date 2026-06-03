package com.nyaysetu.backend.service;

import org.springframework.stereotype.Service;
import lombok.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DigitalSignatureService {

    private final ConcurrentHashMap<String, SignatureMetadata> signatureRegistry = new ConcurrentHashMap<>();

    @Builder
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SignatureMetadata {
        private String documentId;
        private String signerName;
        private String signatureHash;
        private LocalDateTime timestamp;
        private boolean isValid;
    }

    public SignatureMetadata signDocument(String documentId, String signerName) {
        if (documentId == null || signerName == null) {
            throw new IllegalArgumentException("Document ID and Signer Name cannot be null");
        }

        String rawPayload = documentId + ":" + signerName + ":" + UUID.randomUUID().toString() + ":" + LocalDateTime.now();
        String signatureHash = generateSha256(rawPayload);

        SignatureMetadata metadata = new SignatureMetadata();
        metadata.setDocumentId(documentId);
        metadata.setSignerName(signerName);
        metadata.setSignatureHash(signatureHash);
        metadata.setTimestamp(LocalDateTime.now());
        metadata.setValid(true);

        signatureRegistry.put(signatureHash, metadata);
        return metadata;
    }

    public boolean verifySignature(String signatureHash) {
        if (signatureHash == null) {
            return false;
        }
        SignatureMetadata metadata = signatureRegistry.get(signatureHash);
        return metadata != null && metadata.isValid();
    }

    private String generateSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
