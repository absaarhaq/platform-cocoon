package com.talentmatch.platform.shared.util;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public class CandidateIdGenerator {
	
	private CandidateIdGenerator() {}
	
	/**
     * Replicates Python: f"CAND-{YYYYMMDD}-{8-char-uuid-hex-upper}"
     */
    public static String generate() {
        String datePart = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
        String uniquePart = UUID.randomUUID().toString().replace("-", "").substring(0, 8).toUpperCase();
        return "CAND-" + datePart + "-" + uniquePart;
    }

}
