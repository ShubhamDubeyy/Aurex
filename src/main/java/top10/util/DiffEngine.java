package top10.util;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;

public final class DiffEngine {

    private static final double DEFAULT_LENGTH_THRESHOLD = 0.15;

    private DiffEngine() {}

    public static boolean responsesDiffer(HttpRequestResponse baseline, HttpRequestResponse probe) {
        if (baseline == null || probe == null) return baseline != probe;
        if (hasNoResponse(baseline) || hasNoResponse(probe)) return true;
        if (statusDiffers(baseline, probe)) return true;
        if (lengthDiffers(baseline, probe, DEFAULT_LENGTH_THRESHOLD)) return true;
        return bodySimilarity(baseline, probe) < (1.0 - DEFAULT_LENGTH_THRESHOLD);
    }

    public static boolean statusDiffers(HttpRequestResponse a, HttpRequestResponse b) {
        if (hasNoResponse(a) || hasNoResponse(b)) return true;
        return a.response().statusCode() != b.response().statusCode();
    }

    public static boolean lengthDiffers(HttpRequestResponse a, HttpRequestResponse b, double thresholdPercent) {
        int lenA = bodyLength(a);
        int lenB = bodyLength(b);
        int maxLen = Math.max(lenA, lenB);
        if (maxLen == 0) return false;
        double ratio = Math.abs(lenA - lenB) / (double) maxLen;
        return ratio > thresholdPercent;
    }

    public static int lengthDelta(HttpRequestResponse a, HttpRequestResponse b) {
        return Math.abs(bodyLength(a) - bodyLength(b));
    }

    public static boolean exclusiveContains(HttpRequestResponse a, HttpRequestResponse b, String search) {
        boolean inA = containsIgnoreCase(safeBody(a), search);
        boolean inB = containsIgnoreCase(safeBody(b), search);
        return inA != inB;
    }

    public static double bodySimilarity(HttpRequestResponse a, HttpRequestResponse b) {
        int lenA = bodyLength(a);
        int lenB = bodyLength(b);
        int maxLen = Math.max(lenA, lenB);
        if (maxLen == 0) return 1.0;
        return 1.0 - ((double) Math.abs(lenA - lenB) / maxLen);
    }

    private static boolean hasNoResponse(HttpRequestResponse reqResp) {
        return reqResp == null || reqResp.response() == null;
    }

    private static String safeBody(HttpRequestResponse reqResp) {
        if (hasNoResponse(reqResp)) return "";
        String body = reqResp.response().bodyToString();
        return body != null ? body : "";
    }

    private static int bodyLength(HttpRequestResponse reqResp) {
        return safeBody(reqResp).length();
    }

    private static boolean containsIgnoreCase(String text, String search) {
        if (text == null || search == null) return false;
        return text.toLowerCase(Locale.ROOT).contains(search.toLowerCase(Locale.ROOT));
    }
}
