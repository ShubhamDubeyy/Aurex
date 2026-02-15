package top10.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;
import java.util.Set;

public class HttpHelper {

    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".js", ".css", ".png", ".jpg", ".gif", ".svg",
            ".woff", ".woff2", ".ico", ".map", ".ttf", ".eot"
    );

    private final MontoyaApi api;

    public HttpHelper(MontoyaApi api) {
        this.api = api;
    }

    public HttpRequestResponse sendRequest(HttpRequest request) {
        return api.http().sendRequest(request);
    }

    public HttpRequest addHeader(HttpRequest original, String headerName, String headerValue) {
        return original.withAddedHeader(headerName, headerValue);
    }

    public HttpRequest setParameter(HttpRequest original, String paramName, String paramValue, HttpParameterType type) {
        return original.withParameter(HttpParameter.parameter(paramName, paramValue, type));
    }

    public static String bodyToString(HttpRequestResponse reqResp) {
        if (reqResp == null || reqResp.response() == null) return "";
        String body = reqResp.response().bodyToString();
        return body != null ? body : "";
    }

    public static int statusCode(HttpRequestResponse reqResp) {
        if (reqResp == null || reqResp.response() == null) return 0;
        return reqResp.response().statusCode();
    }

    public static boolean bodyContains(HttpRequestResponse reqResp, String search) {
        if (reqResp == null || reqResp.response() == null || search == null) return false;
        String body = reqResp.response().bodyToString();
        if (body == null) return false;
        return body.toLowerCase(Locale.ROOT).contains(search.toLowerCase(Locale.ROOT));
    }

    public static boolean isStaticAsset(HttpRequest request) {
        String path = request.path();
        if (path == null) return false;

        int queryIdx = path.indexOf('?');
        if (queryIdx != -1) path = path.substring(0, queryIdx);
        int fragmentIdx = path.indexOf('#');
        if (fragmentIdx != -1) path = path.substring(0, fragmentIdx);

        String lower = path.toLowerCase(Locale.ROOT);
        for (String ext : STATIC_EXTENSIONS) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    public static String getResponseHeader(HttpRequestResponse reqResp, String headerName) {
        if (reqResp == null || reqResp.response() == null) return "";
        String value = reqResp.response().headerValue(headerName);
        return value != null ? value : "";
    }
}
