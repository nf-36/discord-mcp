package dev.saseq.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class ApiKeyFilter implements Filter {

    @Value("${MCP_API_KEY:}")
    private String apiKey;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();
        
        // Only apply to MCP endpoint
        if ("/mcp".equals(path)) {
            // If API key is not set in environment, allow all (or block all? user said secure it)
            // Given the instruction "secure the endpoint... validated against an environment variable", 
            // I should assume if it's set, it must match. If it's NOT set, what then?
            // Usually, if security is requested, no key = unauthorized if a key is expected.
            
            if (apiKey != null && !apiKey.isEmpty()) {
                String requestKey = httpRequest.getHeader("X-API-Key");
                if (requestKey == null) {
                    requestKey = httpRequest.getHeader("Authorization");
                    if (requestKey != null && requestKey.startsWith("Bearer ")) {
                        requestKey = requestKey.substring(7);
                    }
                }

                if (!apiKey.equals(requestKey)) {
                    httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    httpResponse.getWriter().write("Unauthorized: Invalid or missing API Key");
                    return;
                }
            }
        }

        chain.doFilter(request, response);
    }
}
