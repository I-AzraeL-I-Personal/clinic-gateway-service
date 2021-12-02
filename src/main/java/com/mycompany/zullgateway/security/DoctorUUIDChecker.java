package com.mycompany.zullgateway.security;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

import static com.mycompany.zullgateway.security.JwtProperties.TOKEN_CLAIM_UUID;
import static com.netflix.zuul.context.RequestContext.getCurrentContext;
import static org.springframework.util.ReflectionUtils.rethrowRuntimeException;

//@Component
public class DoctorUUIDChecker extends ZuulFilter {

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 6;
    }

    @Override
    public boolean shouldFilter() {
        return getCurrentContext().getRequest().getRequestURI().equals("/api/doctor/")
                && getCurrentContext().getRequest().getMethod().equals("POST");
    }

    public Object run() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String uuidFromAuthentication = (String) ((HashMap<String, Object>) authentication.getCredentials()).get(TOKEN_CLAIM_UUID);
        try {
            RequestContext context = getCurrentContext();
            InputStream in = (InputStream) context.get("requestEntity");
            if (in == null) {
                in = context.getRequest().getInputStream();
            }
            String body = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
            body = body.replaceAll("(?<=UUID\"(\\s):(\\s?))(\"[^\"]*\")", "UUID\":\"" +
                    uuidFromAuthentication);
            context.set("requestEntity", new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        }
        catch (IOException e) {
            rethrowRuntimeException(e);
        }
        return null;
    }
}
