package com.mycompany.zullgateway.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

public class PreFilter extends ZuulFilter {

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        var requestContext = RequestContext.getCurrentContext();
        var httpServletRequest = requestContext.getRequest();

        System.out.println(
                "Request Method : " + httpServletRequest.getMethod() + " Request URL : " + httpServletRequest.getRequestURL().toString());

        return null;
    }

}
