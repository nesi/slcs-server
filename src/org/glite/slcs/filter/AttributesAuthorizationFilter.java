/*
 * Copyright (c) Members of the EGEE Collaboration. 2004. 
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.  
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 * 
 * $Id: AttributesAuthorizationFilter.java,v 1.8 2007/11/13 14:34:42 vtschopp Exp $
 */
package org.glite.slcs.filter;

import java.io.IOException;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.SLCSException;
import org.glite.slcs.acl.AccessControlList;
import org.glite.slcs.acl.AccessControlListFactory;
import org.glite.slcs.attribute.AttributeDefinitions;
import org.glite.slcs.attribute.AttributeDefinitionsFactory;
import org.glite.slcs.config.Log4JConfiguration;

/**
 * AttributesAuthorizationFilter is an ACL filter based on Shibboleth
 * attributes. The filter uses the underlying AccessControlList implementation
 * to checks if the user is authorized.
 * 
 * @author Valery Tschopp <tschopp@switch.ch>
 * @version $Revision: 1.8 $
 * @see org.glite.slcs.acl.AccessControlList
 */
public class AttributesAuthorizationFilter implements Filter {

    /** Logging */
    private static Log LOG = LogFactory.getLog(AttributesAuthorizationFilter.class);

    /** Attributes ACL */
    private AccessControlList accessControlList_ = null;

    /** Attribute definitions */
    private AttributeDefinitions attributeDefinitions_ = null;

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    public void init(FilterConfig filterConfig) throws ServletException {

        ServletContext context = filterConfig.getServletContext();
        // try to configure log4j
        Log4JConfiguration.configure(context);

        try {
            LOG.info("create and initialize new AccessControlList");
            accessControlList_ = AccessControlListFactory.newInstance(filterConfig);
        } catch (SLCSException e) {
            LOG.error("Failed to instantiate and initalize AccessControlList",
                    e);
            throw new ServletException(
                    "Failed to instantiate and initalize AccessControlList: "
                            + e, e);
        }
        
        // initialize the AttributeDefintions from the servlet context
        try {
            AttributeDefinitionsFactory.initialize(context);
            attributeDefinitions_ = AttributeDefinitionsFactory.getInstance();
        } catch (SLCSException e) {
            LOG.error("Failed to instantiate AttributeDefinitions", e);
            throw new ServletException(
                    "Failed to initialize and create the AttributeDefinitions: " + e, e);
        }
    }

    /**
     * Checks if the user Shibboleth attributes grant him access.
     */
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        boolean authorized = true;
        List userAttributes = null;
        if (request instanceof HttpServletRequest) {
            authorized = false;
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            LOG.info("check authorization: " + httpRequest.getRequestURI());
            // get shib user attributes
            userAttributes = attributeDefinitions_.getUserAttributes(httpRequest);
            // check if user is authorized
            authorized = accessControlList_.isAuthorized(userAttributes);

        }
        if (!authorized) {
            String remoteAddress = request.getRemoteAddr();
            LOG.error(HttpServletResponse.SC_UNAUTHORIZED + ": User (IP:"
                    + remoteAddress + ") is not authorized: " + userAttributes);
            // TODO: custom 401 error page
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Based on your Shibboleth attributes, you are not authorized to access this service");
        }
        else {
            // user is authorized or not a HttpServletRequest, continue
            chain.doFilter(request, response);
        }
    }

    /**
     * Releases all resources
     */
    public void destroy() {
        LOG.info("shutdown ACL implementation");
        accessControlList_.shutdown();
    }

}
