package au.org.arcs.slcs.servlet;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.SLCSException;
import org.glite.slcs.attribute.Attribute;
import org.glite.slcs.audit.event.AuditEvent;
import org.glite.slcs.audit.event.AuthorizationEvent;
import org.glite.slcs.audit.event.SystemEvent;
import org.glite.slcs.dn.DNBuilder;
import org.glite.slcs.pki.CertificateExtension;
import org.glite.slcs.policy.CertificatePolicy;
import org.glite.slcs.servlet.CertificateServlet;
import org.glite.slcs.servlet.LoginServlet;
import org.glite.slcs.session.SLCSSession;
import org.glite.slcs.session.SLCSSessions;

import au.org.arcs.slcs.utils.CryptoUtil;
import au.org.arcs.slcs.utils.CryptoUtil.HybridEncResult;
import au.org.arcs.slcs.whitelist.WhitelistService;
import au.org.arcs.slcs.whitelist.WhitelistServiceImpl;


public class TokenServlet extends LoginServlet {

    private static final long serialVersionUID = 8858107566715074310L;
    private static final String SERVLET_PATH = "/token";
    private static final String SERVICE_PARAM = "service";
    private static final String PARAM_WHITELIST_FILE = "TokenServletWhitelist";
    private static final String PARAM_SERVICE_CERT_DIR = "ServiceCertDir";
    
	/** Logging */
    private static Log LOG = LogFactory.getLog(CertificateServlet.class);
    
    private static String whitelist = null;
    private static String serviceCertDir = null;
    
    public void init(ServletConfig servletConfig) throws ServletException {
    	super.init(servletConfig);
    	ServletContext context = servletConfig.getServletContext();
    	whitelist = context.getInitParameter(PARAM_WHITELIST_FILE);
    	serviceCertDir = context.getInitParameter(PARAM_SERVICE_CERT_DIR);
    	LOG.debug("White list: " + whitelist);
    	LOG.debug("Service certificate directory: " + serviceCertDir);
    }
    
	@Override
	protected void doProcess(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

	        LOG.debug("doProcess...");

	        // read AAF Shibboleth attributes
	        List userAttributes = getUserAttributes(req);
	        // read the remote IP and UserAgent
	        Attribute remoteAddress = getRemoteAddressAttribute(req);
	        userAttributes.add(remoteAddress);
	        Attribute userAgent = getUserAgentAttribute(req);
	        userAttributes.add(userAgent);

	        try {
	        	
	        	String service = getRequestParameter(req, SERVICE_PARAM);
	        	LOG.debug("Got return URL string: " + service);
	        	String return_host = new URL(service).getHost();
	        	
	        	// Check return URL against whitelist
	        	WhitelistService wl = new WhitelistServiceImpl(whitelist);
	        	if (!wl.isInWhitelist(service)) {
	        		throw new SLCSException("This service isn't authorised to access the SLCS Delegation Service");
	        	}
	            // check required attributes
	            checkRequiredAttributes(userAttributes);
	            
	            AuditEvent login = new AuthorizationEvent("Token login", userAttributes);
	            getAuditor().logEvent(login);

	            // create a new DN
	            DNBuilder builder = getDNBuilder();
	            String dn = builder.createDN(userAttributes);
	            // store the new DN in sessions and get authorization token
	            SLCSSessions sessions = getSLCSSessions();
	            SLCSSession session = sessions.createSession(dn);
	            // store attributes in session
	            session.setAttributes(userAttributes);

	            LOG.info("Session created: " + session);

	            String authToken = session.getToken();
	            CertificatePolicy policy = getCertificatePolicy();
	            List extensions = policy.getRequiredCertificateExtensions(userAttributes);
	            String reqUrl = getContextUrl(req, "/certificate");
	            
	            
	            sendLoginResponse(req, res, authToken, reqUrl, dn, extensions, service);
	      
	        } catch (SLCSException e) {
	            LOG.error("Processing error: " + e);
	            sendXMLErrorResponse(req, res, "SLCSLoginResponse", e.getMessage(), e);

	            try {
	                SystemEvent error = new SystemEvent(AuditEvent.LEVEL_ERROR, e.getMessage(), userAttributes);
	                getAuditor().logEvent(error);
	            } catch (SLCSException e1) {
	                LOG.error("Audit error: " + e1);
	            }

	        }	
			
	}
	
    protected String getRequestParameter(
            HttpServletRequest request, String name) throws SLCSException {
        String value = request.getParameter(name);
        if (value == null || value.equals("")) {
            LOG.error("Request parameter " + name + " is missing or empty.");
            throw new SLCSException("Request parameter " + name
                    + " is missing or empty");
        }
        return value;
    }
    
    
    protected void sendLoginResponse(HttpServletRequest req,
            HttpServletResponse res, String authToken, String requestURL,
            String certDN, List certExtensions, String service) throws IOException,
            ServletException, SLCSException {
        // build response
        StringBuffer buf = new StringBuffer();
        buf.append(getXMLDeclaration()).append("\n");

        // send response
        buf.append("<SLCSLoginResponse>").append("\n");
        buf.append("<Status>Success</Status>").append("\n");
        buf.append("<AuthorizationToken>");
        buf.append(authToken);
        buf.append("</AuthorizationToken>").append("\n");
        // request URL
        buf.append("<CertificateRequest url=\"");
        buf.append(requestURL);
        buf.append("\">").append("\n");
        buf.append("<Subject>");
        buf.append(certDN);
        buf.append("</Subject>").append("\n");

        if (certExtensions != null && !certExtensions.isEmpty()) {
            // add certificate extensions
            Iterator extensions = certExtensions.iterator();
            while (extensions.hasNext()) {
                CertificateExtension extension = (CertificateExtension) extensions.next();
                buf.append(extension.toXML()).append("\n");
            }
        }
        buf.append("</CertificateRequest>").append("\n");
        buf.append("</SLCSLoginResponse>").append("\n");
        if (LOG.isDebugEnabled()) {
            LOG.debug("sending SLCSLoginResponse:\n" + buf.toString());
        }
        HybridEncResult result = encryptXmlResponse(buf.toString(), getRequestParameter(req, "service"));

        req.setAttribute("encMessage", CryptoUtil.toHexString(result.encMessage));
        req.setAttribute("encSessionKey", CryptoUtil.toHexString(result.encSessionKey));
        req.setAttribute("serviceUrl", service);
        RequestDispatcher rd = req.getRequestDispatcher("/token/token.jsp");
        rd.forward(req, res);
    }
    
   
    
    private static HybridEncResult encryptXmlResponse(String response, String service) throws SLCSException, IOException {
        URL url = new URL(service);
        String hostName  = url.getHost();
        File file = new File(serviceCertDir, hostName + ".pem");
        if (!file.exists())
            throw new SLCSException("Cannot find public key for service '" + hostName
                    + "'. Please make sure that you have " + hostName + ".pem under " + serviceCertDir);
        CryptoUtil cryptoUtil = new CryptoUtil();
        PublicKey pk = cryptoUtil.decodeKey(serviceCertDir + hostName + ".pem");
        
        HybridEncResult result = cryptoUtil.hybridEncrypt(response.getBytes(), pk);
        
        return result;
    }
    
}
