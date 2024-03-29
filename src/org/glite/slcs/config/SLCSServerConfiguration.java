/*
 * $Id: SLCSServerConfiguration.java,v 1.17 2007/11/13 14:35:26 vtschopp Exp $
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html 
 */
package org.glite.slcs.config;

import javax.servlet.ServletContext;

import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.SLCSConfigurationException;
import org.glite.slcs.SLCSException;
import org.glite.slcs.SLCSServerVersion;
import org.glite.slcs.attribute.AttributeDefinitions;
import org.glite.slcs.attribute.AttributeDefinitionsFactory;

/**
 * SLCSServerConfiguration is the singleton instance of the SLCS server
 * configuration. It must be configured as the WebAppliation Context parameters
 * in the <code>web.xml</code> file.
 * 
 * <pre>
 *  &lt;web-app id=&quot;SLCS&quot; version=&quot;2.4&quot;&gt;
 *  &lt;display-name&gt;SLCS&lt;/display-name&gt;
 *  &lt;!-- webapps context parameters --&gt;
 *     &lt;context-param&gt;
 *        &lt;!-- MANDATORY SLCSServerConfigurationFile: absolute filename or file in classpath --&gt;
 *        &lt;param-name&gt;SLCSServerConfigurationFile&lt;/param-name&gt;
 *        &lt;param-value&gt;/etc/glite/slcs.xml&lt;/param-value&gt;
 *     &lt;/context-param&gt;
 *     ...
 * </pre>
 * 
 * @author Valery Tschopp <tschopp@switch.ch>
 * @version $Revision: 1.17 $
 */
public class SLCSServerConfiguration extends SLCSConfiguration {

    /** Logger */
    public static Log LOG = LogFactory.getLog(SLCSServerConfiguration.class);

    /**
     * Parameter name in the context or in the web.xml file
     */
    static private String CONFIGURATION_FILE_KEY = "SLCSServerConfigurationFile";

    /**
     * Default server configuration filename
     */
    static private String DEFAULT_CONFIGURATION_FILE = "slcs.xml";

    /**
     * Key prefix for a server components configuration in the configuration
     * file
     */
    static public String COMPONENTSCONFIGURATION_PREFIX = "SLCSComponentsConfiguration";

    /**
     * Singelton pattern
     */
    static private SLCSServerConfiguration SINGLETON = null;

    /**
     * Helper for attributes
     */
    private AttributeDefinitions attributeDefinitions_ = null;

    /**
     * Initialize the singleton instance of the SLCSServerConfiguration.<p> 
     * Use the servlet context parameter <code>SLCSServerConfigurationFile</code> to
     * determine the configuration file to load. 
     * <p>Try to configure the log4j engine by loading the config file define in the
     * servlet context parameter <code>Log4JConfigureFile</code>.
     * 
     * @param ctxt
     *            The ServletContext
     * @throws SLCSConfigurationException
     *             If a configuration error occurs.
     * @see org.glite.slcs.config.Log4JConfiguration#configure(ServletContext)
     */
    static public synchronized void initialize(ServletContext ctxt)
            throws SLCSConfigurationException {
        // first configure Log4J with the external log4j config file
        Log4JConfiguration.configure(ctxt);
        // and the SLCS server
        LOG.debug("initialize SLCSServerConfiguration(ServletContext)...");
        String filename = DEFAULT_CONFIGURATION_FILE;
        if (ctxt.getInitParameter(CONFIGURATION_FILE_KEY) != null) {
            filename = ctxt.getInitParameter(CONFIGURATION_FILE_KEY);
        }
        else {
            LOG.warn("Parameter " + CONFIGURATION_FILE_KEY + " not found in the Servlet context, using default file: " + filename);
        }
        initialize(filename);
    }

    /**
     * Initializes the singleton SLCSServerConfiguration object loaded with the
     * given XML filename.
     * 
     * @param filename
     *            The XML filename.
     * @throws SLCSConfigurationException
     *             If an error occurs.
     */
    static public synchronized void initialize(String filename)
            throws SLCSConfigurationException {
        LOG.info(CONFIGURATION_FILE_KEY + "=" + filename);
        if (SINGLETON == null) {
            LOG.info("create new SLCSServerConfiguration");
            SINGLETON = new SLCSServerConfiguration(filename);
        }
        else {
            LOG.info("SLCSServerConfiguration already initialized");
        }
    }

    /**
     * Returns the singleton instance of the SLCSServerConfiguration.
     * 
     * @return The SLCSServerConfiguration singleton.
     */
    static public synchronized SLCSServerConfiguration getInstance() {
        if (SINGLETON == null) {
            throw new IllegalStateException(
                    "Not initialized: call SLCSServerConfiguration.initialize(...) first.");
        }
        return SINGLETON;
    }

    /**
     * DO NOT USE directly the constructor. Factory pattern. Only use
     * initialize() and getInstance().
     * 
     * @param filename
     *            The XML file based configuration file.
     * @throws SLCSConfigurationException
     *             If a configuration error occurs while loading the
     *             configuration file or checking the configuration.
     * @see #initialize(ServletContext)
     * @see #getInstance()
     */
    protected SLCSServerConfiguration(String filename)
            throws SLCSConfigurationException {
        super();
        // echo server version in log file
        LOG.info("SLCSServerVersion=" + SLCSServerVersion.getVersion() + " "
                + SLCSServerVersion.getCopyright());
        LOG.info("XMLFilename=" + filename);
        FileConfiguration configuration = loadConfiguration(filename);
        // setFileConfiguration call checkConfiguration...
        setFileConfiguration(configuration);

        // load the attribute definitions
        createAttributeDefinitions();
    }

    private void createAttributeDefinitions() throws SLCSConfigurationException {

        // read filename from config and getInstance
        String definitionsFile = getString("AttributeDefinitions[@filename]");
        try {
            AttributeDefinitionsFactory.initialize(definitionsFile);
            attributeDefinitions_ = AttributeDefinitionsFactory.getInstance();
        } catch (SLCSException e) {
            LOG.error(e);
            throw new SLCSConfigurationException(
                    "Failed to create AttributeDefinitions: " + definitionsFile,
                    e);
        }
    }

    /**
     * @return The {@link AttributeDefinitions} instance.
     */
    public AttributeDefinitions getAttributeDefinitions() {
        return attributeDefinitions_;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.config.SLCSConfiguration#checkConfiguration()
     */
    protected void checkConfiguration() throws SLCSConfigurationException {
        String filename = getFilename();
        // Shibboleth attributes definitions XML file
        if (!contains("AttributeDefinitions[@filename]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): no "
                    + "AttributeDefinitions[@filename] defined");
            throw new SLCSConfigurationException("Element(s) "
                    + "AttributeDefinitions[@filename] not defined in "
                    + filename);
        }
        // DNBuilder
        if (!contains(COMPONENTSCONFIGURATION_PREFIX
                + ".DNBuilder[@implementation]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".DNBuilder[@implementation] missing");
            throw new SLCSConfigurationException("Element "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".DNBuilder[@implementation] not defined in " + filename);
        }
        // SLCSSessions
        if (!contains(COMPONENTSCONFIGURATION_PREFIX
                + ".SLCSSessions[@implementation]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".SLCSSessions[@implementation] missing");
            throw new SLCSConfigurationException("Element "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".SLCSSessions[@implementation] not defined in "
                    + filename);
        }
        // CAClient
        if (!contains(COMPONENTSCONFIGURATION_PREFIX
                + ".CAClient[@implementation]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".CAClient[@implementation] missing");
            throw new SLCSConfigurationException("Element "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".CAClient[@implementation] not defined in " + filename);
        }
        // CertificatePolicy
        if (!contains(COMPONENTSCONFIGURATION_PREFIX
                + ".CertificatePolicy[@implementation]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".CertificatePolicy[@implementation] missing");
            throw new SLCSConfigurationException("Element "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".CertificatePolicy[@implementation] not defined in "
                    + filename);
        }
        // Auditor
        if (!contains(COMPONENTSCONFIGURATION_PREFIX
                + ".Auditor[@implementation]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".Auditor[@implementation] missing");
            throw new SLCSConfigurationException("Element "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".Auditor[@implementation] not defined in " + filename);
        }
        // AccessControlListEditor
        if (!contains(COMPONENTSCONFIGURATION_PREFIX
                + ".AccessControlListEditor[@implementation]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".AccessControlListEditor[@implementation] missing");
            throw new SLCSConfigurationException(
                    "Element "
                            + COMPONENTSCONFIGURATION_PREFIX
                            + ".AccessControlListEditor[@implementation] not defined in "
                            + filename);
        }
        // GroupManager
        if (!contains(COMPONENTSCONFIGURATION_PREFIX
                + ".GroupManager[@implementation]")) {
            LOG.error("SLCSServerConfiguration(" + filename + "): "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".GroupManager[@implementation] missing");
            throw new SLCSConfigurationException("Element "
                    + COMPONENTSCONFIGURATION_PREFIX
                    + ".GroupManager[@implementation] not defined in "
                    + filename);
        }

    }
}
