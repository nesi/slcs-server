/*
 * $Id: XMLFileAccessControlList.java,v 1.8 2008/05/06 14:29:27 vtschopp Exp $
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html 
 */
package org.glite.slcs.acl.impl;

import java.io.File;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.SLCSConfigurationException;
import org.glite.slcs.SLCSException;
import org.glite.slcs.acl.AccessControlList;
import org.glite.slcs.acl.AccessControlRule;
import org.glite.slcs.attribute.Attribute;
import org.glite.slcs.attribute.AttributeDefinitions;
import org.glite.slcs.attribute.AttributeDefinitionsFactory;
import org.glite.slcs.config.FileConfigurationEvent;
import org.glite.slcs.config.FileConfigurationListener;
import org.glite.slcs.config.FileConfigurationMonitor;

/**
 * XMLFileAccessControlList implements a XML file based Shibboleth ACL. This
 * implementation use a FileConfigurationMonitor to track the file modications
 * and reload it on changes.
 * 
 * @author Valery Tschopp <tschopp@switch.ch>
 * @version $Revision: 1.8 $
 * @see org.glite.slcs.acl.AccessControlList
 * @see org.glite.slcs.config.FileConfigurationListener
 */
public class XMLFileAccessControlList implements AccessControlList,
        FileConfigurationListener {

    /** Name of the ACL file parameter in the {@link FilterConfig} */
    private static String ACLFILE_CONFIG_PARAM = "ACLFile";

    /** Name of the {@link ServletContext} parameter referencing the ACL file */
    private static String ACLFILE_CONTEXT_PARAM = "ContextParamACLFile";

    /** Logging */
    private static Log LOG = LogFactory.getLog(XMLFileAccessControlList.class);

    /** XML file based authorization */
    private XMLConfiguration aclXMLConfiguration_ = null;

    /** List of Access Control Rules */
    private List accessControlRules_ = null;

    /** ACL file change monitor */
    private FileConfigurationMonitor aclConfigurationMonitor_ = null;

    /**
     * Constructor called by the factory.
     */
    public XMLFileAccessControlList() {
        super();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.acl.AccessControlList#init(javax.servlet.FilterConfig)
     */
    public void init(FilterConfig filterConfig) throws SLCSException {

        // initialize the AttributeDefintions from the servlet context
        ServletContext context = filterConfig.getServletContext();
        AttributeDefinitionsFactory.initialize(context);

        String filename = filterConfig.getInitParameter(ACLFILE_CONFIG_PARAM);
        LOG.info(ACLFILE_CONFIG_PARAM + "=" + filename);
        if (filename == null) {
            LOG.info("Parameter '" + ACLFILE_CONFIG_PARAM
                    + "' is not defined, trying parameter '"
                    + ACLFILE_CONTEXT_PARAM + "'");
            String contextKey = filterConfig.getInitParameter(ACLFILE_CONTEXT_PARAM);
            LOG.info(ACLFILE_CONTEXT_PARAM + "=" + contextKey);
            if (contextKey != null) {
                filename = context.getInitParameter(contextKey);
                if (filename == null) {
                    throw new SLCSConfigurationException(
                            "Filter parameter ContextParamACLFile references a undefined Context parameter.");
                }
                LOG.debug("ACL filename=" + filename);
            }
            else {
                throw new SLCSConfigurationException(
                        "Filter parameter ACLFile or ContextParamACLFile not defined");
            }
        }

        // load the XML file
        aclXMLConfiguration_ = createACLXMLConfiguration(filename);

        // create the access control rules list
        accessControlRules_ = createACLAccessControlRules(aclXMLConfiguration_);

        // deals with the FileConfigurationMonitor
        String monitoringInterval = filterConfig.getInitParameter("ACLFileMonitoringInterval");
        if (monitoringInterval != null) {
            LOG.info("ACLFileMonitoringInterval=" + monitoringInterval);
            File file = aclXMLConfiguration_.getFile();
            aclConfigurationMonitor_ = FileConfigurationMonitor.createFileConfigurationMonitor(
                    file, monitoringInterval, this);
            // and start
            aclConfigurationMonitor_.start();
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.acl.AccessControlList#isAuthorized(java.util.List)
     */
    public boolean isAuthorized(List userAttributes) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("userAttributes=" + userAttributes);
        }
        boolean authorized = false;
        Iterator rules = accessControlRules_.iterator();
        while (!authorized && rules.hasNext()) {
            AccessControlRule rule = (AccessControlRule) rules.next();
            List ruleAttributes = rule.getAttributes();
            if (LOG.isDebugEnabled()) {
                LOG.debug("checking rule:" + rule);
            }
            // only rule attrs know if they are caseSensitive or not...
            if (userAttributes.containsAll(ruleAttributes)) {
                authorized = true;
                LOG.info("User authorized by rule: " + rule);
            }
        }

        if (!authorized) {
            LOG.warn("User not authorized: " + userAttributes);
        }

        return authorized;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.acl.AccessControlList#shutdown()
     */
    public void shutdown() {
        // shutdown the FileConfigurationMonitor
        if (aclConfigurationMonitor_ != null) {
            LOG.info("shutdown ACL file monitor");
            aclConfigurationMonitor_.removeFileConfigurationListener(this);
            aclConfigurationMonitor_.shutdown();
            aclConfigurationMonitor_ = null;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.config.FileConfigurationListener#fileConfigurationChanged(org.glite.slcs.config.FileConfigurationEvent)
     */
    public void fileConfigurationChanged(FileConfigurationEvent event) {
        if (event.getType() == FileConfigurationEvent.FILE_MODIFIED) {
            LOG.debug("reload ACL configuration");
            reloadACLConfiguration();
        }
    }

    /**
     * The XML file have changed, then reload the file configuration and
     * recreate all dependent parameters.
     */
    private synchronized void reloadACLConfiguration() {
        String filename = aclXMLConfiguration_.getFileName();
        LOG.info("reload file: " + filename);
        try {
            // reload the XML file
            aclXMLConfiguration_ = createACLXMLConfiguration(filename);
            // recreate the ACL access control rules
            accessControlRules_ = createACLAccessControlRules(aclXMLConfiguration_);
        } catch (SLCSConfigurationException e) {
            LOG.error("Failed to reload ACLConfiguration: " + filename, e);
        }
    }

    /**
     * Loads the ACL XML FileConfiguration.
     * 
     * @param filename
     *            The ACL XML filename to load.
     * @return The FileConfiguration object.
     * @throws SLCSConfigurationException
     *             If an configration error occurs while loading the file.
     */
    static private XMLConfiguration createACLXMLConfiguration(String filename)
            throws SLCSConfigurationException {
        XMLConfiguration config = null;
        try {
            LOG.info("XMLConfiguration file=" + filename);
            config = new XMLConfiguration(filename);
            if (LOG.isDebugEnabled()) {
                File configFile = config.getFile();
                LOG.debug("XMLConfiguration file="
                        + configFile.getAbsolutePath());
            }
        } catch (ConfigurationException e) {
            LOG.error("Failed to create XMLConfiguration: " + filename, e);
            throw new SLCSConfigurationException(
                    "Failed to create XMLConfiguration: " + filename, e);
        }
        return config;
    }

    /**
     * Creates a list of {@link AccessControlRule}s loaded from the
     * {@link FileConfiguration}.
     * 
     * @param config
     *            The ACL FileConfiguration object
     * @return A {@link List} of {@link AccessControlRule}s
     */
    static private List createACLAccessControlRules(FileConfiguration config) {
        List accessControlRules = new LinkedList();
        // list all rules
        int i = 0;
        while (true) {
            String rulePrefix = "AccessControlRule(" + i + ")";
            i++;
            // get the name and id of the rule
            String ruleGroup = config.getString(rulePrefix + "[@group]");
            if (ruleGroup == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(rulePrefix + ": no more rules");
                }
                // no more ACL rule to read, exit while loop
                break;
            }
            int ruleId = config.getInt(rulePrefix + "[@id]");
            // create an empty rule
            AccessControlRule rule = new AccessControlRule(ruleId, ruleGroup);
            // get the attributes name-value for the rule
            List attributeNames = config.getList(rulePrefix
                    + ".Attribute[@name]");
            if (attributeNames.isEmpty()) {
                LOG.error(rulePrefix + ": no attribute in rule, skipping...");
                // error, skipping
                continue;
            }
            AttributeDefinitions attributeDefinitions = AttributeDefinitionsFactory.getInstance();
            List attributeValues = config.getList(rulePrefix + ".Attribute");
            for (int j = 0; j < attributeNames.size(); j++) {
                String name = (String) attributeNames.get(j);
                String value = (String) attributeValues.get(j);
                Attribute attribute = attributeDefinitions.createAttribute(
                        name, value);
                // add attribute to the rule
                rule.addAttribute(attribute);
            }
            // add the rule to the list
            if (LOG.isDebugEnabled()) {
                LOG.debug("adding rule in ACL: " + rule);
            }
            accessControlRules.add(rule);

        } // while

        return accessControlRules;
    }
}
