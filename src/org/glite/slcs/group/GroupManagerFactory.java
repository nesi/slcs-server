/*
 * $Id: GroupManagerFactory.java,v 1.1 2007/02/26 16:56:32 vtschopp Exp $
 * 
 * Created on Aug 30, 2006 by Valery Tschopp <tschopp@switch.ch>
 *
 * Copyright (c) 2006 SWITCH - http://www.switch.ch/
 */
package org.glite.slcs.group;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.SLCSException;
import org.glite.slcs.config.SLCSServerConfiguration;

/**
 * GroupManagerFactory is a factory to get the singleton instance implementing
 * the GroupManager.
 * 
 * @author Valery Tschopp <tschopp@switch.ch>
 * @version $Revision: 1.1 $
 */
public class GroupManagerFactory {

    /** Logging */
    private static Log LOG = LogFactory.getLog(GroupManagerFactory.class);

    /** Singleton pattern */
    private static GroupManager SINGLETON = null;

    /**
     * Factory method to get the singleton instance of the GroupManager
     * implementation as defined in the SLCSServerConfiguration.
     * 
     * @return The GroupManager singleton instance.
     * @throws SLCSException
     *             If an error occurs while instantiation or initializing the
     *             instance.
     */
    public static synchronized GroupManager getInstance() throws SLCSException {
        if (SINGLETON != null) {
            return SINGLETON;
        }
        SLCSServerConfiguration config = SLCSServerConfiguration.getInstance();
        SINGLETON = newInstance(config);
        return SINGLETON;
    }

    /**
     * Creates a new GroupManager implementation instance as define in the
     * SLCSServerConfiguration.
     * 
     * @param config
     *            The SLCSServerConfiguration object.
     * @return The GroupManager implementation instance. If an error occurs while
     *         instantiation or initializing the instance.
     */
    protected static GroupManager newInstance(SLCSServerConfiguration config)
            throws SLCSException {
        GroupManager impl = null;
        String className = config.getString(SLCSServerConfiguration.COMPONENTSCONFIGURATION_PREFIX
                + ".GroupManager[@implementation]");
        LOG.info("GroupManager implementation=" + className);
        try {
            impl = (GroupManager) Class.forName(className).newInstance();
            impl.init(config);
        } catch (InstantiationException e) {
            LOG.error("Can not instantiate class: " + className, e);
            throw new SLCSException("Can not instantiate class: " + className, e);
        } catch (IllegalAccessException e) {
            LOG.error("Illegal access for class: " + className, e);
            throw new SLCSException("Illegal access for class: " + className, e);
        } catch (ClassNotFoundException e) {
            LOG.error("Implementation not found: " + className, e);
            throw new SLCSException("Implementation not found: " + className, e);
        }
        return impl;
    }

    /**
     * Prevents instantiation.
     */
    private GroupManagerFactory() {
    }

}
