/*
 * $Id: SLCSSessionsFactory.java,v 1.3 2007/03/14 13:58:10 vtschopp Exp $
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://eu-egee.org/partners/ for details on the copyright holders.
 * For license conditions see the license file or http://eu-egee.org/license.html 
 */
package org.glite.slcs.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.SLCSException;
import org.glite.slcs.config.SLCSServerConfiguration;

/**
 * SLCSSessionsFactory is a factory to get the singleton implementation instance
 * as defined in the SLCSServerConfiguration.
 * 
 * @author Valery Tschopp &lt;tschopp@switch.ch&gt;
 * @version $Revision: 1.3 $
 */
public class SLCSSessionsFactory {

    /** Logging */
    static private Log LOG = LogFactory.getLog(SLCSSessionsFactory.class);

    /** singleton pattern */
    static private SLCSSessions SINGLETON = null;

    /**
     * Gets the singleton instance implemented as defined in the
     * SLCSServerConfiguration.
     * 
     * @return The singleton implementation of the SLCSSessions.
     * @throws SLCSException
     *             If an error occurs while instantiating or initializing the
     *             implementation.
     */
    static synchronized public SLCSSessions getInstance() throws SLCSException {
        if (SINGLETON != null) {
            return SINGLETON;
        }
        SLCSServerConfiguration config = SLCSServerConfiguration.getInstance();
        SINGLETON = newInstance(config);
        return SINGLETON;
    }

    /**
     * Creates a new intance of the SLCSSessions implementation as defined in
     * the SLCSServerConfiguration.
     * 
     * @param config
     *            The SLCSServerConfiguration object.
     * @return The SLCSSessions implementation instance.
     * @throws SLCSException
     *             If an error occurs while instantiating and initializing the
     *             implementation instance.
     */
    protected static SLCSSessions newInstance(SLCSServerConfiguration config)
            throws SLCSException {
        SLCSSessions impl = null;
        // instantiate
        String className = config
                .getString(SLCSServerConfiguration.COMPONENTSCONFIGURATION_PREFIX
                        + ".SLCSSessions[@implementation]");
        LOG.info("SLCSSessions implementation=" + className);
        try {
            impl = (SLCSSessions) Class.forName(className).newInstance();
            impl.init(config);
        } catch (InstantiationException e) {
            LOG.error("Can not instantiate class: " + className, e);
            throw new SLCSException("Can not instantiate class: " + className,
                    e);
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
     * Prevents instantiation of the factory (utility pattern)
     */
    private SLCSSessionsFactory() {
    }

}
