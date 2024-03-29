/*
 * $Id: DatabaseAuditor.java,v 1.3 2007/06/11 12:49:56 vtschopp Exp $
 * 
 * Created on Aug 30, 2006 by Valery Tschopp <tschopp@switch.ch>
 *
 * Copyright (c) 2006 SWITCH - http://www.switch.ch/
 */
package org.glite.slcs.audit.impl;

import java.sql.SQLException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.SLCSException;
import org.glite.slcs.audit.Auditor;
import org.glite.slcs.audit.event.AuditEvent;
import org.glite.slcs.config.SLCSServerConfiguration;

/**
 * DatabaseAuditor implements a JDBC data store for audit events. Uses a 
 * simple JDBC delegate to store in the DB.
 * 
 * @author Valery Tschopp <tschopp@switch.ch>
 * @version $Revision: 1.3 $
 */
public class DatabaseAuditor implements Auditor {

    /** Logging */
    private static Log LOG= LogFactory.getLog(DatabaseAuditor.class);

    private JDBCAuditEventDatabase database_= null;

    /**
     * Default constructor, called only by factory.
     */
    public DatabaseAuditor() {
        super();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.SLCSServerComponent#init(org.glite.slcs.config.SLCSServerConfiguration)
     */
    public void init(SLCSServerConfiguration config) throws SLCSException {
        // checks the configuration parameters
        String jdbcDriver= config.getString( SLCSServerConfiguration.COMPONENTSCONFIGURATION_PREFIX + ".Auditor.JDBCDriver");
        LOG.info("Auditor.JDBCDriver=" + jdbcDriver);
        String connectionUrl= config.getString(SLCSServerConfiguration.COMPONENTSCONFIGURATION_PREFIX + ".Auditor.ConnectionUrl");
        LOG.info("Auditor.ConnectionUrl=" + connectionUrl);
        String user= config.getString(SLCSServerConfiguration.COMPONENTSCONFIGURATION_PREFIX + ".Auditor.User");
        LOG.info("Auditor.User=" + user);
        String password= config.getString(SLCSServerConfiguration.COMPONENTSCONFIGURATION_PREFIX + ".Auditor.Password");
        LOG.info("Auditor.Password=" + password);

        try {
            LOG.debug("create JDBC DB");
            database_= new JDBCAuditEventDatabase(jdbcDriver,
                                                  connectionUrl,
                                                  user,
                                                  password);
            LOG.debug("connect to DB");
            database_.connect();
        } catch (ClassNotFoundException e) {
            LOG.error("Failed to load JDBC driver: " + jdbcDriver, e);
            throw new SLCSException("Failed to load JDBC driver: " + jdbcDriver,
                                    e);
        } catch (SQLException e) {
            LOG.error("Failed to create the JDBC database: " + connectionUrl
                    + " user: " + user + " password: " + password, e);
            throw new SLCSException("Failed to create the JDBC database: "
                    + connectionUrl + " user: " + user + " password: "
                    + password, e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.audit.Auditor#logEvent(org.glite.slcs.audit.AuditEvent)
     */
    public void logEvent(AuditEvent event) throws SLCSException {
        try {
            database_.insertAuditEvent(event);
        } catch (SQLException e) {
            LOG.warn("Database disconnected, reconnecting...");
            try {
                database_.reconnect();
                database_.insertAuditEvent(event);
            } catch (SQLException e1) {
                LOG.error("Failed to reconnect to DB", e);
                throw new SLCSException("Failed to reconnect to DB", e);
            }
        }

    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.glite.slcs.SLCSServerComponent#shutdown()
     */
    public void shutdown() {
        if (database_ != null) {
            LOG.info("close DB connection");
            database_.close();
            database_= null;
        }
    }

}
