package org.glite.slcs.acl.impl;

import java.util.Iterator;
import java.util.List;

import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.slcs.Attribute;
import org.glite.slcs.acl.AccessControlRule;

public class AddAccessControlRuleXMLOperation extends XMLOperation {

    /** Logging */
    private static Log LOG = LogFactory.getLog(AddAccessControlRuleXMLOperation.class);

    /**
     * The AccessControlRule to add
     */
    private AccessControlRule rule_ = null;

    /**
     * Constructor
     * 
     * @param rule
     *            The AccessControlRule to add.
     */
    public AddAccessControlRuleXMLOperation(AccessControlRule rule) {
        super();
        rule_ = rule;
    }

    protected void doProcessing(XMLConfiguration config) {

        if (LOG.isDebugEnabled())
            LOG.debug("adding: " + rule_);

        // find max id in the list to determine new id for the rule
        // BETTER, generate a random and check the list...
        List ruleIds = config.getList("AccessControlRule[@id]");
        int max = Integer.MIN_VALUE;
        Iterator ids = ruleIds.iterator();
        while (ids.hasNext()) {
            int id = Integer.parseInt((String) ids.next());
            if (id > max) {
                max = id;
            }
        }

        // add the rule in the XML file
        String newId = String.valueOf(max + 1);
        LOG.debug("adding AccessControlRule[@id]=" + newId);
        config.addProperty("AccessControlRule(-1)[@id]", newId);
        config.addProperty("AccessControlRule[@group]", rule_.getGroup());
        List ruleAttributes = rule_.getAttributes();
        Iterator attributes = ruleAttributes.iterator();
        while (attributes.hasNext()) {
            Attribute attribute = (Attribute) attributes.next();
            config.addProperty("AccessControlRule.Attribute(-1)", attribute.getValue());
            config.addProperty("AccessControlRule.Attribute[@name]", attribute.getName());

        }

        // save config
        save(config);

        // success
        setStatus(true);
    }

}
