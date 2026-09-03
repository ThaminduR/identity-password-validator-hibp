/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.password.validator.hibp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.identity.password.validator.hibp.HIBPBreachSource;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.identity.password.validator.hibp.HIBPConnectorConfig;

/**
 * Publishes the breach source. The connector's entire integration with the product is this one service
 * registration against a contract imported at its own compatibility range.
 */
@Component(
        name = "identity.breach.hibp.component",
        immediate = true
)
public class HIBPServiceComponent {

    private static final Log LOG = LogFactory.getLog(HIBPServiceComponent.class);

    private ServiceRegistration<BreachSource> registration;
    private ServiceRegistration<IdentityConnectorConfig> connectorRegistration;
    private HIBPBreachSource source;

    @Activate
    protected void activate(ComponentContext context) {

        source = new HIBPBreachSource();
        registration = context.getBundleContext().registerService(BreachSource.class, source, null);
        // Publishing this gives the connector its per-organization settings and its Console presence. Both
        // are removed when the bundle is removed.
        connectorRegistration = context.getBundleContext()
                .registerService(IdentityConnectorConfig.class, new HIBPConnectorConfig(), null);
        LOG.info("The Have I Been Pwned breach source connector is registered.");
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (connectorRegistration != null) {
            connectorRegistration.unregister();
            connectorRegistration = null;
        }
        if (registration != null) {
            registration.unregister();
            registration = null;
        }
        if (source != null) {
            source.shutdown();
            source = null;
        }
        LOG.info("The Have I Been Pwned breach source connector is unregistered.");
    }

    @Reference(
            name = "identity.governance.service",
            service = IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService"
    )
    protected void setIdentityGovernanceService(IdentityGovernanceService service) {

        HIBPDataHolder.getInstance().setIdentityGovernanceService(service);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService service) {

        HIBPDataHolder.getInstance().setIdentityGovernanceService(null);
    }
}
